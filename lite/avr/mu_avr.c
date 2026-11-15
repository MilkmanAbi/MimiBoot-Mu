/*
 * MimiBoot-Mu Lite for megaAVR (ATmega168/328P/644P/1284P/2560)
 *
 * Lives in the boot section and does as little as the configuration asks:
 *
 *   - decide: start the app now, or listen for an upload first
 *   - listen: STK500v1 over USART0 (avrdude -c arduino, the Arduino IDE)
 *   - check:  CRC-32 of the app against the record written at upload time
 *   - start:  hand the app its reset cause and boot flags, jump to 0
 *
 * plus, when switched on: trial boots (the app must mu_confirm()), staged
 * updates written by the app itself, and a flash-write service for apps.
 *
 * Written from Atmel's AVR061 (STK500 protocol) and the datasheets; no code
 * from other bootloaders. No C runtime: -nostartfiles, no .data, no .bss -
 * all state is on the stack and every constant is in PROGMEM.
 */
#include <avr/boot.h>
#include <avr/eeprom.h>
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/wdt.h>
#include <stdint.h>
#include "lite/mu_lite.h"

#ifndef F_CPU
#error "F_CPU (from the board) is required"
#endif
#if MU_PAGE_SIZE != SPM_PAGESIZE
#error "page size in targets.toml doesn't match the chip"
#endif

#define FAR (FLASHEND > 0xFFFFUL)
#if FAR
typedef uint32_t addr_t;
#else
typedef uint16_t addr_t;
#endif
#if FAR
#define FLASH_BYTE(a) pgm_read_byte_far(a)
#else
#define FLASH_BYTE(a) pgm_read_byte((uint16_t)(a))
#endif

/* STK500v1 (AVR061) */
#define STK_OK          0x10
#define STK_INSYNC      0x14
#define STK_NOSYNC      0x15
#define CRC_EOP         0x20

#define TICK_HZ         100
#define TICKS(ms)       ((uint16_t)((uint32_t)(ms) * TICK_HZ / 1000))

typedef struct {
    addr_t top;             /* end of the highest flash page written in this session */
    uint16_t idle;          /* ticks without a byte */
    uint8_t  ext;           /* address bits 16+ (ATmega2560: STK universal 0x4D) */
    uint8_t  mcusr;
    uint8_t  flags;         /* MU_HF_* for the handoff */
    uint8_t  app_ok;
} st_t;

static void start_app(st_t* s) __attribute__((noreturn));

/* ---- watchdog reset (the only clean way back to a reset state) ---------- */
static void __attribute__((noreturn)) wdt_reset_now(void) {
    wdt_enable(WDTO_15MS);
    for (;;) {}
}

/* Start the app from a real reset: leave a word saying so (and the reset
 * cause it should be told about), let the watchdog reset the chip, and the
 * next boot jumps to the app before touching any peripheral. */
static void __attribute__((noreturn, unused)) reset_into_app(st_t* s, uint8_t kind) {   /* unused without STK500 */
    volatile uint8_t* go = (volatile uint8_t*)MU_GO_ADDR;
    go[0] = 'M';
    go[1] = 'u';
    go[2] = kind;
    go[3] = s->mcusr;
    wdt_reset_now();
}

/* ---- LED ---------------------------------------------------------------- */
#if MU_FEAT_LED && defined(MU_LED_BIT)
#if defined(MU_LED_PORT_B)
#define LED_DDR DDRB
#define LED_PIN PINB
#elif defined(MU_LED_PORT_C)
#define LED_DDR DDRC
#define LED_PIN PINC
#elif defined(MU_LED_PORT_D)
#define LED_DDR DDRD
#define LED_PIN PIND
#endif
#define LED_ON()     (LED_DDR |= _BV(MU_LED_BIT))
#define LED_TOGGLE() (LED_PIN = _BV(MU_LED_BIT))      /* writing PINx toggles PORTx */
#define LED_OFF()    do { LED_DDR &= (uint8_t)~_BV(MU_LED_BIT); PORT_OF_LED &= (uint8_t)~_BV(MU_LED_BIT); } while (0)
#if defined(MU_LED_PORT_B)
#define PORT_OF_LED PORTB
#elif defined(MU_LED_PORT_C)
#define PORT_OF_LED PORTC
#else
#define PORT_OF_LED PORTD
#endif
#else
#define LED_ON()     do {} while (0)
#define LED_TOGGLE() do {} while (0)
#define LED_OFF()    do {} while (0)
#endif

/* ---- CRC-32 (IEEE, as zlib), a nibble at a time ---------------------------- */
#if MU_VERIFY
/* in flash, after the code: the default linker script puts .progmem *before*
 * .init9, which would move the entry point off the boot reset address */
static const uint32_t crc_tab[16] __attribute__((section(".text.mu_crc_tab"), used)) = {
    0x00000000UL, 0x1DB71064UL, 0x3B6E20C8UL, 0x26D930ACUL, 0x76DC4190UL, 0x6B6B51F4UL, 0x4DB26158UL, 0x5005713CUL,
    0xEDB88320UL, 0xF00F9344UL, 0xD6D6A3E8UL, 0xCB61B38CUL, 0x9B64C2B0UL, 0x86D3D2D4UL, 0xA00AE278UL, 0xBDBDF21CUL,
};
#if FAR
#define TAB(i) pgm_read_dword_far(pgm_get_far_address(crc_tab) + 4u * (i))
#else
#define TAB(i) pgm_read_dword(&crc_tab[i])
#endif
static uint32_t crc_flash(addr_t addr, addr_t len) {
    uint32_t c = 0xFFFFFFFFUL;
    while (len--) {
        uint8_t b = FLASH_BYTE(addr++);
        c = (c >> 4) ^ TAB((c ^ b) & 15);
        c = (c >> 4) ^ TAB((c ^ (b >> 4)) & 15);
    }
    return ~c;
}
static uint32_t ee32(uint16_t a) { return eeprom_read_dword((const uint32_t*)a); }
#endif

/* ---- flash pages ---------------------------------------------------------------- */
static void page_write(addr_t addr, const uint8_t* buf) {
    if (addr >= MU_BOOT_START) return;                  /* never the bootloader */
    uint8_t sreg = SREG;
    __asm__ volatile("cli");
    eeprom_busy_wait();
    boot_page_erase(addr);
    boot_spm_busy_wait();
    for (uint16_t i = 0; i < SPM_PAGESIZE; i += 2)
        boot_page_fill(addr + i, buf[i] | (uint16_t)buf[i + 1] << 8);
    boot_page_write(addr);
    boot_spm_busy_wait();
    boot_rww_enable();
    SREG = sreg;
}

#if MU_FEAT_SPM_API
/* The service apps call through the table at FLASHEND-7 (AVR runs SPM only
 * from the boot section). op: MU_SPM_ERASE / MU_SPM_WRITE. */
void mu_spm(uint8_t op, uint32_t addr, const uint8_t* page) __attribute__((used, noinline));
void mu_spm(uint8_t op, uint32_t addr, const uint8_t* page) {
    addr &= ~(uint32_t)(SPM_PAGESIZE - 1);
    if (addr >= MU_BOOT_START) return;
    if (op == MU_SPM_WRITE) {
        page_write(addr, page);
    } else if (op == MU_SPM_ERASE) {
        uint8_t sreg = SREG;
        __asm__ volatile("cli");
        eeprom_busy_wait();
        boot_page_erase(addr);
        boot_spm_busy_wait();
        boot_rww_enable();
        SREG = sreg;
    }
}
#define STR_(x) #x
#define STR(x) STR_(x)
__attribute__((naked, used, section(".mu_api"))) void mu_api_table(void) {
    /* magic first: linker relaxation may shrink the jmp to an rjmp, the entry stays at +4 */
    __asm__ volatile(".byte 'M', 'u', " STR(MU_API_VERSION) ", 0\n jmp mu_spm\n");
}
#endif

/* ---- the app record ----------------------------------------------------------------- */
#if MU_VERIFY
static void record_write(addr_t len, uint32_t crc) {
    eeprom_update_dword((uint32_t*)(MU_REC_OFF + 2), (uint32_t)len);
    eeprom_update_dword((uint32_t*)(MU_REC_OFF + 6), crc);
#if MU_FEAT_TRIAL
    eeprom_update_byte((uint8_t*)(MU_REC_OFF + 10), MU_ST_TRIAL);
    eeprom_update_byte((uint8_t*)(MU_REC_OFF + 11), MU_TRIAL_TRIES);
#else
    eeprom_update_byte((uint8_t*)(MU_REC_OFF + 10), MU_ST_CONFIRMED);
#endif
    eeprom_update_byte((uint8_t*)(MU_REC_OFF + 0), MU_REC_MAGIC0);
    eeprom_update_byte((uint8_t*)(MU_REC_OFF + 1), MU_REC_MAGIC1);
}
#endif

/* Is there an app worth starting? Sets MU_HF_* flags. Doesn't spend trials. */
static uint8_t app_check(st_t* s) {
    (void)s;
#if MU_VERIFY
    if (eeprom_read_byte((const uint8_t*)MU_REC_OFF) == MU_REC_MAGIC0 &&
        eeprom_read_byte((const uint8_t*)(MU_REC_OFF + 1)) == MU_REC_MAGIC1) {
        uint32_t len32 = ee32(MU_REC_OFF + 2);
        addr_t len = (addr_t)len32;
        if (len == 0 || len32 > MU_BOOT_START || crc_flash(0, len) != ee32(MU_REC_OFF + 6)) return 0;
        s->flags |= MU_HF_VERIFIED;
#if MU_FEAT_TRIAL
        if (eeprom_read_byte((const uint8_t*)(MU_REC_OFF + 10)) == MU_ST_TRIAL) {
            if (eeprom_read_byte((const uint8_t*)(MU_REC_OFF + 11)) == 0) return 0;     /* never confirmed */
            s->flags |= MU_HF_TRIAL;
        }
#endif
        return 1;
    }
    s->flags |= MU_HF_NO_RECORD;
#endif
    return pgm_read_word(0) != 0xFFFF;
}

/* ---- staged update: the app wrote an image to the upper half -------------------------- */
#if MU_FEAT_STAGED
#define STAGE_BASE  ((MU_BOOT_START / 2) & ~(uint32_t)(SPM_PAGESIZE - 1))
static uint8_t stage_install(st_t* s, uint8_t* buf) {
    if (eeprom_read_byte((const uint8_t*)(MU_REC_OFF + 12)) != MU_STAGE_MAGIC) return 0;
    uint32_t len32 = ee32(MU_STAGE_OFF), crc = ee32(MU_STAGE_OFF + 4);
    addr_t len = (addr_t)len32;
    if (len == 0 || len32 > MU_BOOT_START - STAGE_BASE || crc_flash(STAGE_BASE, len) != crc) {
        eeprom_update_byte((uint8_t*)(MU_REC_OFF + 12), 0xFF);   /* nothing (valid) to install */
        return 0;
    }
    /* copy; a power cut here just repeats the copy on the next boot */
    for (addr_t a = 0; a < len; a += SPM_PAGESIZE) {
        for (uint16_t i = 0; i < SPM_PAGESIZE; i++)
            buf[i] = a + i < len ? FLASH_BYTE(STAGE_BASE + a + i) : 0xFF;
        page_write(a, buf);
    }
    if (crc_flash(0, len) != crc) return 0;                      /* didn't take: try again next boot */
    record_write(len, crc);
    eeprom_update_byte((uint8_t*)(MU_REC_OFF + 12), 0xFF);
    s->flags |= MU_HF_INSTALLED;
    return 1;
}
#endif

/* ---- UART + timeout ticks ---------------------------------------------------------------- */
#if MU_FEAT_STK500
static void uart_init(void) {
    UCSR0A = _BV(U2X0);
    UBRR0 = (uint16_t)((F_CPU + 4UL * MB_UART_BAUD) / (8UL * MB_UART_BAUD) - 1);
    UCSR0C = _BV(UCSZ01) | _BV(UCSZ00);
    UCSR0B = _BV(RXEN0) | _BV(TXEN0);
    TCCR1A = 0;
    OCR1A = (uint16_t)(F_CPU / 1024 / TICK_HZ - 1);
    TCCR1B = _BV(WGM12) | _BV(CS12) | _BV(CS10);         /* CTC, /1024 */
}

static void putch(uint8_t c) {
    while (!(UCSR0A & _BV(UDRE0))) {}
    UDR0 = c;
}

static uint8_t getch(st_t* s) {
    for (;;) {
        if (UCSR0A & _BV(RXC0)) {
            s->idle = 0;
            return UDR0;
        }
        if (TIFR1 & _BV(OCF1A)) {
            TIFR1 = _BV(OCF1A);
            if ((s->idle & 7) == 0) LED_TOGGLE();
            if (++s->idle >= TICKS(MU_TIMEOUT_MS)) {
                if (s->app_ok) reset_into_app(s, 'R');       /* nobody came: run the app */
                s->idle = 0;
#if !MU_FEAT_NOAPP_STAY
                wdt_reset_now();
#endif
            }
        }
    }
}

static void skip(st_t* s, uint8_t n) { while (n--) getch(s); }

static void sync_ok(st_t* s) {
    if (getch(s) != CRC_EOP) {                              /* lost sync: start over */
        putch(STK_NOSYNC);
        wdt_reset_now();
    }
    putch(STK_INSYNC);
}

static void __attribute__((noreturn)) loader(st_t* s, uint8_t* buf) {
    uint16_t word = 0;
    uart_init();
    LED_ON();
    for (;;) {
        uint8_t ch = getch(s);
#if FAR
        addr_t addr = ((uint32_t)s->ext << 16) | ((uint32_t)word << 1);
#else
        addr_t addr = (addr_t)(word << 1);
#endif
        if (ch == 'A') {                                     /* GET_PARAMETER */
            uint8_t p = getch(s);
            sync_ok(s);
            putch(p == 0x81 ? 8 : p == 0x82 ? 1 : 3);       /* SW major/minor, else "3" */
        } else if (ch == 'B') {                              /* SET_DEVICE */
            skip(s, 20);
            sync_ok(s);
        } else if (ch == 'E') {                              /* SET_DEVICE_EXT */
            skip(s, 5);
            sync_ok(s);
        } else if (ch == 'U') {                              /* LOAD_ADDRESS: a word address */
            word = getch(s);
            word |= (uint16_t)getch(s) << 8;
            sync_ok(s);
        } else if (ch == 'V') {                              /* UNIVERSAL */
            uint8_t b0 = getch(s);
            getch(s);
            uint8_t b2 = getch(s);
            getch(s);
            sync_ok(s);
            if (b0 == 0x4D) s->ext = b2;                     /* load extended address */
            putch(0);
        } else if (ch == 'd') {                              /* PROG_PAGE */
            uint16_t len = (uint16_t)getch(s) << 8;
            len |= getch(s);
            uint8_t type = getch(s);
            for (uint16_t i = 0; i < SPM_PAGESIZE; i++) buf[i] = 0xFF;
            for (uint16_t i = 0; i < len; i++) {
                uint8_t b = getch(s);
                if (i < SPM_PAGESIZE) buf[i] = b;
            }
            sync_ok(s);
            if (type == 'F') {
                page_write(addr, buf);
                if (addr < MU_BOOT_START && addr + SPM_PAGESIZE > s->top) s->top = addr + SPM_PAGESIZE;
            }
#if MU_FEAT_EEPROM
            else if (type == 'E') {
                for (uint16_t i = 0; i < len && i < SPM_PAGESIZE; i++)
                    eeprom_update_byte((uint8_t*)(uint16_t)(addr + i), buf[i]);
            }
#endif
        } else if (ch == 't') {                              /* READ_PAGE */
            uint16_t len = (uint16_t)getch(s) << 8;
            len |= getch(s);
            uint8_t type = getch(s);
            sync_ok(s);
            for (uint16_t i = 0; i < len; i++) {
#if MU_FEAT_EEPROM
                if (type == 'E') { putch(eeprom_read_byte((const uint8_t*)(uint16_t)(addr + i))); continue; }
#else
                (void)type;
#endif
                putch(FLASH_BYTE(addr + i));
            }
        } else if (ch == 'u') {                              /* READ_SIGN */
            sync_ok(s);
            putch(MU_SIG0);
            putch(MU_SIG1);
            putch(MU_SIG2);
        } else if (ch == 'Q') {                              /* LEAVE_PROGMODE: done */
            sync_ok(s);
            putch(STK_OK);
#if MU_VERIFY
            if (s->top) record_write(s->top, crc_flash(0, s->top));
#endif
            reset_into_app(s, 'G');                          /* the app starts from a real reset */
        } else {                                             /* GET_SYNC, ENTER_PROGMODE, ... */
            sync_ok(s);
        }
        putch(STK_OK);
    }
}
#endif /* MU_FEAT_STK500 */

/* ---- start the app ----------------------------------------------------------------------- */
static void start_app(st_t* s) {
#if MU_FEAT_TRIAL
    if (s->flags & MU_HF_TRIAL) {                            /* spend the try before it runs */
        uint8_t left = eeprom_read_byte((const uint8_t*)(MU_REC_OFF + 11));
        eeprom_update_byte((uint8_t*)(MU_REC_OFF + 11), left ? left - 1 : 0);
        wdt_enable(WDTO_8S);                                 /* a hang is a failed try too */
    }
#endif
    /* peripherals are at their reset values: this boot never touched them */
#if MU_FEAT_HANDOFF
    GPIOR0 = MU_HANDOFF_SIG;
    GPIOR1 = s->mcusr;
    GPIOR2 = s->flags;
#endif
    __asm__ volatile("mov r2, %0\n jmp 0\n" ::"r"(s->mcusr));
    __builtin_unreachable();
}

/* ---- reset ------------------------------------------------------------------------------- */
/* The first instruction at the boot reset address: zero register, stack below
 * the words that survive a watchdog reset, then the real entry. */
static void mu_main(void) __attribute__((noreturn, used, noinline));
void __attribute__((naked, used, section(".init9"))) mu_entry(void) {
    __asm__ volatile(
        "clr __zero_reg__\n"
        "out __SREG__, __zero_reg__\n"
        "ldi r28, lo8(%0)\n"
        "ldi r29, hi8(%0)\n"
        "out __SP_L__, r28\n"
        "out __SP_H__, r29\n"
        "jmp mu_main\n" ::"i"(RAMEND - MU_RAM_RESERVED));
}

static void mu_main(void) {
    st_t st;
    st_t* s = &st;
    uint8_t buf[SPM_PAGESIZE];
    s->top = 0;
    s->idle = 0;
    s->ext = 0;
    s->flags = 0;
    s->mcusr = MCUSR;
    MCUSR = 0;
    wdt_disable();                                       /* a watchdog reset leaves it running */

    volatile uint32_t* req = (volatile uint32_t*)MU_REQ_ADDR;
    volatile uint8_t* go = (volatile uint8_t*)MU_GO_ADDR;
    uint8_t requested = *req == MU_REQ_MAGIC;
    uint8_t run_now = go[0] == 'M' && go[1] == 'u' && (go[2] == 'G' || go[2] == 'R') && (s->mcusr & _BV(WDRF));
    if (run_now) {
        if (go[2] == 'G') s->flags |= MU_HF_UPLOADED;
        s->mcusr = go[3];                                /* the reset the app should hear about */
    }
    *req = 0;
    go[0] = 0;
#if MU_FEAT_STAGED
    stage_install(s, buf);
#endif
    s->app_ok = app_check(s);
    uint8_t listen;
#if MU_ENTRY == 1                                        /* every reset, except the app's own watchdog */
    listen = !(s->mcusr & _BV(WDRF));
#else                                                    /* reset pin / DTR only */
    listen = (s->mcusr & _BV(EXTRF)) != 0;
#endif
#if MU_FEAT_APP_REQUEST
    listen |= requested;
#else
    (void)requested;
#endif
    if (run_now) listen = 0;
#if MU_FEAT_NOAPP_STAY
    if (!s->app_ok) listen = 1;
#endif
#if MU_FEAT_STK500
    if (listen) loader(s, buf);
#else
    (void)listen;
#endif
    if (s->app_ok) start_app(s);
    for (;;) {                                           /* nothing to run and nothing to listen with */
        LED_TOGGLE();
        for (volatile uint32_t i = 0; i < F_CPU / 40; i++) {}
    }
}
