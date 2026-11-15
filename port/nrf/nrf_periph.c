/*
 * MimiBoot-Mu - Nordic nRF51 / nRF52 peripherals the bootloader needs:
 * reset cause, HF crystal, TIMER0 for time, GPIO, the console UART, watchdog.
 *
 * Clock: the CPU stays on its reset clock. The UART is clocked from HFCLK, so
 * the 32/16 MHz crystal is started for an accurate baud rate (every nRF52
 * module has one: the radio needs it) and stopped again before an image
 * starts. If it doesn't start, the internal RC (about +-1.5 %) is used.
 *
 * Time: TIMER0 at 1 MHz, polled (the nRF51 has no SysTick; the same code
 * runs on both). Restored to its reset state before an image starts.
 *
 * UART: the nRF51 and the nRF52832/833/840 have the classic UART (6-byte RX
 * FIFO, polled). Parts without it (nRF52805/810/811/820, MB_NRF_UARTE) use
 * UARTE with one-byte EasyDMA transfers, the way Zephyr's poll_in does.
 *
 * Watchdog: can't be stopped, and keeps running through a soft reset. A
 * watchdog the app left running is fed from the first instruction on.
 *
 * Debug access (nRF52 with the newer APPROTECT, "configuration 249" in
 * Nordic's errata header): debug is closed at reset and firmware opens it
 * by copying UICR.APPROTECT into APPROTECT.DISABLE, as Nordic's SystemInit
 * (nrf52_handle_approtect) does; a board sitting in the menu stays
 * debuggable. With MB_FEAT_DEBUG_LOCK it is never opened and FORCEPROTECT
 * keeps it shut until the next reset, whatever UICR says or the app tries.
 * Older silicon has no such registers (they're left alone): there UICR
 * alone decides. The bootloader never writes UICR.
 *
 * Flash lock (MB_FEAT_BOOT_LOCK), before an image starts, until reset:
 *   nRF51                     MPU.PROTENSET0/1, 4 KB blocks (PROTBLOCKSIZE = 0)
 *   nRF52805/810/811/832      BPROT.CONFIG0..3, 4 KB blocks
 *   nRF52820/833/840          ACL: one region, write and erase blocked
 * Register layouts from Nordic's MDK (nrf51.h, nrf52.h, nrf52840.h); the
 * same mechanism as the nRF Connect SDK's fprotect (fprotect_bprot.c,
 * fprotect_acl.c). Written from those, compile-checked; not yet run on a chip.
 */
#include "core/mimiboot.h"
#include "port/cortexm/mcu.h"

/* ---- registers ------------------------------------------------------------- */
#define CLOCK_HFCLKSTART    0x40000000u
#define CLOCK_HFCLKSTOP     0x40000004u
#define CLOCK_HFSTARTED     0x40000100u
#define POWER_RESETREAS     0x40000400u
#define UICR_APPROTECT      0x10001208u
#define APPROTECT_FORCE     0x40000550u     /* APPROTECT.FORCEPROTECT: write 0 = closed until reset (write-once) */
#define APPROTECT_DISABLE   0x40000558u     /* APPROTECT.DISABLE: 0x5A = open */
#define FICR_VAR1           0x10000130u     /* the words nrf52_configuration_249() reads */
#define FICR_VAR2           0x10000134u

#define PROT_CONFIG0        0x40000600u     /* BPROT.CONFIG0 / nRF51 MPU.PROTENSET0 */
#define PROT_CONFIG1        0x40000604u
#define PROT_DISABLEINDEBUG 0x40000608u     /* 0: protection holds in debug interface mode too */
#define MPU_PROTBLOCKSIZE   0x4000060Cu     /* nRF51: 0 = 4 KB blocks */
#define BPROT_CONFIG2       0x40000610u
#define BPROT_CONFIG3       0x40000614u
#define ACL_ADDR(n)         (0x4001E800u + 16u * (n))
#define ACL_SIZE(n)         (ACL_ADDR(n) + 4u)
#define ACL_PERM(n)         (ACL_ADDR(n) + 8u)
#define ACL_PERM_NO_WRITE   (1u << 1)       /* WRITE = Disable: write and erase blocked, reads allowed */
#define ACL_REGIONS         8u
#define PROT_BLOCK          4096u

#define TIMER               0x40008000u     /* TIMER0 */
#define T_START             (TIMER + 0x000)
#define T_STOP              (TIMER + 0x004)
#define T_CLEAR             (TIMER + 0x00C)
#define T_CAPTURE0          (TIMER + 0x040)
#define T_MODE              (TIMER + 0x504)
#define T_BITMODE           (TIMER + 0x508)
#define T_PRESCALER         (TIMER + 0x510)
#define T_CC0               (TIMER + 0x540)

#define WDT                 0x40010000u
#define WDT_START           (WDT + 0x000)
#define WDT_RUNSTATUS       (WDT + 0x400)
#define WDT_CRV             (WDT + 0x504)
#define WDT_RREN            (WDT + 0x508)
#define WDT_CONFIG          (WDT + 0x50C)
#define WDT_RR(n)           (WDT + 0x600 + 4u * (n))
#define WDT_RELOAD          0x6E524635u

#define U                   0x40002000u     /* UART0 / UARTE0 */
#define U_STARTRX           (U + 0x000)
#define U_STOPRX            (U + 0x004)
#define U_STARTTX           (U + 0x008)
#define U_STOPTX            (U + 0x00C)
#define U_RXDRDY            (U + 0x108)
#define U_ENDRX             (U + 0x110)
#define U_TXDRDY            (U + 0x11C)
#define U_ENDTX             (U + 0x120)
#define U_ERROR             (U + 0x124)
#define U_RXTO              (U + 0x144)
#define U_TXSTOPPED         (U + 0x158)
#define U_ERRORSRC          (U + 0x480)
#define U_ENABLE            (U + 0x500)
#define U_PSELRTS           (U + 0x508)
#define U_PSELTXD           (U + 0x50C)
#define U_PSELCTS           (U + 0x510)
#define U_PSELRXD           (U + 0x514)
#define U_RXD               (U + 0x518)
#define U_TXD               (U + 0x51C)
#define U_BAUDRATE          (U + 0x524)
#define U_RXD_PTR           (U + 0x534)
#define U_RXD_MAXCNT        (U + 0x538)
#define U_TXD_PTR           (U + 0x544)
#define U_TXD_MAXCNT        (U + 0x548)
#define U_CONFIG            (U + 0x56C)

#define GPIO(port)          ((port) ? 0x50000300u : 0x50000000u)
#define G_OUTSET            0x508u
#define G_OUTCLR            0x50Cu
#define G_IN                0x510u
#define G_PIN_CNF(n)        (0x700u + 4u * (uint32_t)(n))
#define CNF_RESET           0x2u            /* input, input buffer disconnected */
#define CNF_OUTPUT          0x3u            /* output, input buffer disconnected */
#define CNF_IN_PULLUP       0xCu
#define CNF_IN_PULLDOWN     0x4u
#define PSEL(port, pin)     (((uint32_t)(port) << 5) | (uint32_t)(pin))
#define PSEL_NONE           0xFFFFFFFFu
#define SPIN                200000u

/* ---- reset cause ------------------------------------------------------------- */
uint32_t mcu_reset_flags_take(void) {
    uint32_t r = REG32(POWER_RESETREAS);
    REG32(POWER_RESETREAS) = r;                             // write-1-to-clear: the next reset starts clean
    if (r & (1u << 1)) return MB_RESET_WATCHDOG;            // DOG
    if (r & ((1u << 2) | (1u << 3))) return MB_RESET_SOFT;  // SREQ, LOCKUP
    return MB_RESET_POWER;                                  // power-on, pin, wake-up
}

/* ---- clock + time ------------------------------------------------------------- */
static uint32_t last_us, rem_us, now;

#if MB_NRF_SERIES == 52
/* Silicon with the firmware-controlled APPROTECT branch: Nordic's
 * nrf52_configuration_249(), per part (FICR word 0x130) from this revision
 * (word 0x134) on. Unknown parts: no (leave the registers alone). */
static bool approtect_in_firmware(void) {
    uint32_t part = REG32(FICR_VAR1), rev = REG32(FICR_VAR2);
    switch (part) {
        case 0x06: return rev >= 0x07;              /* nRF52832 */
        case 0x08: return rev >= 0x05;              /* nRF52840 */
        case 0x0A: return rev >= 0x02;              /* nRF52810 */
        case 0x0D: return rev >= 0x01;              /* nRF52833 */
        case 0x0E: return rev >= 0x01;              /* nRF52811 */
        case 0x0F: return rev >= 0x01;              /* nRF52805 */
        case 0x10: return rev >= 0x03;              /* nRF52820 */
        default:   return false;
    }
}
#endif

void mcu_init(void) {
#if MB_NRF_SERIES == 52
    if (approtect_in_firmware()) {
#if MB_FEAT_DEBUG_LOCK
        REG32(APPROTECT_FORCE) = 0;                         // shut until reset; DISABLE writes are ignored after this
#elif MB_NRF_APPROTECT
        REG32(APPROTECT_DISABLE) = REG32(UICR_APPROTECT);   // open only if UICR says so (0x5A)
#endif
    }
#endif
    REG32(CLOCK_HFSTARTED) = 0;
    REG32(CLOCK_HFCLKSTART) = 1;
    for (uint32_t n = 0; !REG32(CLOCK_HFSTARTED) && n < SPIN; n++) {}
    REG32(T_STOP) = 1;
    REG32(T_CLEAR) = 1;
    REG32(T_MODE) = 0;                                      // timer
    REG32(T_BITMODE) = 3;                                   // 32 bit
    REG32(T_PRESCALER) = 4;                                 // 16 MHz / 2^4 = 1 MHz
    REG32(T_START) = 1;
}

void mcu_restore(void) {
    REG32(T_STOP) = 1;
    REG32(T_CLEAR) = 1;
    REG32(T_BITMODE) = 0;                                   // reset values
    REG32(T_PRESCALER) = 4;
    REG32(T_CC0) = 0;
    REG32(CLOCK_HFCLKSTOP) = 1;
    REG32(CLOCK_HFSTARTED) = 0;
}

uint32_t mcu_time_ms(void) {
    REG32(T_CAPTURE0) = 1;
    uint32_t us = REG32(T_CC0);
    rem_us += us - last_us;                                 // wraps cleanly every 71 minutes
    last_us = us;
    now += rem_us / 1000u;
    rem_us %= 1000u;
    return now;
}

/* ---- GPIO ------------------------------------------------------------------------ */
static void pin_cnf(int port, int pin, uint32_t cnf) { REG32(GPIO(port) + G_PIN_CNF(pin)) = cnf; }
__attribute__((unused)) static void pin_write(int port, int pin, bool high) {
    REG32(GPIO(port) + (high ? G_OUTSET : G_OUTCLR)) = 1u << pin;
}

void mcu_led(bool on) {
#ifdef MB_LED_PORT
    pin_write(MB_LED_PORT, MB_LED_PIN, on == (MB_LED_ACTIVE_HIGH != 0));
    pin_cnf(MB_LED_PORT, MB_LED_PIN, CNF_OUTPUT);
#else
    (void)on;
#endif
}

bool mcu_button(void) {
#ifdef MB_BUTTON_PORT
    pin_cnf(MB_BUTTON_PORT, MB_BUTTON_PIN, MB_BUTTON_ACTIVE_HIGH ? CNF_IN_PULLDOWN : CNF_IN_PULLUP);
    for (volatile int i = 0; i < 2000; i++) {}
    bool level = (REG32(GPIO(MB_BUTTON_PORT) + G_IN) >> MB_BUTTON_PIN) & 1u;
    return level == (MB_BUTTON_ACTIVE_HIGH != 0);
#else
    return false;
#endif
}

void mcu_pins_release(void) {
#ifdef MB_LED_PORT
    pin_cnf(MB_LED_PORT, MB_LED_PIN, CNF_RESET);
    pin_write(MB_LED_PORT, MB_LED_PIN, false);
#endif
#ifdef MB_BUTTON_PORT
    pin_cnf(MB_BUTTON_PORT, MB_BUTTON_PIN, CNF_RESET);
#endif
}

/* ---- UART -------------------------------------------------------------------------- */
#if MB_NRF_UARTE
static volatile uint8_t rx_byte, tx_byte;               // EasyDMA buffers: must be in RAM
#endif

void mcu_uart_init(void) {
    pin_write(MB_UART_TX_PORT, MB_UART_TX_PIN, true);       // idle high before the UART takes the pin
    pin_cnf(MB_UART_TX_PORT, MB_UART_TX_PIN, CNF_OUTPUT);
    pin_cnf(MB_UART_RX_PORT, MB_UART_RX_PIN, CNF_IN_PULLUP);
    REG32(U_PSELTXD) = PSEL(MB_UART_TX_PORT, MB_UART_TX_PIN);
    REG32(U_PSELRXD) = PSEL(MB_UART_RX_PORT, MB_UART_RX_PIN);
    REG32(U_PSELRTS) = PSEL_NONE;
    REG32(U_PSELCTS) = PSEL_NONE;
    REG32(U_BAUDRATE) = MB_NRF_BAUD;
    REG32(U_CONFIG) = 0;                                    // 8N1, no flow control
    REG32(U_ERRORSRC) = REG32(U_ERRORSRC);
    REG32(U_ERROR) = 0;
#if MB_NRF_UARTE
    REG32(U_ENABLE) = 8;
    REG32(U_ENDRX) = 0;
    REG32(U_RXD_PTR) = (uint32_t)(uintptr_t)&rx_byte;
    REG32(U_RXD_MAXCNT) = 1;
    REG32(U_STARTRX) = 1;
#else
    REG32(U_ENABLE) = 4;
    REG32(U_RXDRDY) = 0;
    REG32(U_TXDRDY) = 0;
    REG32(U_STARTTX) = 1;
    REG32(U_STARTRX) = 1;
#endif
}

void mcu_uart_deinit(void) {
#if MB_NRF_UARTE
    REG32(U_RXTO) = 0;
    REG32(U_TXSTOPPED) = 0;
    REG32(U_STOPRX) = 1;
    for (uint32_t n = 0; !REG32(U_RXTO) && n < SPIN; n++) {}
    REG32(U_STOPTX) = 1;
    for (uint32_t n = 0; !REG32(U_TXSTOPPED) && n < SPIN; n++) {}
#else
    REG32(U_STOPTX) = 1;                                    // putc waited for the last byte already
    REG32(U_STOPRX) = 1;
#endif
    REG32(U_ENABLE) = 0;
    REG32(U_PSELTXD) = PSEL_NONE;
    REG32(U_PSELRXD) = PSEL_NONE;
    REG32(U_BAUDRATE) = 0x04000000u;                        // reset value (250 kbaud)
    REG32(U_RXDRDY) = 0; REG32(U_TXDRDY) = 0; REG32(U_ERROR) = 0;
    REG32(U_ENDRX) = 0; REG32(U_ENDTX) = 0; REG32(U_RXTO) = 0; REG32(U_TXSTOPPED) = 0;
    REG32(U_ERRORSRC) = REG32(U_ERRORSRC);
    pin_cnf(MB_UART_TX_PORT, MB_UART_TX_PIN, CNF_RESET);
    pin_cnf(MB_UART_RX_PORT, MB_UART_RX_PIN, CNF_RESET);
    pin_write(MB_UART_TX_PORT, MB_UART_TX_PIN, false);
}

int mcu_uart_getc(void) {
    if (REG32(U_ERROR)) {                                   // overrun / framing: clear and carry on
        REG32(U_ERROR) = 0;
        REG32(U_ERRORSRC) = REG32(U_ERRORSRC);
    }
#if MB_NRF_UARTE
    if (!REG32(U_ENDRX)) return -1;
    int c = rx_byte;
    REG32(U_ENDRX) = 0;
    REG32(U_STARTRX) = 1;                                   // bytes meanwhile wait in the UARTE's RX FIFO
    return c;
#else
    if (!REG32(U_RXDRDY)) return -1;
    REG32(U_RXDRDY) = 0;                                    // clear first, then read: the FIFO may hold more
    return (int)(REG32(U_RXD) & 0xFFu);
#endif
}

void mcu_uart_putc(char c) {
#if MB_NRF_UARTE
    tx_byte = (uint8_t)c;
    REG32(U_ENDTX) = 0;
    REG32(U_TXD_PTR) = (uint32_t)(uintptr_t)&tx_byte;
    REG32(U_TXD_MAXCNT) = 1;
    REG32(U_STARTTX) = 1;
    for (uint32_t n = 0; !REG32(U_ENDTX) && n < SPIN; n++) {}
#else
    REG32(U_TXDRDY) = 0;
    REG32(U_TXD) = (uint8_t)c;
    for (uint32_t n = 0; !REG32(U_TXDRDY) && n < SPIN; n++) {}
#endif
}

/* ---- watchdog (can't be stopped; survives a soft reset) ---------------------------- */
void mcu_wdt_feed(void) {
    if (!(REG32(WDT_RUNSTATUS) & 1u)) return;
    uint32_t en = REG32(WDT_RREN);
    for (uint32_t i = 0; i < 8; i++)
        if (en & (1u << i)) REG32(WDT_RR(i)) = WDT_RELOAD;
}

void mcu_wdt_start(uint32_t ms) {
    if (REG32(WDT_RUNSTATUS) & 1u) { mcu_wdt_feed(); return; }   // already running: its timeout stays
    uint32_t crv = (uint32_t)(((uint64_t)ms * 32768u) / 1000u);
    REG32(WDT_CRV) = crv < 15 ? 15 : crv;
    REG32(WDT_RREN) = 1;                                    // one reload register (RR0)
    REG32(WDT_CONFIG) = 1;                                  // run while sleeping, pause while halted by a debugger
    REG32(WDT_START) = 1;
}

void mcu_wdt_disarm(void) { mcu_wdt_feed(); }             // can't stop it: give the most time we can

/* ---- hardware random numbers (RNG, bias correction on), for console unlock nonces ---- */
#define RNG                 0x4000D000u
#define RNG_START           (RNG + 0x000)
#define RNG_STOP            (RNG + 0x004)
#define RNG_VALRDY          (RNG + 0x100)
#define RNG_CONFIG          (RNG + 0x504)
#define RNG_VALUE           (RNG + 0x508)

int mcu_random(void* buf, size_t len) {
    uint8_t* b = buf;
    int rc = MB_OK;
    REG32(RNG_CONFIG) = 1;                                  // DERCEN: bias correction (slower, uniform)
    REG32(RNG_VALRDY) = 0;
    REG32(RNG_START) = 1;
    for (size_t i = 0; i < len && rc == MB_OK; i++) {
        uint32_t n = 0;
        while (!REG32(RNG_VALRDY))
            if (++n > SPIN) { rc = MB_E_TIMEOUT; break; }
        b[i] = (uint8_t)REG32(RNG_VALUE);
        REG32(RNG_VALRDY) = 0;
    }
    REG32(RNG_STOP) = 1;
    REG32(RNG_CONFIG) = 0;                                  // back to its reset state for the app
    return rc;
}

/* ---- flash lock until reset (MB_FEAT_BOOT_LOCK) ------------------------------------- */
#if MB_FEAT_BOOT_LOCK
int mcu_flash_lock(uint32_t off, uint32_t len) {
    if (!len || off % PROT_BLOCK || len % PROT_BLOCK || off >= MB_FLASH_SIZE || len > MB_FLASH_SIZE - off) return MB_E_BADARG;
#if MB_NRF_LOCK_ACL
    // The first free region (all zero) takes it; ADDR/SIZE/PERM are write-once until reset.
    for (uint32_t n = 0; n < ACL_REGIONS; n++) {
        if (REG32(ACL_PERM(n)) || REG32(ACL_SIZE(n))) continue;
        REG32(ACL_ADDR(n)) = off;
        REG32(ACL_SIZE(n)) = len;
        REG32(ACL_PERM(n)) = ACL_PERM_NO_WRITE;
        __asm volatile("dsb" ::: "memory");
        return REG32(ACL_ADDR(n)) == off && REG32(ACL_SIZE(n)) == len && REG32(ACL_PERM(n)) == ACL_PERM_NO_WRITE ? MB_OK : MB_E_IO;
    }
    return MB_E_NOSPACE;
#else
    // BPROT (and the nRF51 MPU, laid out the same): one bit per 4 KB block,
    // write-1-to-set, cleared only by a reset
    uint32_t mask[4] = { 0, 0, 0, 0 };
    for (uint32_t b = off / PROT_BLOCK; b < (off + len) / PROT_BLOCK; b++) mask[b / 32] |= 1u << (b % 32);
#if MB_NRF_LOCK_MPU
    REG32(MPU_PROTBLOCKSIZE) = 0;                           // 4 KB blocks
#endif
    REG32(PROT_DISABLEINDEBUG) = 0;                         // and while a debugger is attached
    if (mask[0]) REG32(PROT_CONFIG0) = mask[0];
    if (mask[1]) REG32(PROT_CONFIG1) = mask[1];
#if MB_NRF_LOCK_BPROT
    if (mask[2]) REG32(BPROT_CONFIG2) = mask[2];            // only the nRF52832 has 512 KB to cover
    if (mask[3]) REG32(BPROT_CONFIG3) = mask[3];
#endif
    __asm volatile("dsb" ::: "memory");
    if ((REG32(PROT_CONFIG0) & mask[0]) != mask[0] || (REG32(PROT_CONFIG1) & mask[1]) != mask[1]) return MB_E_IO;
    return MB_OK;
#endif
}
#endif
