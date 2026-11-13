/*
 * MimiBoot-Mu - bare-metal Cortex-M port of the Night core (STM32, nRF, SAMD)
 *
 * Console: a UART (115200 8N1 by default). Normal boots are silent; the menu
 * opens when the board's button is held, when any key arrives on the UART in
 * the first MB_BREAK_IN_MS after reset (mbtool sends them), when the running
 * OS asks for it, or when nothing is bootable.
 *
 * Starting an image (XIP from its slot, or from RAM): interrupts masked in
 * the NVIC and cleared, SysTick stopped, UART/pins/clocks/timer back to reset
 * state, the image's vector table put in force (VTOR, or the chip's fallback
 * when it has none), MSP from it, PRIMASK *enabled* (STM32Cube, nrfx, ASF
 * and FreeRTOS expect to start with interrupts on), jump.
 *
 * Chips without VTOR (Cortex-M0):
 *   remap  STM32F0: the table is copied to the start of SRAM, which is mapped
 *          at 0. Apps keep RAM[0 : MB_M0_VECTORS*4] free.
 *   relay  nRF51: every exception goes through the bootloader's own table,
 *          which forwards to the table whose address is in the RAM word at
 *          MB_RELAY_ADDR (the start of RAM). Apps keep RAM[0:8] free.
 *
 * Built with -DMB_CM_CLIENT the same file is the app side instead: only the
 * flash, layout and reboot parts, as mb_mcu_port for client/mb_client.c.
 */
#include "core/mimiboot.h"
#include "port/cortexm/mcu.h"
#include <string.h>

static const mb_layout_t layout = MB_LAYOUT_INIT;

#ifdef MB_TRUSTED_KEY_COUNT
static const uint8_t trusted[MB_TRUSTED_KEY_COUNT][32] = MB_TRUSTED_KEYS;
static const mb_keyring_t keyring = { MB_TRUSTED_KEY_COUNT, trusted };
#define KEYRING (&keyring)
#else
#define KEYRING NULL
#endif
#ifndef MB_REQUIRE_SIGNATURE
#define MB_REQUIRE_SIGNATURE 0
#endif
#ifndef MB_BREAK_IN_MS
#define MB_BREAK_IN_MS 300
#endif
#ifndef MB_RAM2_SIZE
#define MB_RAM2_BASE 0
#define MB_RAM2_SIZE 0
#endif
#ifndef MB_RAM_RESERVED
#define MB_RAM_RESERVED 0                   /* bytes at the start of RAM that images must leave alone */
#endif
#define STR_(x) #x
#define STR(x) STR_(x)

#if MB_VECTORS == MB_VECTORS_RELAY && MB_TIME_SYSTICK
#error "relay vectors: the bootloader must not use interrupts (time via mcu_time_ms)"
#endif

#ifndef MB_CM_CLIENT
#if MB_TIME_SYSTICK
static volatile uint32_t ticks;
static uint32_t now_ms(void) { return ticks; }
#else
static uint32_t now_ms(void) { return mcu_time_ms(); }
#endif
static uint32_t reset_flags;

/* ---- startup ---------------------------------------------------------------- */
extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
int main(void);

void Reset_Handler(void) {
#if MB_VECTORS == MB_VECTORS_RELAY
    REG32(MB_RELAY_ADDR) = 0;               // our own exceptions until an image starts
#endif
    uint32_t *s = &_sidata, *d = &_sdata;
    while (d < &_edata) *d++ = *s++;
    for (d = &_sbss; d < &_ebss;) *d++ = 0;
    main();
    for (;;) {}
}

#if MB_VECTORS == MB_VECTORS_RELAY
/* Forward exception n to entry n of the table at *MB_RELAY_ADDR. r0/r1 are
 * already stacked by the exception entry and lr holds EXC_RETURN, so the
 * image's handler runs exactly as if the hardware had called it. While the
 * bootloader runs (word = 0) a fault just stops here. */
__attribute__((naked)) static void relay(void) {
    __asm volatile(
        ".syntax unified\n"
        "ldr  r0, 1f\n"
        "ldr  r0, [r0]\n"
        "cmp  r0, #0\n"
        "beq  2f\n"
        "mrs  r1, ipsr\n"
        "lsls r1, r1, #2\n"
        "ldr  r0, [r0, r1]\n"
        "bx   r0\n"
        "2: b 2b\n"
        ".align 2\n"
        "1: .word " STR(MB_RELAY_ADDR) "\n");
}
#define H(x) ((const void*)relay)
#define N_VECTORS (16 + MB_IRQS)
#else
static void Fault_Handler(void) { for (;;) {} }
#define H(x) ((const void*)(x))
#define N_VECTORS 16
#endif

#if MB_TIME_SYSTICK
void SysTick_Handler(void) { ticks++; }
#else
#define SysTick_Handler Fault_Handler
#endif

__attribute__((section(".isr_vector"), used)) const void* const mb_vectors[N_VECTORS] = {
    &_estack, (const void*)Reset_Handler, H(Fault_Handler), H(Fault_Handler),
    H(Fault_Handler), H(Fault_Handler), H(Fault_Handler), 0, 0, 0, 0,
    H(Fault_Handler), H(Fault_Handler), 0, H(Fault_Handler), H(SysTick_Handler),
#if MB_VECTORS == MB_VECTORS_RELAY
    [16 ... N_VECTORS - 1] = (const void*)relay,
#endif
};
#endif /* !MB_CM_CLIENT */

/* ---- flash ------------------------------------------------------------------- */
static int f_read(uint32_t off, void* buf, size_t n) {
    if (off > MB_FLASH_SIZE || n > MB_FLASH_SIZE - off) return MB_E_BADARG;
    memcpy(buf, (const void*)(uintptr_t)(MB_FLASH_BASE + off), n);
    return MB_OK;
}
static int f_erase(uint32_t off, size_t n) {
    if (off < layout.boot.size) return MB_E_REFUSED;         // never the bootloader itself
    return mcu_flash_erase(off, n);
}
static int f_program(uint32_t off, const void* b, size_t n) {
    if (off < layout.boot.size) return MB_E_REFUSED;
    return mcu_flash_program(off, b, n);
}

#ifdef MB_CM_CLIENT
/* ---- the app side: what client/mb_client.c needs (flash + layout + reboot) ------------ */
static void client_reboot(void) {
    __asm volatile("dsb" ::: "memory");
    REG32(SCB_AIRCR) = 0x05FA0004u;
    for (;;) {}
}
/* an address inside the slot holding the running image's vector table */
static uint32_t active_table(void) {
#if MB_VECTORS == MB_VECTORS_RELAY
    return REG32(MB_RELAY_ADDR);
#elif MB_VECTORS == MB_VECTORS_REMAP
    return REG32(MB_RAM_BASE + 4) & ~1u;    // the copied reset vector points into the slot
#else
    return REG32(SCB_VTOR);
#endif
}
static int client_self_slot(void) {
    uint32_t v = active_table();
    for (int i = 0; i < layout.n_slots; i++) {
        uint32_t lo = MB_FLASH_BASE + layout.slot[i].offset;
        if (v >= lo && v - lo < layout.slot[i].size) return i;
    }
    return MB_SLOT_NONE;
}
const mb_port_t mb_mcu_port = {
    .name = MB_BOARD_NAME, .target = MB_TARGET, .layout = &layout, .arch = MB_ARCH_ARM,
    .keys = KEYRING, .require_signature = MB_REQUIRE_SIGNATURE,
    .flash_read = f_read, .flash_erase = f_erase, .flash_program = f_program, .reboot = client_reboot,
    .self_slot = client_self_slot,
};
#else

/* ---- memory the image (and the handoff) may use: RAM below the loader's own --------- */
static bool in_ram(uint32_t a, uint32_t n) {
    return (a >= MB_RAM_BASE + MB_RAM_RESERVED && a < MB_LOADER_RAM && n <= MB_LOADER_RAM - a);
}
static void* ram_ptr(uint32_t a, uint32_t n) { return in_ram(a, n) ? (void*)(uintptr_t)a : NULL; }
static bool sp_ok(uint32_t sp) {
    if (sp & 3) return false;
    if (sp > MB_RAM_BASE && sp <= MB_RAM_BASE + MB_RAM_SIZE) return true;
    return MB_RAM2_SIZE && sp > MB_RAM2_BASE && sp <= MB_RAM2_BASE + MB_RAM2_SIZE;
}

/* ---- starting an image --------------------------------------------------------------- */
static void quiesce(void) {
    __asm volatile("cpsid i" ::: "memory");
    REG32(SYST_CSR) = 0;
    for (int i = 0; i < MB_NVIC_WORDS; i++) {
        REG32(NVIC_ICER0 + 4u * (uint32_t)i) = 0xFFFFFFFFu;
        REG32(NVIC_ICPR0 + 4u * (uint32_t)i) = 0xFFFFFFFFu;
    }
    REG32(SCB_ICSR) = ICSR_PENDSTCLR | ICSR_PENDSVCLR;
    mcu_uart_deinit();
    mcu_pins_release();
    mcu_restore();
}

/* MB_FEAT_SCRUB_RAM: on the way out, zero the bootloader's whole RAM region
 * (its data, the boot log copy, config text, key material on the stack...),
 * from registers only, so the image starts with nothing of the loader in RAM. */
static void __attribute__((noreturn, naked)) jump(uint32_t sp, uint32_t pc) {
    __asm volatile(
        ".syntax unified\n"
#if MB_FEAT_SCRUB_RAM
        "ldr  r2, 3f\n"
        "ldr  r3, 4f\n"
        "movs r4, #0\n"
        "1:   cmp  r2, r3\n"
        "bhs  2f\n"
        "str  r4, [r2]\n"
        "adds r2, #4\n"
        "b    1b\n"
        "2:\n"
#endif
        "msr msp, r0\n"
        "movs r2, #0\n"
        "msr control, r2\n"     // privileged, MSP
        "isb\n"
        "cpsie i\n"
        "bx r1\n"
#if MB_FEAT_SCRUB_RAM
        ".align 2\n"
        "3: .word " STR(MB_LOADER_RAM_ASM) "\n"
        "4: .word " STR(MB_RAM_END_ASM) "\n"
#endif
    );
}

static int start(uint32_t vectors, uint32_t lo, uint32_t hi) {
    if (vectors & (MB_VTOR_ALIGN - 1)) return MB_E_CORRUPT;  // VTOR can't point there
    uint32_t sp = REG32(vectors), pc = REG32(vectors + 4);
    if (!sp_ok(sp) || !(pc & 1) || (pc & ~1u) < lo || (pc & ~1u) >= hi) return MB_E_CORRUPT;
    quiesce();
#if MB_VECTORS == MB_VECTORS_REMAP
    mcu_remap_vectors(vectors);
#elif MB_VECTORS == MB_VECTORS_RELAY
    REG32(MB_RELAY_ADDR) = vectors;
#else
    REG32(SCB_VTOR) = vectors;
#endif
    __asm volatile("dsb\n isb" ::: "memory");
    jump(sp, pc);
}

static bool can_start(const mb_image_hdr_t* h) {
    if (h->arch != MB_ARCH_ANY && h->arch != MB_ARCH_ARM) return false;
    if (h->load_type == MB_LOAD_CHAIN) return true;
    return h->load_type == MB_LOAD_RAM && in_ram(h->load_addr, h->payload_size);
}

static int launch(const mb_image_hdr_t* h, uint32_t slot_off, uint32_t slot_size) {
    uint32_t base = MB_FLASH_BASE + slot_off;
    return start(base + h->payload_offset, base, base + slot_size);
}

static int launch_ram(const mb_image_hdr_t* h) {
    if (!can_start(h) || h->load_type != MB_LOAD_RAM) return MB_E_REFUSED;
    uint32_t v = h->entry ? h->entry : h->load_addr;
    if (v < h->load_addr || v - h->load_addr > h->payload_size - 8) return MB_E_CORRUPT;
    return start(v, h->load_addr, h->load_addr + h->payload_size);
}

/* ---- console, time, watchdog, resets ------------------------------------------------ */
static uint32_t time_ms(void) { return now_ms(); }
static bool console_open(uint32_t wait_ms) { (void)wait_ms; return true; }    // a UART is always "there"
static int  getc_port(uint32_t ms) {
    uint32_t t0 = now_ms();
    do {
        int c = mcu_uart_getc();
        if (c >= 0) return c;
        mcu_wdt_feed();                                     // a person at the menu isn't a hang
    } while (now_ms() - t0 < ms);
    return -1;
}
static void write_port(const char* s, size_t n) { while (n--) mcu_uart_putc(*s++); }
static void wd_arm(uint32_t ms) { mcu_wdt_start(ms); }
static void wd_off(void) { mcu_wdt_disarm(); }
static void reboot(void) {
    mcu_uart_deinit();
    __asm volatile("dsb" ::: "memory");
    REG32(SCB_AIRCR) = 0x05FA0004u;                         // SYSRESETREQ
    for (;;) {}
}
#ifdef MB_SYSMEM_ADDR
static void reboot_rom(void) {
    // the chip's own system-memory loader (STM32: USART / USB DFU / I2C ...)
    uint32_t sp = REG32(MB_SYSMEM_ADDR), pc = REG32(MB_SYSMEM_ADDR + 4);
    quiesce();
#if MB_VECTORS == MB_VECTORS_VTOR
    REG32(SCB_VTOR) = MB_SYSMEM_ADDR;
#endif
    jump(sp, pc);
}
#define REBOOT_ROM reboot_rom
#else
#define REBOOT_ROM NULL                     // no ROM loader on this chip (nRF, SAM D): the menu stays
#endif
static uint32_t cause(void) { return reset_flags; }
static const char* reason(void) {
    return reset_flags & MB_RESET_WATCHDOG ? "watchdog" : reset_flags & MB_RESET_SOFT ? "software reset" : "power-on/pin";
}

// The menu key: the board button, or a key on the UART soon after reset.
static bool button(void) {
    if (mcu_button()) return true;
    mcu_led(true);
    uint32_t t0 = now_ms();
    bool hit = false;
    while (!hit && now_ms() - t0 < MB_BREAK_IN_MS) {
        hit = mcu_uart_getc() >= 0;
        mcu_wdt_feed();
    }
    mcu_led(false);
    return hit;
}
static uint32_t caps(void) { return MB_CAP_CONTROL | MB_CAP_CONFIG | MB_CAP_RAM | MB_CAP_ARM | MB_CAP_XIP; }

const mb_port_t mb_mcu_port = {
    .name = MB_BOARD_NAME, .target = MB_TARGET, .layout = &layout, .arch = MB_ARCH_ARM,
    .keys = KEYRING, .require_signature = MB_REQUIRE_SIGNATURE,
    .flash_read = f_read, .flash_erase = f_erase, .flash_program = f_program,
    .can_start = can_start, .launch = launch, .ram_ptr = ram_ptr, .launch_ram = launch_ram,
    .time_ms = time_ms, .watchdog_arm = wd_arm, .watchdog_disarm = wd_off, .button = button,
    .console_open = console_open, .getc = getc_port, .write = write_port,
    .reboot = reboot, .reboot_rom = REBOOT_ROM, .reset_cause = cause, .reset_reason = reason,
    .capabilities = caps,
};

int main(void) {
    reset_flags = mcu_reset_flags_take();
    mcu_init();
    mcu_wdt_feed();                                         // a watchdog the last app left running
#if MB_TIME_SYSTICK
    REG32(SYST_RVR) = MB_CLOCK_HZ / 1000u - 1u;             // 1 ms
    REG32(SYST_CVR) = 0;
    REG32(SYST_CSR) = 7;                                    // core clock, interrupt, enable
#endif
    mcu_uart_init();
    mb_main(&mb_mcu_port);
    return 0;
}

#endif /* MB_CM_CLIENT */
