/*
 * MimiBoot-Mu - bare-metal Cortex-M port of the Komorebi core (STM32, nRF, SAMD)
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

#if defined(MB_TRUSTED_KEY_COUNT) && !defined(MB_CM_STAGE0)   /* stage 0 trusts the stage-1 keys only */
static const uint8_t trusted[MB_TRUSTED_KEY_COUNT][32] = MB_TRUSTED_KEYS;
static const mb_keyring_t keyring = { MB_TRUSTED_KEY_COUNT, trusted };
#define KEYRING (&keyring)
#else
#define KEYRING NULL
#endif
#ifndef MB_REQUIRE_SIGNATURE
#define MB_REQUIRE_SIGNATURE 0
#endif
#if defined(MB_TRUSTED_P256_KEY_COUNT) && MB_FEAT_ECDSA && !defined(MB_CM_STAGE0)
static const uint8_t trusted_p256[MB_TRUSTED_P256_KEY_COUNT][64] = MB_TRUSTED_P256_KEYS;
static const mb_keyring_p256_t p256_ring = { MB_TRUSTED_P256_KEY_COUNT, trusted_p256 };
#define P256_RING (&p256_ring)
#else
#define P256_RING NULL
#endif
#if defined(MB_UNLOCK_KEY_COUNT) && !defined(MB_CM_CLIENT) && !defined(MB_CM_STAGE0)
static const uint8_t unlock_trusted[MB_UNLOCK_KEY_COUNT][32] = MB_UNLOCK_KEYS;
static const mb_keyring_t unlock_ring = { MB_UNLOCK_KEY_COUNT, unlock_trusted };
#define UNLOCK_RING (&unlock_ring)
#else
#define UNLOCK_RING NULL
#endif
#if MB_FEAT_LMS && defined(MB_TRUSTED_LMS_KEY_COUNT) && !defined(MB_CM_STAGE0)
static const uint8_t trusted_lms[MB_TRUSTED_LMS_KEY_COUNT][MB_LMS_PUB_MAX] = MB_TRUSTED_LMS_KEYS;
static const mb_keyring_lms_t lms_ring = {MB_TRUSTED_LMS_KEY_COUNT, trusted_lms};
#define LMS_RING (&lms_ring)
#else
#define LMS_RING NULL
#endif
#if MB_FEAT_LMS && MB_FEAT_TWO_STAGE && defined(MB_S1_LMS_KEY_COUNT) && !defined(MB_CM_CLIENT)
static const uint8_t s1_trusted_lms[MB_S1_LMS_KEY_COUNT][MB_LMS_PUB_MAX] = MB_S1_LMS_KEYS;
static const mb_keyring_lms_t s1_lms_ring = {MB_S1_LMS_KEY_COUNT, s1_trusted_lms};
#define S1_LMS_RING (&s1_lms_ring)
#else
#define S1_LMS_RING NULL
#endif
/* Two-stage builds: the keys stage 0 accepts stage 1 images from (S1_KEYS),
 * separate from the app keys. Stage 1 carries them too, to refuse a badly
 * signed upload at once. */
#if MB_FEAT_TWO_STAGE && defined(MB_S1_KEY_COUNT) && !defined(MB_CM_CLIENT)
static const uint8_t s1_trusted[MB_S1_KEY_COUNT][32] = MB_S1_KEYS;
static const mb_keyring_t s1_ring = { MB_S1_KEY_COUNT, s1_trusted };
#define S1_RING (&s1_ring)
#else
#define S1_RING NULL
#endif
#if MB_FEAT_TWO_STAGE && defined(MB_S1_P256_KEY_COUNT) && MB_FEAT_ECDSA && !defined(MB_CM_CLIENT)
static const uint8_t s1_trusted_p256[MB_S1_P256_KEY_COUNT][64] = MB_S1_P256_KEYS;
static const mb_keyring_p256_t s1_p256_ring = { MB_S1_P256_KEY_COUNT, s1_trusted_p256 };
#define S1_P256_RING (&s1_p256_ring)
#else
#define S1_P256_RING NULL
#endif
/* key revocation (REVOKE_KEYS): every stage and the app side honour revocations;
 * only the bootloader's console records new ones */
#ifdef MB_REVOKE_KEY_COUNT
static const uint8_t revoke_trusted[MB_REVOKE_KEY_COUNT][32] = MB_REVOKE_KEYS;
static const mb_keyring_t revoke_ring = { MB_REVOKE_KEY_COUNT, revoke_trusted };
#define REVOKE_RING (&revoke_ring)
#else
#define REVOKE_RING NULL
#endif
#if MB_FEAT_BOOT_RECORD && !defined(MB_CM_CLIENT) && !defined(MB_CM_STAGE0)
// Measured boot: the bootloader's own image, from the linker script's bounds (= mimiboot.bin)
extern const uint8_t _mb_image_start[], _mb_image_end[];
static int loader_hash(uint8_t out[32]) {
    mb_sha256_t s;
    mb_sha256_init(&s);
    mb_sha256_update(&s, _mb_image_start, (size_t)(_mb_image_end - _mb_image_start));
    mb_sha256_final(&s, out);
    return MB_OK;
}
#define LOADER_HASH loader_hash
#else
#define LOADER_HASH NULL
#endif
#if defined(MB_ENC_KEY) && MB_FEAT_ENC && !defined(MB_CM_CLIENT) && !defined(MB_CM_STAGE0)
static const uint8_t enc_key[32] = MB_ENC_KEY;     // the board's X25519 decryption key (ENC_KEY)
#define ENC_KEY enc_key
#else
#define ENC_KEY NULL
#endif
#if defined(MB_VENDOR_NRF) && MB_FEAT_CONSOLE_AUTH && !defined(MB_CM_CLIENT) && !defined(MB_CM_STAGE0)
#define RANDOM mcu_random
#else
#define RANDOM NULL
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
#ifndef MB_CM_STAGE0
static uint32_t now_ms(void) { return ticks; }
#endif
#elif !defined(MB_CM_STAGE0)
static uint32_t now_ms(void) { return mcu_time_ms(); }
#endif
#ifndef MB_CM_STAGE0
static uint32_t reset_flags;
#endif

/* ---- startup ---------------------------------------------------------------- */
extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
int main(void);

extern const void* const mb_vectors[];

void Reset_Handler(void) {
#if MB_VECTORS == MB_VECTORS_RELAY && defined(MB_CM_STAGE1)
    // stage 0's table (at address 0) relays here: our exceptions go to our handlers
    REG32(MB_RELAY_ADDR) = (uint32_t)(uintptr_t)mb_vectors;
#elif MB_VECTORS == MB_VECTORS_RELAY
    REG32(MB_RELAY_ADDR) = 0;               // our own exceptions until an image starts
#endif
    uint32_t *s = &_sidata, *d = &_sdata;
    while (d < &_edata) *d++ = *s++;
    for (d = &_sbss; d < &_ebss;) *d++ = 0;
    main();
    for (;;) {}
}

/* A fault (HardFault, NMI: a flash ECC error, a bus error reading a damaged
 * slot, a bug) used to spin here until someone power-cycled the board. Now it
 * leaves a note in RAM that survives the reset (.noinit, checked with a magic
 * and a complement) saying which slot was being checked, and resets; the next
 * boot marks that slot bad and falls back (mb_main). */
/* Two-stage builds put .noinit at the same address in both stages (first in
 * their RAM, same RAM size), with a magic each: one stage never consumes the
 * other's note. */
#ifdef MB_CM_STAGE0
#define CRUMB_MAGIC 0x3054424Du                     /* "MBT0" */
#else
#define CRUMB_MAGIC 0x4D424654u                     /* "MBFT" */
#endif
__attribute__((section(".noinit"))) static volatile uint32_t crumb[3];

void mb_cm_fault(void) {
    uint32_t s = mb_checking_slot;
    crumb[0] = CRUMB_MAGIC;
    crumb[1] = s;
    crumb[2] = ~s;
    __asm volatile("dsb" ::: "memory");
    REG32(SCB_AIRCR) = 0x05FA0004u;                 // SYSRESETREQ
    for (;;) {}
}

static int fault_slot(void) {
    int s = -1;
    if (crumb[0] != CRUMB_MAGIC) return -1;         // nothing, or the other stage's note: leave it
    if (crumb[2] == ~crumb[1] && crumb[1] < MB_SLOT_NONE) s = (int)crumb[1];
    crumb[0] = 0;
    return s;
}

#if MB_VECTORS == MB_VECTORS_RELAY && defined(MB_CM_STAGE1)
/* Stage 1 on a chip without VTOR: the hardware uses stage 0's table, which
 * relays to this one, so this one must hold real handlers (a relay here would
 * relay to itself). The bootloader uses no interrupts: every entry faults. */
#define Fault_Handler mb_cm_fault
#define H(x) ((const void*)(x))
#define N_VECTORS (16 + MB_IRQS)
#define RELAY_IRQS mb_cm_fault
#elif MB_VECTORS == MB_VECTORS_RELAY
/* Forward exception n to entry n of the table at *MB_RELAY_ADDR. r0/r1 are
 * already stacked by the exception entry and lr holds EXC_RETURN, so the
 * image's handler runs exactly as if the hardware had called it. While the
 * bootloader runs (word = 0) a fault goes to mb_cm_fault. */
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
        "2: ldr r0, 3f\n"
        "bx   r0\n"
        ".align 2\n"
        "1: .word " STR(MB_RELAY_ADDR) "\n"
        "3: .word mb_cm_fault\n");
}
#define H(x) ((const void*)relay)
#define N_VECTORS (16 + MB_IRQS)
#define RELAY_IRQS relay
#else
#define Fault_Handler mb_cm_fault
#define H(x) ((const void*)(x))
#if MB_CONSOLE_USB
#define N_VECTORS (16 + MB_USB_IRQ_LAST + 1)     /* up to the USB interrupt(s); the rest fault */
#else
#define N_VECTORS 16
#endif
#endif

#if MB_TIME_SYSTICK
void SysTick_Handler(void) { ticks++; }
#else
#define SysTick_Handler mb_cm_fault
#endif

__attribute__((section(".isr_vector"), used)) const void* const mb_vectors[N_VECTORS] = {
    &_estack, (const void*)Reset_Handler, H(Fault_Handler), H(Fault_Handler),
    H(Fault_Handler), H(Fault_Handler), H(Fault_Handler), 0, 0, 0, 0,
    H(Fault_Handler), H(Fault_Handler), 0, H(Fault_Handler), H(SysTick_Handler),
#if MB_VECTORS == MB_VECTORS_RELAY
    [16 ... N_VECTORS - 1] = (const void*)RELAY_IRQS,
#elif MB_CONSOLE_USB
    [16 ... 16 + MB_USB_IRQ_FIRST - 1] = (const void*)mb_cm_fault,
    [16 + MB_USB_IRQ_FIRST ... 16 + MB_USB_IRQ_LAST] = (const void*)mb_usb_irq,
#endif
};
#endif /* !MB_CM_CLIENT */

/* ---- flash ------------------------------------------------------------------- */
static int f_read(uint32_t off, void* buf, size_t n) {
    if (off > MB_FLASH_SIZE || n > MB_FLASH_SIZE - off) return MB_E_BADARG;
    memcpy(buf, (const void*)(uintptr_t)(MB_FLASH_BASE + off), n);
    return MB_OK;
}
/* Never the bootloader itself: the boot region (stage 0 and the store, in a
 * two-stage build), the stage 1 that is running, and from an app, either
 * stage-1 copy (stage 1 is updated through MimiBoot's own console only).
 * Stage 0 writes nothing but the store. */
#ifndef MB_CM_STAGE0
static bool own_flash(uint32_t off, size_t n) {
    if (off < layout.boot.size) return true;
#if MB_FEAT_TWO_STAGE
    for (int i = 0; i < layout.n_slots; i++) {
        const mb_slot_def_t* s = &layout.slot[i];
        if (s->role != MB_ROLE_STAGE1 || off >= s->offset + s->size || off + n <= s->offset) continue;
#if defined(MB_CM_CLIENT)
        return true;
#elif defined(MB_CM_STAGE1)
        if (i == MB_STAGE1_SLOT) return true;
#endif
    }
#endif
    (void)n;
    return false;
}
static int f_erase(uint32_t off, size_t n) {
    if (own_flash(off, n)) return MB_E_REFUSED;
    return mcu_flash_erase(off, n);
}
static int f_program(uint32_t off, const void* b, size_t n) {
    if (own_flash(off, n)) return MB_E_REFUSED;
    return mcu_flash_program(off, b, n);
}
#endif

/* The rollback floors' store: the last erase unit of the bootloader region
 * (the linker keeps code out of it). Only the bootloader writes it, and only
 * before the region is locked; the app side reads it. Two-stage builds always
 * have it: stage 0 keeps its stage-1 records there. */
#if MB_FEAT_PROTECTED_FLOOR || MB_FEAT_TWO_STAGE
#ifndef MB_CM_CLIENT
static int floor_program(uint32_t off, const void* b, size_t n) {
    // off below the store wraps to a huge difference: refused by the same test
    if (n > MB_FLOOR_SIZE || (uint32_t)(off - MB_FLOOR_OFF) > MB_FLOOR_SIZE - n) return MB_E_BADARG;
    return mcu_flash_program(off, b, n);
}
#define FLOOR_PROGRAM floor_program
#if defined(MB_FLOOR_UNIT) && MB_FLOOR_UNIT
// two erase units: a full one is compacted into the other (core/mb_floor.c)
static int floor_erase(uint32_t off, size_t n) {
    if (off % MB_FLOOR_UNIT || n != MB_FLOOR_UNIT || (uint32_t)(off - MB_FLOOR_OFF) > MB_FLOOR_SIZE - n) return MB_E_BADARG;
    return mcu_flash_erase(off, n);
}
#define FLOOR_ERASE floor_erase
#define FLOOR_UNIT MB_FLOOR_UNIT
#endif
#else
#define FLOOR_PROGRAM NULL
#endif
#ifndef FLOOR_ERASE
#define FLOOR_ERASE NULL
#define FLOOR_UNIT 0
#endif
static const mb_floor_store_t floor_store = { .off = MB_FLOOR_OFF, .size = MB_FLOOR_SIZE, .entry = MB_FLOOR_ENTRY,
                                              .read = f_read, .program = FLOOR_PROGRAM, .unit = FLOOR_UNIT,
                                              .erase = FLOOR_ERASE };
#define FLOOR (&floor_store)
#else
#define FLOOR NULL
#endif

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
#ifdef MB_VENDOR_NRF
// POWER->SYSTEMOFF (0x40000500 on nRF51 and nRF52): off until a wake-up source (a
// GPIO with SENSE, NFC, a reset) starts the chip again, through the bootloader
static void client_poweroff(void) {
    *(volatile uint32_t*)0x40000500u = 1;
    for (;;) __asm volatile("wfe");
}
#define POWEROFF client_poweroff
#else
#define POWEROFF NULL
#endif
const mb_port_t mb_mcu_port = {
    .name = MB_BOARD_NAME, .target = MB_TARGET, .layout = &layout, .arch = MB_ARCH_ARM,
    .keys = KEYRING, .p256_keys = P256_RING, .lms_keys = LMS_RING, .require_signature = MB_REQUIRE_SIGNATURE,
    .flash_read = f_read, .flash_erase = f_erase, .flash_program = f_program, .reboot = client_reboot,
    .self_slot = client_self_slot, .floor = FLOOR, .revoke_keys = REVOKE_RING,
    .retains_ram = true, .poweroff = POWEROFF,
};
#else

/* ---- memory the image (and the handoff) may use: RAM below the loader's own --------- */
static bool in_ram(uint32_t a, uint32_t n) {
    return (a >= MB_RAM_BASE + MB_RAM_RESERVED && a < MB_LOADER_RAM && n <= MB_LOADER_RAM - a);
}
#ifndef MB_CM_STAGE0
static void* ram_ptr(uint32_t a, uint32_t n) { return in_ram(a, n) ? (void*)(uintptr_t)a : NULL; }
#endif
static bool sp_ok(uint32_t sp) {
    if (sp & 3) return false;
    if (sp > MB_RAM_BASE && sp <= MB_RAM_BASE + MB_RAM_SIZE) return true;
    return MB_RAM2_SIZE && sp > MB_RAM2_BASE && sp <= MB_RAM2_BASE + MB_RAM2_SIZE;
}

/* ---- starting an image --------------------------------------------------------------- */
static void quiesce(void) {
#if MB_CONSOLE_USB && !defined(MB_CM_STAGE0)
    // first, while interrupts and the millisecond clock still run: USB flushes,
    // detaches, and its 48 MHz clock goes off, so the app starts clean
    mcu_usb_close();
#endif
    __asm volatile("cpsid i" ::: "memory");
    REG32(SYST_CSR) = 0;
    for (int i = 0; i < MB_NVIC_WORDS; i++) {
        REG32(NVIC_ICER0 + 4u * (uint32_t)i) = 0xFFFFFFFFu;
        REG32(NVIC_ICPR0 + 4u * (uint32_t)i) = 0xFFFFFFFFu;
    }
    REG32(SCB_ICSR) = ICSR_PENDSTCLR | ICSR_PENDSVCLR;
#ifndef MB_CM_STAGE0
    // stage 0 never opened the UART or the pins: "closing" them would wait on
    // status bits of a peripheral whose clock was never on (STM32 TC, SAM D SYNCBUSY)
#if !MB_CONSOLE_USB
    mcu_uart_deinit();
#endif
    mcu_pins_release();
#endif
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
#if MB_FEAT_BOOT_LOCK && !defined(MB_CM_STAGE0)
    // The image gets the chip with the bootloader (code, keys, rollback floors)
    // write-protected until the next reset. Every bootloader write is done by
    // now. A lock that doesn't take is not a reason to stop booting: the board
    // would be bricked by its own protection. (Stage 0 doesn't lock: stage 1
    // still has to write the store.)
    (void)mcu_flash_lock(layout.boot.offset, layout.boot.size);
#if MB_FEAT_TWO_STAGE
    // both stage-1 copies: the app may neither replace the bootloader nor erase its way back
    for (int i = 0; i < layout.n_slots; i++)
        if (layout.slot[i].role == MB_ROLE_STAGE1) (void)mcu_flash_lock(layout.slot[i].offset, layout.slot[i].size);
#endif
#if MB_FEAT_LOCK_GOLDEN
    // and the recovery image: what the board falls back to must survive the app
    for (int i = 0; i < layout.n_slots; i++)
        if (layout.slot[i].role == MB_ROLE_GOLDEN) (void)mcu_flash_lock(layout.slot[i].offset, layout.slot[i].size);
#endif
#endif
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

#ifdef MB_CM_STAGE0
/* ---- stage 0 (two-stage builds): pick a stage 1 and start it ------------------------- */
static const mb_port_t stage0_port = {
    .name = MB_BOARD_NAME, .target = MB_TARGET, .layout = &layout, .arch = MB_ARCH_ARM,
    .keys = S1_RING, .p256_keys = S1_P256_RING, .stage1_keys = S1_RING, .stage1_p256_keys = S1_P256_RING,
    .lms_keys = S1_LMS_RING, .stage1_lms_keys = S1_LMS_RING,
    .require_signature = MB_REQUIRE_SIGNATURE, .flash_base = MB_FLASH_BASE, .revoke_keys = REVOKE_RING,
    .flash_read = f_read, .can_start = can_start, .floor = FLOOR, .fault_slot = fault_slot,
};

int main(void) {
    // no UART and no reset-cause read here: stage 1 sets those up and needs the
    // reset flags as the hardware left them (watchdog resets, crash guard)
    mcu_init();
    mcu_wdt_feed();
    mb_stage0_choice_t c;
    if (mb_stage0_choose(&stage0_port, &c) == MB_OK) {
        const mb_slot_def_t* s = &layout.slot[c.slot];
        (void)launch(&c.info.hdr, s->offset, s->size);      // returns only if the vector table is bad
    }
    // no stage 1 to start: the chip's own loader where there is one, else wait
    // for a debugger (SWD can always reflash)
#ifdef MB_SYSMEM_ADDR
    reboot_rom();
#endif
    for (;;) mcu_wdt_feed();
}
#else

static int launch_ram(const mb_image_hdr_t* h) {
    if (!can_start(h) || h->load_type != MB_LOAD_RAM) return MB_E_REFUSED;
    uint32_t v = h->entry ? h->entry : h->load_addr;
    if (v < h->load_addr || v - h->load_addr > h->payload_size - 8) return MB_E_CORRUPT;
    return start(v, h->load_addr, h->load_addr + h->payload_size);
}

/* ---- console, time, watchdog, resets ------------------------------------------------ */
static uint32_t time_ms(void) { return now_ms(); }
uint32_t mb_cm_ms(void) { return now_ms(); }
#if MB_CONSOLE_USB
// native USB: it comes up only now, and "someone is there" means a terminal opened the port
static bool console_open(uint32_t wait_ms) { return mcu_usb_open(wait_ms); }
static int  con_rx(void) { return mcu_usb_getc(); }
static void write_port(const char* s, size_t n) { mcu_usb_write(s, n); }
#else
static bool console_open(uint32_t wait_ms) { (void)wait_ms; return true; }    // a UART is always "there"
static int  con_rx(void) { return mcu_uart_getc(); }
static void write_port(const char* s, size_t n) { while (n--) mcu_uart_putc(*s++); }
#endif
static int  getc_port(uint32_t ms) {
    uint32_t t0 = now_ms();
    do {
        int c = con_rx();
        if (c >= 0) return c;
        mcu_wdt_feed();                                     // a person at the menu isn't a hang
    } while (now_ms() - t0 < ms);
    return -1;
}
static void wd_arm(uint32_t ms) { mcu_wdt_start(ms); }
static void wd_off(void) { mcu_wdt_disarm(); }
static void reboot(void) {
#if MB_CONSOLE_USB
    mcu_usb_close();                                        // the host sees it go (the UART was never opened)
#else
    mcu_uart_deinit();
#endif
    __asm volatile("dsb" ::: "memory");
    REG32(SCB_AIRCR) = 0x05FA0004u;                         // SYSRESETREQ
    for (;;) {}
}
static uint32_t cause(void) { return reset_flags; }
static const char* reason(void) {
    return reset_flags & MB_RESET_WATCHDOG ? "watchdog" : reset_flags & MB_RESET_SOFT ? "software reset" : "power-on/pin";
}

// The menu key: the board button, or a key on the UART soon after reset.
// (Over USB there is no early key: the port isn't up yet. The button, an app's
// request or nothing bootable open it.)
static bool button(void) {
    if (mcu_button()) return true;
    if (MB_CONSOLE_USB) return false;
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

/* for the console's security line: what this port does to protect the bootloader */
#if MB_FEAT_BOOT_LOCK
#define LOCK_TXT "bootloader flash locked at handoff"
#elif defined(MB_VENDOR_NRF)
#define LOCK_TXT "bootloader flash NOT locked (BOOT_LOCK off)"
#else
#define LOCK_TXT "bootloader flash: lock with option bytes/fuses (mbtool provision)"
#endif
#if defined(MB_VENDOR_NRF) && MB_FEAT_DEBUG_LOCK
#define DEBUG_TXT ", debug forced shut"
#elif defined(MB_VENDOR_NRF)
#define DEBUG_TXT ", debug as UICR says"
#else
#define DEBUG_TXT ""
#endif

#ifdef MB_CM_STAGE1
static int stage1_slot(void) { return MB_STAGE1_SLOT; }    // linked for this copy, so it runs from this copy
#define STAGE1_SLOT stage1_slot
#else
#define STAGE1_SLOT NULL
#endif

const mb_port_t mb_mcu_port = {
    .name = MB_BOARD_NAME, .target = MB_TARGET, .layout = &layout, .arch = MB_ARCH_ARM,
    .keys = KEYRING, .p256_keys = P256_RING, .lms_keys = LMS_RING, .require_signature = MB_REQUIRE_SIGNATURE, .unlock_keys = UNLOCK_RING, .random = RANDOM,
    .flash_read = f_read, .flash_erase = f_erase, .flash_program = f_program,
    .can_start = can_start, .launch = launch, .ram_ptr = ram_ptr, .launch_ram = launch_ram,
    .time_ms = time_ms, .watchdog_arm = wd_arm, .watchdog_disarm = wd_off, .button = button,
    .console_open = console_open, .getc = getc_port, .write = write_port,
    .reboot = reboot, .reboot_rom = REBOOT_ROM, .reset_cause = cause, .reset_reason = reason,
    .capabilities = caps, .floor = FLOOR, .fault_slot = fault_slot, .lockdown = LOCK_TXT DEBUG_TXT,
    .stage1_slot = STAGE1_SLOT, .stage1_keys = S1_RING, .stage1_p256_keys = S1_P256_RING, .stage1_lms_keys = S1_LMS_RING, .flash_base = MB_FLASH_BASE, .revoke_keys = REVOKE_RING,
    .enc_key = ENC_KEY, .loader_hash = LOADER_HASH,
    .retains_ram = true,    /* SRAM keeps its contents across a soft or watchdog reset on these parts */
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
#if !MB_CONSOLE_USB
    mcu_uart_init();
#endif
    mb_main(&mb_mcu_port);
    return 0;
}

#endif /* MB_CM_STAGE0 */
#endif /* MB_CM_CLIENT */
