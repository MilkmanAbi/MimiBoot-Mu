/*
 * Emulator test payload for nRF51 (QEMU microbit): what MimiBoot starts.
 * Cortex-M0 has no VTOR, so MimiBoot relays exceptions through its own table
 * to the table whose address it left in the RAM word at 0x20000000. This app
 * raises an SVC and an NVIC interrupt and counts that its handlers ran.
 *
 * Last, it probes the emulator: a flash write without NVMC write-enable must
 * not change flash, or the bootloader's flash tests would prove nothing.
 */
#include <stdint.h>
#include "mimiboot/mb_handoff.h"

#ifndef NAME
#define NAME "app"
#endif
#ifndef PROBE
#define PROBE 0x0003FFFCu          /* last word of a 256 KB nRF51 */
#endif
#define R(a) (*(volatile uint32_t*)(uintptr_t)(a))
#define U 0x40002000u
#define IRQN 20

__attribute__((section(".noinit.mb_handoff"), used, aligned(8))) volatile mb_handoff_t mb_handoff;
extern uint32_t _estack;
void reset(void);
static volatile uint32_t svc_hits, irq_hits;
static void spin(void) { for (;;) {} }
static void on_svc(void) { svc_hits++; }
static void on_irq(void) { irq_hits++; }

__attribute__((section(".isr_vector"), used)) const void* const vt[48] = {
    &_estack, (const void*)reset, (const void*)spin, (const void*)spin, 0, 0, 0, 0, 0, 0, 0,
    (const void*)on_svc, 0, 0, (const void*)spin, (const void*)spin,
    [16 ... 47] = (const void*)spin,
    [16 + IRQN] = (const void*)on_irq,
};

static void putc_(char c) {
    R(U + 0x11C) = 0;                       // EVENTS_TXDRDY
    R(U + 0x51C) = (uint8_t)c;              // TXD
    for (uint32_t n = 0; !R(U + 0x11C) && n < 1000000u; n++) {}
}
static void puts_(const char* s) { while (*s) putc_(*s++); }
static void putv(const volatile char* s, int n) { for (int i = 0; i < n && s[i]; i++) putc_(s[i]); }
static void hex(uint32_t v) { for (int i = 28; i >= 0; i -= 4) putc_("0123456789abcdef"[(v >> i) & 15]); }

void reset(void) {
    svc_hits = irq_hits = 0;
    R(U + 0x50C) = 24;                      // PSELTXD (micro:bit TX)
    R(U + 0x500) = 4;                       // ENABLE: UART
    R(U + 0x008) = 1;                       // STARTTX
#ifdef CHECK_LO
    // the bootloader's RAM region (below our small stack at the top): how much of it isn't zero?
    uint32_t dirty = 0;
    for (uint32_t a = CHECK_LO; a < CHECK_HI; a += 4) dirty += R(a) != 0;
#endif
    uint32_t pm;
    __asm volatile("mrs %0, primask" : "=r"(pm));
    puts_("\r\nMU-APP " NAME " relay=");
    hex(R(0x20000000));
    puts_(" primask=");
    hex(pm);
    __asm volatile("svc 0" ::: "memory");
    R(0xE000E100) = 1u << IRQN;             // NVIC ISER
    R(0xE000E200) = 1u << IRQN;             // NVIC ISPR: taken right away
    __asm volatile("dsb\n isb" ::: "memory");
#ifdef CHECK_LO
    puts_(" loaderram-dirty=");
    hex(dirty);
#endif
    puts_(" svc=");
    hex(svc_hits);
    puts_(" irq=");
    hex(irq_hits);
    if (mb_handoff.magic == MB_HANDOFF_MAGIC) {
        puts_(" slot=");
        putv(mb_handoff.slot_name, 8);
        puts_(" args=[");
        putv(mb_handoff.args, 96);
        puts_("]");
    } else {
        puts_(" no-handoff");
    }
    if (R(PROBE) == 0xFFFFFFFFu) {          // the emulator's NVMC must ignore writes without WEN
        R(0x4001E504) = 0;                  // CONFIG = read-only
        R(PROBE) = 0;
        puts_(" nowen=");
        hex(R(PROBE));
    }
    puts_("\r\nMU-APP-DONE\r\n");
    for (;;) {}
}
