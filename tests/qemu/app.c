/*
 * Emulator test payload: what MimiBoot starts. Prints where it runs (VTOR),
 * what the bootloader handed over and whether interrupts were left enabled,
 * then idles. Legacy USART (F1/F2/F4) at UART.
 */
#include <stdint.h>
#include "mimiboot/mb_handoff.h"

#ifndef UART
#define UART 0x40011000u
#endif
#ifndef NAME
#define NAME "app"
#endif
#define R(a) (*(volatile uint32_t*)(uintptr_t)(a))

__attribute__((section(".noinit.mb_handoff"), used, aligned(8))) volatile mb_handoff_t mb_handoff;
extern uint32_t _estack;
void reset(void);
static void spin(void) { for (;;) {} }
__attribute__((section(".isr_vector"), used)) const void* const vt[16] = {
    &_estack, (const void*)reset, (const void*)spin, (const void*)spin, (const void*)spin, (const void*)spin,
    (const void*)spin, 0, 0, 0, 0, (const void*)spin, (const void*)spin, 0, (const void*)spin, (const void*)spin,
};

static void putc_(char c) {
    while (!(R(UART) & (1u << 7))) {}
    R(UART + 4) = (uint8_t)c;
}
static void puts_(const char* s) { while (*s) putc_(*s++); }
static void putv(const volatile char* s, int n) { for (int i = 0; i < n && s[i]; i++) putc_(s[i]); }
static void hex(uint32_t v) { for (int i = 28; i >= 0; i -= 4) putc_("0123456789abcdef"[(v >> i) & 15]); }

void reset(void) {
    R(UART + 0x0C) = (1u << 13) | (1u << 3) | (1u << 2);       // UE TE RE
    uint32_t pm;
    __asm volatile("mrs %0, primask" : "=r"(pm));
    puts_("\r\nMU-APP " NAME " vtor=");
    hex(R(0xE000ED08));
    puts_(" primask=");
    hex(pm);
    if (mb_handoff.magic == MB_HANDOFF_MAGIC) {
        puts_(" slot=");
        putv(mb_handoff.slot_name, 8);
        puts_(" kind=");
        hex(mb_handoff.kind);
        puts_(" args=[");
        putv(mb_handoff.args, 96);
        puts_("]");
    } else {
        puts_(" no-handoff");
    }
    puts_("\r\nMU-APP-DONE\r\n");
    for (;;) {}
}
