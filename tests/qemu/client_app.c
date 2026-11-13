/*
 * Emulator test payload using the MimiBoot client library (the app side):
 * which slot am I in, did I get a valid handoff, what are my args.
 */
#include <stdint.h>
#include "client/mb_client.h"

#define R(a) (*(volatile uint32_t*)(uintptr_t)(a))
extern const mb_port_t mb_mcu_port;
__attribute__((section(".noinit.mb_handoff"), used, aligned(8))) volatile mb_handoff_t mb_handoff;
extern uint32_t _estack;
void reset(void);
static void spin(void) { for (;;) {} }
__attribute__((section(".isr_vector"), used)) const void* const vt[16] = {
    &_estack, (const void*)reset, (const void*)spin, (const void*)spin, (const void*)spin, (const void*)spin,
    (const void*)spin, 0, 0, 0, 0, (const void*)spin, (const void*)spin, 0, (const void*)spin, (const void*)spin,
};
extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss;

static void putc_(char c) { while (!(R(UART) & (1u << 7))) {} R(UART + 4) = (uint8_t)c; }
static void puts_(const char* s) { while (*s) putc_(*s++); }
static void dec(int v) {
    char b[12];
    int i = 0;
    if (v < 0) { putc_('-'); v = -v; }
    do { b[i++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (i) putc_(b[--i]);
}

void reset(void) {
    uint32_t *s = &_sidata, *d = &_sdata;
    while (d < &_edata) *d++ = *s++;
    for (d = &_sbss; d < &_ebss;) *d++ = 0;
    R(UART + 0x0C) = (1u << 13) | (1u << 3) | (1u << 2);
    mb_client_init(&mb_mcu_port);
    mb_client_set_handoff(&mb_handoff);
    mb_client_status_t st;
    int rc = mb_client_status(&st);
    puts_("\r\nMU-CLIENT slot=");
    dec(st.slot);
    puts_(" status_rc=");
    dec(rc);
    puts_(" handoff=");
    dec(mb_client_handoff() != 0);
    puts_(" name=");
    puts_(st.name);
    puts_(" args=[");
    puts_(mb_client_args());
    puts_("]\r\nMU-CLIENT-DONE\r\n");
    for (;;) {}
}
