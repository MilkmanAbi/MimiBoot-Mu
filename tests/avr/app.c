/*
 * Test sketch for the AVR Lite bootloader (no Arduino core: plain avr-libc).
 * Prints what the bootloader handed over, then takes one-letter commands:
 *   b  reboot into the bootloader         c  confirm (end the trial)
 *   r  plain reboot (watchdog)            s  receive an image and stage it:
 *      's' u16 length, u32 crc32, bytes...  -> written above MU_STAGE_BASE, committed
 */
#include "mu_avr.h"
#include <util/delay.h>

#ifndef NAME
#define NAME "app"
#endif

static void tx(char c) { while (!(UCSR0A & _BV(UDRE0))) {} UDR0 = c; }
static void txs(const char* s) { while (*s) tx(*s++); }
static void hex8(uint8_t v) { tx("0123456789abcdef"[v >> 4]); tx("0123456789abcdef"[v & 15]); }
static uint8_t rx(void) { while (!(UCSR0A & _BV(RXC0))) {} return UDR0; }
static void drain(void) { while (!(UCSR0A & _BV(TXC0))) {} }

static mu_handoff_t h;

static void banner(void) {
    txs("\r\nMU-AVR-APP " NAME " by=");
    hex8(h.by_mimiboot);
    txs(" mcusr=");
    hex8(h.mcusr);
    txs(" flags=");
    hex8(h.flags);
    txs(" trial=");
    hex8(mu_in_trial());
    txs("\r\n");
}

int main(void) {
    h = mu_handoff();
    UCSR0A = _BV(U2X0) | _BV(TXC0);
    UBRR0 = (uint16_t)((F_CPU + 4UL * 115200) / (8UL * 115200) - 1);
    UCSR0C = _BV(UCSZ01) | _BV(UCSZ00);
    UCSR0B = _BV(RXEN0) | _BV(TXEN0);
    banner();
    for (;;) {
        char c = (char)rx();
        if (c == 'b') { txs("REQ\r\n"); drain(); mu_enter_bootloader(); }
        if (c == 'r') { txs("RESET\r\n"); drain(); mu_reboot(); }
        if (c == 'c') { mu_confirm(); txs("CONFIRMED\r\n"); }
        if (c == '?') banner();
#if defined(STAGE_TEST)
        if (c == 's') {
            if (!mu_api_present()) { txs("NO-API\r\n"); continue; }
            uint16_t len = rx();
            len |= (uint16_t)rx() << 8;
            uint32_t crc = 0;
            for (uint8_t i = 0; i < 4; i++) crc |= (uint32_t)rx() << (8 * i);
            static uint8_t page[SPM_PAGESIZE];
            uint32_t at = MU_STAGE_BASE;
            for (uint16_t done = 0; done < len;) {
                uint16_t i = 0;
                for (; i < SPM_PAGESIZE && done < len; i++, done++) page[i] = rx();
                for (; i < SPM_PAGESIZE; i++) page[i] = 0xFF;
                mu_spm(MU_SPM_WRITE, at, page);
                at += SPM_PAGESIZE;
                tx('.');                                    /* flow control: one page at a time */
            }
            uint32_t got = mu_crc32_flash(MU_STAGE_BASE, len);
            txs(got == crc ? "STAGED\r\n" : "STAGE-CRC-BAD\r\n");
            drain();
            if (got == crc) mu_stage_commit(len, crc);
        }
#endif
    }
}
