/*
 * MimiBoot example app
 *
 * Prints how it was booted (slot, entry, args from the handoff, which CPU)
 * and confirms itself after 5 s of running (the "health check"). Built as
 * hello_noconfirm it never confirms, to watch MimiBoot roll it back; built
 * as hello_ram it is a RAM image (mbtool ramboot, or a slot entry), and with
 * PICO_PLATFORM=rp2350-riscv it runs on the Hazard3 cores.
 *
 * Keys on the USB console:
 *   s  status         m  reboot into the MimiBoot menu
 *   o  boot the other slot once        r  reboot     u  ROM USB loader
 */
#include <stdio.h>
#include "pico/stdlib.h"
#include "client/mb_client.h"
#include "port/rp2350/mb_rp2350.h"
#include "mimiboot/mb_handoff.h"
#include "hardware/watchdog.h"

MB_HANDOFF_BUFFER;              // MimiBoot writes the boot info here; mbtool finds it in the ELF

static const char* state_name(int s) {
    static const char* n[] = { "empty", "NEW", "TRIAL", "GOOD", "BAD" };
    return s >= 0 && s <= 4 ? n[s] : "?";
}

static void status(void) {
    mb_client_status_t st;
    if (mb_client_status(&st) != MB_OK) { printf("status: can't read the boot log\n"); return; }
#if defined(__riscv)
    printf("running on Hazard3 (RISC-V)\n");
#else
    printf("running on Cortex-M33 (Arm)\n");
#endif
    const mb_handoff_t* h = mb_client_handoff();
    if (h) printf("handoff: slot %s, entry '%s', kind %u, MimiBoot %lu.%lu, args \"%s\"\n", h->slot_name, h->entry_name, h->kind,
                  (unsigned long)MB_VERSION_MAJOR(h->loader_version), (unsigned long)MB_VERSION_MINOR(h->loader_version), h->args);
    else printf("no handoff this boot; args from flash: \"%s\"\n", mb_client_args());
    if (st.slot == MB_SLOT_NONE) { printf("not running from a slot (RAM image, or flashed directly)\n"); return; }
    printf("slot %s: \"%s\" v%lu.%lu.%lu, security %lu (floor %lu), %s, %d tries left, active %s, strikes %d\n",
           mb_slot_name(&mb_rp2350_port, st.slot), st.name, (unsigned long)MB_VERSION_MAJOR(st.version),
           (unsigned long)MB_VERSION_MINOR(st.version), (unsigned long)MB_VERSION_PATCH(st.version), (unsigned long)st.security_version,
           (unsigned long)st.min_security, state_name(st.state), st.tries_left, mb_slot_name(&mb_rp2350_port, st.active), st.strikes);
}

int main(void) {
    stdio_init_all();
    mb_client_init(&mb_rp2350_port);
    mb_client_set_handoff(&mb_handoff);          // first thing: take it before anything reuses that RAM
    for (int i = 0; i < 30 && !stdio_usb_connected(); i++) sleep_ms(100);
    printf("\nhello from the MimiBoot example%s\n", watchdog_caused_reboot() ? " (after a watchdog reset)" : "");
    status();
    bool confirmed = false;
    absolute_time_t health = make_timeout_time_ms(5000);
    for (;;) {
        watchdog_update();                       // a trial boot runs under the watchdog until it confirms
#ifndef HELLO_NEVER_CONFIRM
        if (!confirmed && time_reached(health)) {
            int rc = mb_client_confirm();
            printf("healthy for 5 s: confirm -> %d\n", rc);
            confirmed = true;
            status();
        }
#endif
        int c = getchar_timeout_us(100000);
        if (c == 's') status();
        else if (c == 'm') { mb_client_request(MB_REQ_MENU, 0); printf("menu on next boot\n"); sleep_ms(50); watchdog_reboot(0, 0, 10); }
        else if (c == 'o') { mb_client_request(MB_REQ_BOOT_ONCE, mb_client_other_slot()); printf("other slot once\n"); sleep_ms(50); watchdog_reboot(0, 0, 10); }
        else if (c == 'r') watchdog_reboot(0, 0, 10);
        else if (c == 'u') { mb_client_request(MB_REQ_BOOTSEL, 0); watchdog_reboot(0, 0, 10); }
    }
}
