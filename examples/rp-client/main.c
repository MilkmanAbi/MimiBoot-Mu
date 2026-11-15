/* OS-side boot control demonstration. No action until a console command. */
#include "client/mb_client.h"
#include "pico/stdlib.h"
#if PICO_RP2040
#include "port/rp2040/mb_rp2040.h"
#define BOOT_PORT mb_rp2040_port
#else
#include "port/rp2350/mb_rp2350.h"
#define BOOT_PORT mb_rp2350_port
#endif
#include <stdio.h>
MB_HANDOFF_BUFFER;
int main(void) {
    mb_client_init(&BOOT_PORT);
    mb_client_set_handoff(&mb_handoff); /* before startup clears/reuses this buffer */
    stdio_init_all();
    /* A real OS confirms only after its own acceptance checks pass. */
    for (;;) {
        int c = getchar_timeout_us(100000);
        int rc = MB_OK;
        if (c == '?')
            printf("caps=%08lx: m menu, c config, a Arm/Arm os entry, x Arm/Hazard3 os entry, v Hazard3/Arm os entry, "
                   "y Hazard3/Hazard3, g confirm\n",
                   (unsigned long)mb_client_capabilities());
        else if (c == 'm')
            rc = mb_client_reboot_menu();
        else if (c == 'c')
            rc = mb_client_reboot_config();
        else if (c == 'a' || c == 'x' || c == 'v' || c == 'y') {
            mb_topology_t pair = {(c == 'v' || c == 'y') ? MB_ARCH_RISCV : MB_ARCH_ARM,
                                  (c == 'x' || c == 'y') ? MB_ARCH_RISCV : MB_ARCH_ARM, 0};
            /* Change os to the stable ID of an installed primary-ISA-compatible image.
             * Mixed images must contain their own matching secondary-core startup. */
            rc = mb_client_reboot_profile("os", pair, "init=/sbin/init");
        } else if (c == 'g')
            rc = mb_client_confirm();
        if (rc != MB_OK)
            printf("boot service refused: %d\n", rc);
    }
}
