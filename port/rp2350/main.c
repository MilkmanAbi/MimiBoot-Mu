/*
 * MimiBoot on RP2350
 *
 * The bootrom starts this image from the beginning of flash. The normal
 * path touches only flash, the SHA block and (for trial boots) the
 * watchdog, then chains into the chosen slot: no USB, no console, a few
 * milliseconds plus the hash.
 *
 * Menu: press BOOT while the backlight/LED is lit just after power-up
 * (holding BOOT *through* reset is the chip's own USB loader instead),
 * or ask from the running image (e.g. an OS command that calls mb_client_reboot_menu()).
 */
#include "core/mimiboot.h"
#include "port/rp2350/mb_rp2350.h"

#include "hardware/watchdog.h"
#if defined(MB_BOOT_DIAGNOSTICS) && defined(__riscv)
#include "pico/runtime_init.h"
#include "pico/bootrom.h"
#include "boot/picoboot_constants.h"   /* REBOOT2_FLAG_REBOOT_TYPE_BOOTSEL */
static void pre_sdk_guard(void) {
    volatile uint32_t *tick = (volatile uint32_t *)0x40108030u;
    tick[0] = 0; tick[1] = 12; tick[0] = 1;
    *(volatile uint32_t *)0x401000c8u = 0x4d425256u;
    *(volatile uint32_t *)0x401000ccu = 101;
    /* Return after scheduling BOOTSEL, so a failure before main recovers too. */
    rom_reboot(REBOOT2_FLAG_REBOOT_TYPE_BOOTSEL, 4000, 0, 0);
}
static void pre_sdk_rom_done(void) { *(volatile uint32_t *)0x401000ccu = 110; }
static void pre_sdk_resets_done(void) { *(volatile uint32_t *)0x401000ccu = 120; }
static void pre_sdk_clocks_begin(void) { *(volatile uint32_t *)0x401000ccu = 140; }
static void pre_sdk_clocks_done(void) { *(volatile uint32_t *)0x401000ccu = 150; }
static void pre_sdk_locks_done(void) { *(volatile uint32_t *)0x401000ccu = 190; }
PICO_RUNTIME_INIT_FUNC_RUNTIME(pre_sdk_guard, "00001");
PICO_RUNTIME_INIT_FUNC_RUNTIME(pre_sdk_rom_done, "00099");
PICO_RUNTIME_INIT_FUNC_RUNTIME(pre_sdk_resets_done, "00199");
PICO_RUNTIME_INIT_FUNC_RUNTIME(pre_sdk_clocks_begin, "00499");
PICO_RUNTIME_INIT_FUNC_RUNTIME(pre_sdk_clocks_done, "00599");
PICO_RUNTIME_INIT_FUNC_RUNTIME(pre_sdk_locks_done, "01099");
#endif
#ifdef MB_BOOT_DIAGNOSTICS
#ifdef __riscv
static volatile uint32_t*const trace=(volatile uint32_t*)0x2006ff40u;
#else
static volatile uint32_t*const trace=(volatile uint32_t*)0x2006ff00u;
#endif
void mb_boot_progress(unsigned stage){trace[2]=stage;}
#endif
int main(void) {
#ifdef MB_BOOT_DIAGNOSTICS
    trace[0]=0x4d424e54;
#ifdef __riscv
    trace[1]=2;
#else
    trace[1]=1;
#endif
    trace[2]=0;
    watchdog_enable(8000,false);
#endif
    mb_main(&mb_rp2350_port);
}
