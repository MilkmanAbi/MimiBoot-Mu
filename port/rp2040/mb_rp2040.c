/* RP2040 port of the supplied MimiBoot core. The RAM-probe build starts with
 * every flash write refused. Backup/JEDEC commands do not change flash. */
#include "core/mimiboot.h"
#include "pico/bootrom.h"
#include "pico/stdio_usb.h"
#include "pico/stdlib.h"
#ifdef MB_RP2040_CLIENT
#include "pico/flash.h"
#endif
#include "hardware/flash.h"
#include "hardware/irq.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/scb.h"
#include "hardware/structs/sio.h"
#include "hardware/structs/ssi.h"
#include "hardware/structs/systick.h"
#include "hardware/structs/timer.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef MB_RAM_PROBE
#define LOADER_RAM 0x20010000u
#else
#define LOADER_RAM 0x20020000u
#endif
#ifndef MB_RP2040_LAYOUT
#if PICO_FLASH_SIZE_BYTES >= (16u << 20)
#define MB_RP2040_LAYOUT MB_LAYOUT_16M_INIT
#elif PICO_FLASH_SIZE_BYTES >= (4u << 20)
#define MB_RP2040_LAYOUT MB_LAYOUT_4M_INIT
#else
#define MB_RP2040_LAYOUT MB_LAYOUT_2M_INIT
#endif
#endif
static const mb_layout_t layout = MB_RP2040_LAYOUT;
#ifdef MB_RAM_PROBE
static bool writes_enabled = false;
#else
static bool writes_enabled = true;
#endif
#ifdef MB_KEYS_HEADER
#include MB_KEYS_HEADER
static const uint8_t trusted[MB_TRUSTED_KEY_COUNT][32] = MB_TRUSTED_KEYS;
static const mb_keyring_t keyring = {MB_TRUSTED_KEY_COUNT, trusted};
#define KEYRING (&keyring)
#else
#define KEYRING NULL
#endif
#ifndef MB_REQUIRE_SIGNATURE
#define MB_REQUIRE_SIGNATURE 0
#endif
static uint8_t jedec[3];
static void __no_inline_not_in_flash_func(flash_xip)(void) {
    ((rom_connect_internal_flash_fn)rom_func_lookup_inline(ROM_FUNC_CONNECT_INTERNAL_FLASH))();
    ((rom_flash_exit_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_EXIT_XIP))();
    ((rom_flash_enter_cmd_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_ENTER_CMD_XIP))();
}
static void __no_inline_not_in_flash_func(read_jedec)(void) {
    uint8_t tx[4] = {0x9f, 0, 0, 0}, rx[4];
    uint32_t key = save_and_disable_interrupts();
    ((rom_connect_internal_flash_fn)rom_func_lookup_inline(ROM_FUNC_CONNECT_INTERNAL_FLASH))();
    ((rom_flash_exit_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_EXIT_XIP))();
    hw_write_masked(&ioqspi_hw->io[1].ctrl, 2u << 8, 3u << 8);
    unsigned sent = 0, got = 0;
    while (got < 4) {
        if (sent < 4 && (ssi_hw->sr & 2)) {
            ssi_hw->dr0 = tx[sent++];
        }
        if (ssi_hw->sr & 8)
            rx[got++] = (uint8_t)ssi_hw->dr0;
    }
    hw_write_masked(&ioqspi_hw->io[1].ctrl, 3u << 8, 3u << 8);
    ((rom_flash_flush_cache_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_FLUSH_CACHE))();
    ((rom_flash_enter_cmd_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_ENTER_CMD_XIP))();
    restore_interrupts(key);
    memcpy(jedec, rx + 1, 3);
}
static int rd(uint32_t off, void *buf, size_t n) {
    if (off > layout.flash_size || n > layout.flash_size - off)
        return MB_E_BADARG;
    memcpy(buf, (const void *)(0x10000000u + off), n);
    return 0;
}
static int __no_inline_not_in_flash_func(raw_er)(uint32_t off, size_t n) {
    if (!writes_enabled || off < layout.boot.size)
        return MB_E_REFUSED;
    if ((off & 4095) || (n & 4095) || off > layout.flash_size || n > layout.flash_size - off)
        return MB_E_BADARG;
    uint32_t key = save_and_disable_interrupts();
    ((rom_connect_internal_flash_fn)rom_func_lookup_inline(ROM_FUNC_CONNECT_INTERNAL_FLASH))();
    ((rom_flash_exit_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_EXIT_XIP))();
    ((rom_flash_range_erase_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_RANGE_ERASE))(off, n, 4096, 0x20);
    ((rom_flash_flush_cache_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_FLUSH_CACHE))();
    ((rom_flash_enter_cmd_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_ENTER_CMD_XIP))();
    restore_interrupts(key);
    return 0;
}
static int __no_inline_not_in_flash_func(raw_pg)(uint32_t off, const void *buf, size_t n) {
    if (!writes_enabled || off < layout.boot.size)
        return MB_E_REFUSED;
    if ((off & 255) || (n & 255) || off > layout.flash_size || n > layout.flash_size - off)
        return MB_E_BADARG;
    uint32_t key = save_and_disable_interrupts();
    ((rom_connect_internal_flash_fn)rom_func_lookup_inline(ROM_FUNC_CONNECT_INTERNAL_FLASH))();
    ((rom_flash_exit_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_EXIT_XIP))();
    ((rom_flash_range_program_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_RANGE_PROGRAM))(off, buf, n);
    ((rom_flash_flush_cache_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_FLUSH_CACHE))();
    ((rom_flash_enter_cmd_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_ENTER_CMD_XIP))();
    restore_interrupts(key);
    return 0;
}
/* SDK client writes require an explicit other-core rendezvous. Loader-only
 * writes run before core1 is launched. Never silently assume an OS core is idle. */
#ifdef MB_RP2040_CLIENT
typedef struct {
    uint32_t off;
    size_t n;
    const void *buf;
    bool erase;
    int result;
} flash_op_t;
static void __no_inline_not_in_flash_func(do_flash_op)(void *v) {
    flash_op_t *o = v;
    o->result = o->erase ? raw_er(o->off, o->n) : raw_pg(o->off, o->buf, o->n);
}
static int er(uint32_t off, size_t n) {
    flash_op_t o = {off, n, NULL, true, MB_E_IO};
    int rc = flash_safe_execute(do_flash_op, &o, 1000);
    return rc == PICO_OK ? o.result : MB_E_IO;
}
static int pg(uint32_t off, const void *b, size_t n) {
    flash_op_t o = {off, n, b, false, MB_E_IO};
    int rc = flash_safe_execute(do_flash_op, &o, 1000);
    return rc == PICO_OK ? o.result : MB_E_IO;
}
#else
#define er raw_er
#define pg raw_pg
#endif
static void *ram(uint32_t a, uint32_t n) {
    return a >= 0x20000000u && a < LOADER_RAM && n <= LOADER_RAM - a ? (void *)a : NULL;
}
static bool can_start(const mb_image_hdr_t *h) {
    return h->load_type == MB_LOAD_RAM && (h->arch == MB_ARCH_ARM || h->arch == MB_ARCH_ANY) &&
           ram(h->load_addr, h->payload_size);
}
static void __attribute__((naked, noreturn)) jump_image(uint32_t sp, uint32_t pc) {
    __asm volatile("msr msp,r0\n bx r1");
}
static int launch_ram(const mb_image_hdr_t *h) {
    if (!can_start(h))
        return MB_E_REFUSED;
    uint32_t vectors = h->entry ? h->entry : h->load_addr;
    if ((vectors & 255) || h->payload_size < 8 || vectors < h->load_addr ||
        vectors > h->load_addr + h->payload_size - 8)
        return MB_E_CORRUPT;
    uint32_t *v = (uint32_t *)vectors;
    uint32_t sp = v[0], pc = v[1];
    if (sp < 0x20000000 || sp > 0x20042000 || (sp & 7) || !(pc & 1) || (pc & ~1u) < h->load_addr ||
        (pc & ~1u) >= h->load_addr + h->payload_size)
        return MB_E_CORRUPT;
    stdio_flush();
    sleep_ms(20);
    stdio_usb_deinit();
    save_and_disable_interrupts();
    systick_hw->csr = 0;
    timer_hw->inte = 0;
    *(volatile uint32_t *)0xe000e180 = ~0u;
    *(volatile uint32_t *)0xe000e280 = ~0u;
    scb_hw->vtor = vectors;
    __dsb();
    __isb();
    jump_image(sp, pc);
}
static bool console_open(uint32_t timeout) {
    uint32_t end = to_ms_since_boot(get_absolute_time()) + timeout;
    while (!stdio_usb_connected() && (int32_t)(to_ms_since_boot(get_absolute_time()) - end) < 0)
        sleep_ms(1);
    return stdio_usb_connected();
}
static int getc_port(uint32_t ms) { return getchar_timeout_us(ms * 1000u); }
static void write_port(const char *s, size_t n) { stdio_put_string(s, (int)n, false, false); }
static uint32_t tm(void) { return to_ms_since_boot(get_absolute_time()); }
static void wd(uint32_t ms) { watchdog_enable(ms > 8000 ? 8000 : ms, true); }
static void wd_off(void) { watchdog_disable(); }
static void reboot(void) {
    watchdog_reboot(0, 0, 10);
    for (;;)
        ;
}
static void rom(void) { reset_usb_boot(0, 0); }

#ifndef MB_RAM_PROBE
static bool __no_inline_not_in_flash_func(key_now)(void) {
    uint32_t key = save_and_disable_interrupts();
    uint32_t old = ioqspi_hw->io[1].ctrl;
    hw_write_masked(&ioqspi_hw->io[1].ctrl, 3u << 8, 3u << 8);
    for (volatile unsigned i = 0; i < 1000; i++) {
    }
    bool pressed = !(sio_hw->gpio_hi_in & 2);
    ioqspi_hw->io[1].ctrl = old;
    restore_interrupts(key);
    return pressed;
}
#endif
static bool button(void) {
#ifdef MB_RAM_PROBE
    return true;
#else
    uint32_t end = tm() + 600;
    bool hit = false;
#ifdef PICO_DEFAULT_LED_PIN
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    gpio_put(PICO_DEFAULT_LED_PIN, 1);
#endif
    while (!hit && (int32_t)(tm() - end) < 0) {
        hit = key_now();
        sleep_ms(5);
    }
#ifdef PICO_DEFAULT_LED_PIN
    gpio_put(PICO_DEFAULT_LED_PIN, 0);
    gpio_deinit(PICO_DEFAULT_LED_PIN);
#endif
    return hit;
#endif
}
static uint32_t caps(void) { return MB_CAP_CONTROL | MB_CAP_CONFIG | MB_CAP_RAM | MB_CAP_ARM; }
static int prepare(mb_topology_t t) { return t.core0 == MB_ARCH_ARM && t.core1 == MB_ARCH_ARM ? MB_OK : MB_E_UNSUPP; }

static uint32_t cause(void) {
    return watchdog_enable_caused_reboot() ? MB_RESET_WATCHDOG
           : watchdog_caused_reboot()      ? MB_RESET_SOFT
                                           : MB_RESET_POWER;
}
static const char *reason(void) { return "RP2040"; }
const mb_port_t mb_rp2040_port = {.capabilities = caps,
                                  .prepare_topology = prepare,
                                  .name = "rp2040",
                                  .target = "rp2040",
                                  .layout = &layout,
                                  .arch = MB_ARCH_ARM,
                                  .keys = KEYRING,
                                  .require_signature = MB_REQUIRE_SIGNATURE,
                                  .flash_read = rd,
                                  .flash_erase = er,
                                  .flash_program = pg,
                                  .can_start = can_start,
                                  .ram_ptr = ram,
                                  .launch_ram = launch_ram,
                                  .time_ms = tm,
                                  .watchdog_arm = wd,
                                  .watchdog_disarm = wd_off,
                                  .button = button,
                                  .console_open = console_open,
                                  .getc = getc_port,
                                  .write = write_port,
                                  .reboot = reboot,
                                  .reboot_rom = rom,
                                  .reset_cause = cause,
                                  .reset_reason = reason};
#ifndef MB_RP2040_CLIENT
int main(void) {
    stdio_init_all();
    flash_xip();
    read_jedec();
#ifdef MB_RAM_PROBE
    while (!stdio_usb_connected())
        sleep_ms(1);
    puts("MimiBoot RP2040 RAM probe; flash writes locked");
    char line[80];
    for (;;) {
        printf("probe> ");
        fflush(stdout);
        unsigned n = 0;
        int c;
        while ((c = getchar_timeout_us(1000000)) != '\r' && c != '\n') {
            if (c < 0)
                continue;
            if (n < sizeof line - 1)
                line[n++] = (char)c;
        }
        line[n] = 0;
        if (!strcmp(line, "jedec"))
            printf("JEDEC %02x %02x %02x; bytes=%lu\n", jedec[0], jedec[1], jedec[2],
                   jedec[2] >= 16 && jedec[2] <= 24 ? 1ul << jedec[2] : 0ul);
        else if (!strncmp(line, "backup ", 7)) {
            uint32_t count = strtoul(line + 7, 0, 0);
            uint32_t actual = jedec[2] >= 16 && jedec[2] <= 24 ? 1u << jedec[2] : 0;
            if (!actual || count != actual) {
                puts("ERR size");
                continue;
            }
            printf("BACKUP %lu\n", (unsigned long)count);
            fflush(stdout);
            const uint8_t *flash = (const uint8_t *)0x10000000;
            uint32_t crc = 0;
            for (uint32_t off = 0; off < count; off += 256) {
                size_t len = count - off < 256 ? count - off : 256;
                crc = mb_crc32(crc, flash + off, len);
                write_port((const char *)flash + off, len);
            }
            write_port((const char *)&crc, 4);
            puts("\nBACKUP DONE");
        } else if (!strcmp(line, "mimiboot")) {
            puts("Entering MimiBoot, flash writes remain locked");
            break;
        } else if (!strcmp(line, "enable-writes AFTER-BACKUP")) {
            if (jedec[2] < 16 || jedec[2] > 24 || (1u << jedec[2]) < layout.flash_size) {
                puts("ERR flash is smaller than the compiled board layout");
                continue;
            }
            writes_enabled = true;
            puts("flash writes enabled outside boot region");
            break;
        } else if (!strcmp(line, "bootsel"))
            rom();
        else
            puts("jedec | backup <exact bytes> | mimiboot | enable-writes AFTER-BACKUP | bootsel");
    }
#endif
    mb_main(&mb_rp2040_port);
}

#endif
