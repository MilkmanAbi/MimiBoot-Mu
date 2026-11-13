/*
 * MimiBoot - RP2350 port (Arm Cortex-M33 or Hazard3 RISC-V)
 *
 *   flash   reads through the untranslated, uncached XIP alias (0x1C000000):
 *           physical offsets, never stale after an erase/program
 *   hash    the SHA-256 block, fed by DMA (flash alias or SRAM)
 *   launch  XIP images: the bootrom's chain_image maps the slot at the flash
 *           base, so every slot runs the same binary linked at 0x10000000.
 *           RAM images: copied below MimiBoot's own RAM (the top 64 KB, see
 *           mimiboot_memmap.ld) and chained there; one for the *other*
 *           architecture goes through rom_reboot(RAM_IMAGE | TO_RISCV/ARM),
 *           which switches the cores and starts it from SRAM.
 *   key     BOOT (QSPI chip select), read from RAM with flash idle
 *   console USB CDC, brought up only when the console is actually needed
 *
 * The same file serves apps (MB_RP2350_CLIENT): flash writes then go through
 * flash_safe_execute (the other core and IRQs are parked), and self_slot
 * asks the bootrom where the running image really lives.
 */
#include "port/rp2350/mb_rp2350.h"
#ifdef MB_BOOT_DIAGNOSTICS
#include "core/mimiboot.h"
#endif
#include "boot/picoboot_constants.h"
#include "hardware/flash.h"
#include "hardware/irq.h"
#include "hardware/regs/otp.h"
#include "hardware/regs/psm.h"
#include "hardware/resets.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/otp.h"
#include "hardware/structs/psm.h"
#include "hardware/structs/qmi.h"
#include "hardware/structs/sio.h"
#include "hardware/structs/timer.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "pico/bootrom.h"
#include "pico/sha256.h"
#include "pico/stdlib.h"
#include <string.h>
#if !defined(__riscv)
#include "hardware/structs/systick.h"
#endif
#ifdef MB_RP2350_CLIENT
#include "pico/flash.h"
#else
#include "pico/stdio_usb.h"
#endif

static uint32_t night_caps(void) {
    uint32_t c = MB_CAP_CONTROL | MB_CAP_CONFIG | MB_CAP_RAM | MB_CAP_XIP;
    uint32_t flags = otp_hw->critical;
    if (!(flags & OTP_CRITICAL_ARM_DISABLE_BITS))
        c |= MB_CAP_ARM;
    if (!(flags & (OTP_CRITICAL_RISCV_DISABLE_BITS | OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS)))
        c |= MB_CAP_RISCV;
    if ((c & (MB_CAP_ARM | MB_CAP_RISCV)) == (MB_CAP_ARM | MB_CAP_RISCV))
        c |= MB_CAP_MIXED;
#ifdef MB_RP2350_UNIVERSAL
    c |= MB_CAP_ARCH_SWITCH;
#endif
    return c;
}
#ifndef MB_RP2350_CLIENT
static int night_prepare(mb_topology_t t) {
    uint32_t caps = night_caps();
#ifdef __riscv
    const unsigned primary = MB_ARCH_RISCV;
#else
    const unsigned primary = MB_ARCH_ARM;
#endif
    if (t.core0 != primary || t.core1 < 1 || t.core1 > 2)
        return MB_E_UNSUPP;
    if (t.core1 == MB_ARCH_RISCV && !(caps & MB_CAP_RISCV))
        return MB_E_UNSUPP;
    if (t.core1 == MB_ARCH_ARM && !(caps & MB_CAP_ARM))
        return MB_E_UNSUPP;
    uint32_t key = save_and_disable_interrupts();
    hw_set_bits(&psm_hw->frce_off, PSM_FRCE_OFF_PROC1_BITS);
    uint32_t budget = 1000000;
    while (!(psm_hw->frce_off & PSM_FRCE_OFF_PROC1_BITS) && --budget) {
    }
    if (!budget) {
        restore_interrupts(key);
        return MB_E_TIMEOUT;
    }
    uint32_t old = otp_hw->archsel;
    uint32_t desired = (old & ~OTP_ARCHSEL_CORE1_BITS) | (t.core1 == MB_ARCH_RISCV ? OTP_ARCHSEL_CORE1_BITS : 0);
    otp_hw->archsel = desired;
    __dmb();
    hw_clear_bits(&psm_hw->frce_off, PSM_FRCE_OFF_PROC1_BITS);
    budget = 1000000;
    while (((otp_hw->archsel_status >> 1) & 1) != (t.core1 == MB_ARCH_RISCV) && --budget) {
    }
    restore_interrupts(key);
    return budget ? MB_OK : MB_E_TIMEOUT;
}
#endif
#ifndef MB_RP2350_LAYOUT
#if PICO_FLASH_SIZE_BYTES >= (16u << 20)
#define MB_RP2350_LAYOUT MB_LAYOUT_16M_INIT
#elif PICO_FLASH_SIZE_BYTES >= (4u << 20)
#define MB_RP2350_LAYOUT MB_LAYOUT_4M_INIT
#else
#define MB_RP2350_LAYOUT MB_LAYOUT_2M_INIT
#endif
#endif

#if defined(__riscv)
#define MY_ARCH MB_ARCH_RISCV
#else
#define MY_ARCH MB_ARCH_ARM
#endif

// SRAM a RAM image (or a handoff) may use: everything below MimiBoot's own
// RAM. The linker script puts MimiBoot at MB_RP2350_LOADER_RAM and up.
#define SRAM_BASE_ADDR 0x20000000u
#ifndef MB_RP2350_LOADER_RAM
#define MB_RP2350_LOADER_RAM 0x20070000u
#endif

static const mb_layout_t layout = MB_RP2350_LAYOUT;

// Trusted keys: from mbtool keygen's header, at build time only
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

#define FLASH_PHYS(off) ((const void *)(XIP_NOCACHE_NOALLOC_NOTRANSLATE_BASE + (off)))

static bool in_flash(uint32_t off, size_t len) { return off <= layout.flash_size && len <= layout.flash_size - off; }

// The bootloader itself is off limits to everyone
static bool writable(uint32_t off, size_t len) {
    return in_flash(off, len) && off >= layout.boot.offset + layout.boot.size;
}

static int f_read(uint32_t off, void *buf, size_t len) {
    if (!in_flash(off, len))
        return MB_E_BADARG;
    memcpy(buf, FLASH_PHYS(off), len);
    return MB_OK;
}

typedef struct {
    uint32_t off;
    const void *data;
    size_t len;
    bool erase;
} flash_op_t;

// Erase / program with bootrom calls only, not the SDK's flash_range_*.
// Found on hardware: from an image started by chain_image, the SDK's
// re-entry into XIP (it runs a "boot2" copied out of boot RAM) hangs the
// chip. This does what that step is for by hand: back to generic XIP, then
// the fast-read QMI setup and the address translation that were in force.
// Runs from RAM with interrupts off (the caller sees to that).
static void __no_inline_not_in_flash_func(do_flash_op)(void *arg) {
    flash_op_t *op = arg;
    rom_connect_internal_flash_fn connect =
        (rom_connect_internal_flash_fn)rom_func_lookup_inline(ROM_FUNC_CONNECT_INTERNAL_FLASH);
    rom_flash_exit_xip_fn exit_xip = (rom_flash_exit_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_EXIT_XIP);
    rom_flash_range_erase_fn rom_erase = (rom_flash_range_erase_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_RANGE_ERASE);
    rom_flash_range_program_fn rom_program =
        (rom_flash_range_program_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_RANGE_PROGRAM);
    rom_flash_flush_cache_fn flush = (rom_flash_flush_cache_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_FLUSH_CACHE);
    rom_flash_enter_cmd_xip_fn enter_xip =
        (rom_flash_enter_cmd_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_ENTER_CMD_XIP);
    uint32_t timing = qmi_hw->m[0].timing, rcmd = qmi_hw->m[0].rcmd, rfmt = qmi_hw->m[0].rfmt;
    uint32_t atrans[8];
    for (int i = 0; i < 8; i++)
        atrans[i] = qmi_hw->atrans[i];
    connect();
    exit_xip();
    if (op->erase)
        rom_erase(op->off, op->len, FLASH_BLOCK_SIZE, 0xD8);
    else
        rom_program(op->off, op->data, op->len);
    flush();
    enter_xip();
    qmi_hw->m[0].timing = timing;
    qmi_hw->m[0].rcmd = rcmd;
    qmi_hw->m[0].rfmt = rfmt;
    for (int i = 0; i < 8; i++)
        qmi_hw->atrans[i] = atrans[i];
    flush(); // nothing stale from the slow-read window
}

static int run_flash_op(flash_op_t *op) {
#ifdef MB_RP2350_CLIENT
    int rc = flash_safe_execute(do_flash_op, op, 1000); // apps: park the other core and IRQs
    return rc == PICO_OK ? MB_OK : MB_E_IO;
#else
    uint32_t s = save_and_disable_interrupts();
    do_flash_op(op);
    restore_interrupts(s);
    return MB_OK;
#endif
}

static int f_erase(uint32_t off, size_t len) {
    if (!writable(off, len) || off % FLASH_SECTOR_SIZE || len % FLASH_SECTOR_SIZE)
        return MB_E_BADARG;
    // a sector at a time: interrupts are off during each, and a multi-MB
    // erase in one go would starve USB long enough for the host to give up
    for (size_t done = 0; done < len; done += FLASH_SECTOR_SIZE) {
        flash_op_t op = {off + (uint32_t)done, NULL, FLASH_SECTOR_SIZE, true};
        int rc = run_flash_op(&op);
        if (rc != MB_OK)
            return rc;
    }
    return MB_OK;
}

static int f_program(uint32_t off, const void *buf, size_t len) {
    if (!writable(off, len) || off % FLASH_PAGE_SIZE || len % FLASH_PAGE_SIZE)
        return MB_E_BADARG;
    // flash_range_program can't read its source from flash while XIP is off
    static uint8_t page[FLASH_PAGE_SIZE];
    const uint8_t *src = buf;
    for (size_t done = 0; done < len; done += FLASH_PAGE_SIZE) {
        memcpy(page, src + done, FLASH_PAGE_SIZE);
        flash_op_t op = {off + (uint32_t)done, page, FLASH_PAGE_SIZE, false};
        int rc = run_flash_op(&op);
        if (rc != MB_OK)
            return rc;
    }
    return MB_OK;
}

static int sha_hw(const uint8_t *p, uint32_t len, uint8_t out[32]) {
    pico_sha256_state_t st;
    if (pico_sha256_try_start(&st, SHA256_BIG_ENDIAN, true) != PICO_OK)
        return MB_E_UNSUPP; // busy: software fallback
    for (uint32_t done = 0; done < len;) {
        uint32_t n = len - done > 0x8000 ? 0x8000 : len - done;
        pico_sha256_update_blocking(&st, p + done, n);
        done += n;
    }
    sha256_result_t r;
    pico_sha256_finish(&st, &r);
    memcpy(out, r.bytes, 32);
    return MB_OK;
}

static int f_hash(uint32_t off, uint32_t len, uint8_t out[32]) {
    if (!in_flash(off, len))
        return MB_E_BADARG;
    return sha_hw(FLASH_PHYS(off), len, out);
}

static int f_hash_mem(const void *p, uint32_t len, uint8_t out[32]) { return sha_hw(p, len, out); }

static uint32_t f_time(void) { return to_ms_since_boot(get_absolute_time()); }

static uint32_t f_cause(void) {
    if (watchdog_enable_caused_reboot())
        return MB_RESET_WATCHDOG; // a timeout, not a requested reboot
    if (watchdog_caused_reboot())
        return MB_RESET_SOFT;
    return MB_RESET_POWER;
}

#ifndef MB_RP2350_CLIENT

// ---------------------------------------------------------------------------
// Bootloader only
// ---------------------------------------------------------------------------

static bool console_up;
static uint8_t __attribute__((aligned(4))) chain_workarea[4096]; // bootrom wants >= 3264 bytes

static void f_wdt(uint32_t ms) { watchdog_enable(ms > 8000000 ? 8000000 : ms, true); }
static void f_wdt_off(void) { watchdog_disable(); }

// BOOT pulls QSPI_SS low. Reading it means floating the flash chip select,
// so this runs from RAM with interrupts off (nothing may touch flash).
static bool __no_inline_not_in_flash_func(boot_key_now)(void) {
    const uint CS = 1;
    uint32_t flags = save_and_disable_interrupts();
#ifdef __riscv
    __asm volatile("fence iorw,iorw\n fence.i" ::: "memory");
#endif
    hw_write_masked(&ioqspi_hw->io[CS].ctrl, GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
    for (volatile int i = 0; i < 1000; ++i) {
    }
    bool pressed = !(sio_hw->gpio_hi_in & SIO_GPIO_HI_IN_QSPI_CSN_BITS);
    hw_write_masked(&ioqspi_hw->io[CS].ctrl, GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
    /* Complete the chip-select restore before fetching code from flash.
     * Hazard3 can return to XIP sooner than a posted APB write completes. */
    (void)ioqspi_hw->io[CS].ctrl;
#ifdef __riscv
    __asm volatile("fence iorw,iorw\n fence.i" ::: "memory");
#else
    __dsb();
    __isb();
#endif
    restore_interrupts(flags);
    return pressed;
}

// The bootrom itself samples BOOT at reset (held = ROM USB loader), so the
// menu key is "press BOOT just after power-up": the cue pin (the LCD
// backlight on the Waveshare board, the LED on a Pico 2) lights for the
// window. Costs MB_RP2350_KEY_WINDOW_MS of boot time; 0 disables it.
#ifndef MB_RP2350_KEY_WINDOW_MS
#define MB_RP2350_KEY_WINDOW_MS 600
#endif
#ifndef MB_RP2350_CUE_PIN
#ifdef PICO_DEFAULT_LED_PIN
#define MB_RP2350_CUE_PIN PICO_DEFAULT_LED_PIN
#elif defined(WAVESHARE_LCD_BL_PIN)
#define MB_RP2350_CUE_PIN WAVESHARE_LCD_BL_PIN
#else
#define MB_RP2350_CUE_PIN -1
#endif
#endif

static bool f_button(void) {
#ifdef MB_BOOT_DIAGNOSTICS
    if (watchdog_enable_caused_reboot()) return true;
    mb_bcl_t diagnostic_log;mb_bcl_load(&diagnostic_log,&mb_rp2350_port);
    if(diagnostic_log.cur.request==MB_REQ_NONE)return true;
#endif
    if (!MB_RP2350_KEY_WINDOW_MS)
        return false;
#if MB_RP2350_CUE_PIN >= 0
    gpio_init(MB_RP2350_CUE_PIN);
    gpio_set_dir(MB_RP2350_CUE_PIN, GPIO_OUT);
    gpio_put(MB_RP2350_CUE_PIN, 1);
#endif
    bool hit = false;
    uint32_t end = f_time() + MB_RP2350_KEY_WINDOW_MS;
    while (!hit && (int32_t)(f_time() - end) < 0) {
        hit = boot_key_now();
        if (!hit)
            sleep_ms(10);
    }
#if MB_RP2350_CUE_PIN >= 0
    gpio_put(MB_RP2350_CUE_PIN, 0);
    gpio_deinit(MB_RP2350_CUE_PIN); // back to how reset left it, for the next image
#endif
    return hit;
}

static bool f_console_open(uint32_t wait_ms) {
    if (!console_up) {
        stdio_usb_init();
        console_up = true;
    }
    uint32_t end = f_time() + wait_ms;
    while (!stdio_usb_connected()) {
#ifdef MB_BOOT_DIAGNOSTICS
        watchdog_update();
#endif
        if ((int32_t)(f_time() - end) > 0)
            return false;
        sleep_ms(10);
    }
    sleep_ms(250); // terminals often drop the first bytes after DTR
    return true;
}

static int f_getc(uint32_t timeout_ms) {
#ifdef MB_BOOT_DIAGNOSTICS
    watchdog_update();
#endif
    int c = getchar_timeout_us(timeout_ms * 1000u);
    return c == PICO_ERROR_TIMEOUT ? -1 : c;
}

static void f_write(const char *s, size_t n) {
#ifdef MB_BOOT_DIAGNOSTICS
 watchdog_update();
#endif
 stdio_put_string(s,(int)n,false,true);
}

// Leave the chip the way the next image expects to find it after reset:
// no interrupts armed, timers quiet, USB gone (and the host told so), and
// the DMA / SHA blocks fresh but *released* (the bootrom may hash the image).
static void quiesce(void) {
    if (console_up) {
        stdio_flush();
        sleep_ms(20);
        reset_block_num(RESET_USBCTRL); // drops the pull-up: the host sees a disconnect
        sleep_ms(150);
        unreset_block_num_wait_blocking(RESET_USBCTRL);
        console_up = false;
    }
    uint32_t s = save_and_disable_interrupts();
    for (uint i = 0; i < NUM_IRQS; i++) {
        irq_set_enabled(i, false);
        irq_clear(i);
    }
#if !defined(__riscv)
    systick_hw->csr = 0;
#endif
    timer0_hw->inte = 0;
    timer1_hw->inte = 0;
    reset_unreset_block_num_wait_blocking(RESET_DMA);
    reset_unreset_block_num_wait_blocking(RESET_SHA256);
    restore_interrupts(s);
}

static void *f_ram_ptr(uint32_t addr, uint32_t len) {
    if (addr < SRAM_BASE_ADDR || addr >= MB_RP2350_LOADER_RAM || len > MB_RP2350_LOADER_RAM - addr)
        return NULL;
    return (void *)(uintptr_t)addr;
}

static bool f_can_start(const mb_image_hdr_t *h) {
    if (h->load_type == MB_LOAD_RAM) // either arch: the other one via a switch reboot
        return (h->arch == MB_ARCH_ARM || h->arch == MB_ARCH_RISCV || h->arch == MB_ARCH_ANY) &&
               f_ram_ptr(h->load_addr, h->payload_size) != NULL;
    // XIP: chain_image runs it on the current cores. An image for the other
    // cores needs the other half of a universal MimiBoot to start it.
    if (h->load_type != MB_LOAD_CHAIN)
        return false;
#ifdef MB_RP2350_UNIVERSAL
    return h->arch == MB_ARCH_ANY || h->arch == MB_ARCH_ARM || h->arch == MB_ARCH_RISCV;
#else
    return h->arch == MB_ARCH_ANY || h->arch == MY_ARCH;
#endif
}

#ifdef MB_RP2350_UNIVERSAL
// Reboot with both cores switched; the bootrom then starts the other half of
// this (universal) image, which finds the boot request in the log.
static void f_switch_arch(uint8_t arch) {
    quiesce();
    uint32_t flags = REBOOT2_FLAG_REBOOT_TYPE_NORMAL | REBOOT2_FLAG_NO_RETURN_ON_SUCCESS |
                     (arch == MB_ARCH_RISCV ? REBOOT2_FLAG_REBOOT_TO_RISCV : REBOOT2_FLAG_REBOOT_TO_ARM);
    rom_reboot(flags, 10, 0, 0);
}
#define SWITCH_ARCH f_switch_arch
#else
#define SWITCH_ARCH NULL
#endif

/* A universal loader may itself be running through a rolling QMI mapping.
 * Chain physical slot offsets from identity mapping. The entire transition
 * executes from SRAM; restore the caller mapping if the ROM rejects it. */
static int __no_inline_not_in_flash_func(chain_physical)(
    rom_chain_image_fn chain, rom_flash_reset_address_trans_fn identity,
    rom_flash_flush_cache_fn flush, uint32_t base, uint32_t size) {
  uint32_t saved[8];
  for (unsigned i = 0; i < 8; i++)
    saved[i] = qmi_hw->atrans[i];
  identity();
  flush();
  int rc = chain(chain_workarea, sizeof chain_workarea, base, size);
  for (unsigned i = 0; i < 8; i++)
    qmi_hw->atrans[i] = saved[i];
  flush();
#ifdef __riscv
  __asm volatile("fence.i" ::: "memory");
#else
  __dsb();
  __isb();
#endif
  return rc;
}

static int f_launch(const mb_image_hdr_t *hdr, uint32_t slot_off,
                    uint32_t slot_size) {
  if (hdr->load_type != MB_LOAD_CHAIN)
    return MB_E_UNSUPP;
  quiesce();
  uint32_t base = XIP_BASE + slot_off + hdr->payload_offset;
  uint32_t size = slot_size - hdr->payload_offset;
  rom_chain_image_fn chain =
      (rom_chain_image_fn)rom_func_lookup_inline(ROM_FUNC_CHAIN_IMAGE);
  rom_flash_reset_address_trans_fn identity =
      (rom_flash_reset_address_trans_fn)rom_func_lookup_inline(
          ROM_FUNC_FLASH_RESET_ADDRESS_TRANS);
  rom_flash_flush_cache_fn flush =
      (rom_flash_flush_cache_fn)rom_func_lookup_inline(
          ROM_FUNC_FLASH_FLUSH_CACHE);
  bootrom_release_lock(BOOTROM_LOCK_ENABLE);
  uint32_t key = save_and_disable_interrupts();
  int rc = chain_physical(chain, identity, flush, base, size);
  restore_interrupts_from_disabled(key);
  bootrom_acquire_lock_blocking(BOOTROM_LOCK_ENABLE);
  watchdog_disable(); // only on failure: a trial's watchdog mustn't reset the
                      // console next
  return rc;
}

static int f_launch_ram(const mb_image_hdr_t *hdr) {
  if (!f_ram_ptr(hdr->load_addr, hdr->payload_size))
    return MB_E_REFUSED;
  /* REBOOT_TO_* selects core 0. A homogeneous RAM image for the other ISA
   * also needs core 1 selected while that socket is held in reset. Mixed
   * profiles already switch loader ISA and prepare their explicit pair. */
  if (hdr->arch != MB_ARCH_ANY && hdr->arch != MY_ARCH) {
    mb_topology_t pair = {MY_ARCH, hdr->arch, 0};
    int prepared = night_prepare(pair);
    if (prepared)
      return prepared;
  }
  uint32_t size = (hdr->payload_size + 3u) & ~3u;
  /* RAM_IMAGE preserves the declared image range across its reboot. A
   * NOLOAD handoff commonly follows the file-backed bytes; include it too. */
  if (hdr->handoff_addr) {
    if (hdr->handoff_addr < hdr->load_addr ||
        !f_ram_ptr(hdr->handoff_addr, sizeof(mb_handoff_t)))
      return MB_E_REFUSED;
    uint32_t handoff_end =
        hdr->handoff_addr - hdr->load_addr + sizeof(mb_handoff_t);
    if (handoff_end > size)
      size = (handoff_end + 3u) & ~3u;
  }
  quiesce();
  int rc;
  if ((hdr->arch == MB_ARCH_ANY || hdr->arch == MY_ARCH) &&
      MY_ARCH != MB_ARCH_RISCV) {
    rc = rom_chain_image(chain_workarea, sizeof(chain_workarea), hdr->load_addr,
                         size);
  } else {
    // Switch both cores to the other architecture and have the bootrom
    // look for the image in SRAM. The trial attempt is already recorded.
    uint32_t flags = REBOOT2_FLAG_REBOOT_TYPE_RAM_IMAGE |
                     REBOOT2_FLAG_NO_RETURN_ON_SUCCESS |
                     (hdr->arch == MB_ARCH_RISCV ? REBOOT2_FLAG_REBOOT_TO_RISCV
                                                 : REBOOT2_FLAG_REBOOT_TO_ARM);
    rc = rom_reboot(flags, 10, hdr->load_addr, size);
  }
  watchdog_disable();
  return rc;
}

static void f_reboot(void) {
  if (console_up) {
    stdio_flush();
    sleep_ms(20);
  }
  watchdog_reboot(0, 0, 10);
  for (;;)
    tight_loop_contents();
}

static void f_rom(void) {
  if (console_up) {
    stdio_flush();
    sleep_ms(20);
  }
  rom_reset_usb_boot(0, 0);
}

static const char *f_reason(void) {
    uint32_t c = f_cause();
    return c & MB_RESET_WATCHDOG ? "watchdog reset" : c & MB_RESET_SOFT ? "reboot" : "power-on / reset";
}

const mb_port_t mb_rp2350_port = {
    .capabilities = night_caps,
#ifndef MB_RP2350_CLIENT
    .prepare_topology = night_prepare,
#endif
    .name = "rp2350",
    .target = MB_RP2350_TARGET,
    .layout = &layout,
    .arch = MY_ARCH,
    .keys = KEYRING,
    .require_signature = MB_REQUIRE_SIGNATURE,
    .flash_read = f_read,
    .flash_erase = f_erase,
    .flash_program = f_program,
    .hash_flash = f_hash,
    .hash_mem = f_hash_mem,
    .can_start = f_can_start,
    .launch = f_launch,
    .ram_ptr = f_ram_ptr,
    .launch_ram = f_launch_ram,
    .switch_arch = SWITCH_ARCH,
    .time_ms = f_time,
    .watchdog_arm = f_wdt,
    .watchdog_disarm = f_wdt_off,
    .button = f_button,
    .console_open = f_console_open,
    .getc = f_getc,
    .write = f_write,
    .reboot = f_reboot,
    .reboot_rom = f_rom,
    .reset_cause = f_cause,
    .reset_reason = f_reason,
};

#else

// ---------------------------------------------------------------------------
// App side
// ---------------------------------------------------------------------------

static int f_self(void) {
    // where does 0x10000000 really come from? (the bootrom set up the mapping)
    intptr_t storage = rom_flash_runtime_to_storage_addr(XIP_BASE);
    if (storage < 0)
        return MB_SLOT_NONE;
    if ((uint32_t)storage >= XIP_BASE)
        storage -= XIP_BASE; // seen on hardware: it returns an address, not an offset
    for (int i = 0; i < layout.n_slots; i++)
        if ((uint32_t)storage == layout.slot[i].offset + MB_IMG_PAYLOAD_OFF)
            return i;
    return MB_SLOT_NONE; // not started by MimiBoot from a slot (flashed at 0, or a RAM image)
}

static void f_reboot(void) {
    watchdog_reboot(0, 0, 10);
    for (;;)
        tight_loop_contents();
}

const mb_port_t mb_rp2350_port = {
    .capabilities = night_caps,
#ifndef MB_RP2350_CLIENT
    .prepare_topology = night_prepare,
#endif
    .name = "rp2350",
    .target = MB_RP2350_TARGET,
    .layout = &layout,
    .arch = MY_ARCH,
    .keys = KEYRING,
    .require_signature = MB_REQUIRE_SIGNATURE,
    .flash_read = f_read,
    .flash_erase = f_erase,
    .flash_program = f_program,
    .hash_flash = f_hash,
    .hash_mem = f_hash_mem,
    .time_ms = f_time,
    .reboot = f_reboot,
    .reset_cause = f_cause,
    .self_slot = f_self,
};

#endif
