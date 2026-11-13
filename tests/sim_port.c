/*
 * MimiBoot - simulated port for host tests
 *
 * Flash behaves like NOR: erase sets 0xFF, program can only clear bits.
 * Any erase/program can be made the moment the power fails: it is left half
 * done and control jumps back to the test, which then "powers up" again on
 * the same flash contents. RAM is an array at a fake 0x20000000 with the
 * top 64 KB belonging to "the bootloader".
 */
#include "tests/sim_port.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint8_t sim_flash[SIM_FLASH_SIZE];
uint8_t sim_ram[SIM_RAM_SIZE];
sim_t sim;

// RFC 8032 test 1 key pair: a fixed key the tests sign with
const uint8_t sim_test_secret[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};
const uint8_t sim_test_public[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};
static const uint8_t keys[1][32] = { {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
} };
static const mb_keyring_t keyring = { 1, keys };

static const mb_layout_t layout = {
    .flash_size = SIM_FLASH_SIZE, .sector_size = 4096, .page_size = 256,
    .boot = { 0x000000, 0x010000 },
    .log = { { 0x010000, 0x1000 }, { 0x011000, 0x1000 } },
    .cfg = { { 0x012000, 0x1000 }, { 0x013000, 0x1000 } },
    .n_slots = 5,
    .slot = { { 0x020000, 0x060000, MB_ROLE_AB, "a" }, { 0x080000, 0x060000, MB_ROLE_AB, "b" },
              { 0x0E0000, 0x060000, MB_ROLE_GOLDEN, "g" }, { 0x140000, 0x060000, MB_ROLE_AUX, "c" },
              { 0x1A0000, 0x050000, MB_ROLE_AUX, "d" } },
    .data = { 0x1F0000, SIM_FLASH_SIZE - 0x1F0000 },
};

static void power_fail(void) {
    sim.outcome = SIM_POWERCUT;
    longjmp(*sim.jmp, 1);
}

static bool cut_now(void) {
    sim.ops++;
    return sim.cut_at && sim.ops == sim.cut_at;
}

static int f_read(uint32_t off, void* buf, size_t len) {
    if (off > SIM_FLASH_SIZE || len > SIM_FLASH_SIZE - off) return MB_E_BADARG;
    memcpy(buf, sim_flash + off, len);
    return MB_OK;
}

static int f_erase(uint32_t off, size_t len) {
    if (off % 4096 || len % 4096 || off + len > SIM_FLASH_SIZE) return MB_E_BADARG;
    if (sim.fail_writes) return MB_E_IO;
    for (size_t s = 0; s < len; s += 4096) {
        if (cut_now()) {
            memset(sim_flash + off + s, 0xFF, 2048);    // a sector half erased
            power_fail();
        }
        memset(sim_flash + off + s, 0xFF, 4096);
        sim.erases++;
    }
    return MB_OK;
}

static int f_program(uint32_t off, const void* buf, size_t len) {
    if (off % 256 || len % 256 || off + len > SIM_FLASH_SIZE) return MB_E_BADARG;
    if (sim.fail_writes) return MB_E_IO;
    const uint8_t* b = buf;
    if (cut_now()) {
        for (size_t i = 0; i < len / 2; i++) sim_flash[off + i] &= b[i];
        power_fail();
    }
    for (size_t i = 0; i < len; i++) sim_flash[off + i] &= b[i];     // NOR: bits only go 1 -> 0
    sim.programs++;
    return MB_OK;
}

// The sim "chip" can run Arm or RISC-V. Like the RP2350 port without a
// universal bootloader: an XIP image must match the current architecture;
// a RAM image of the other one is started through an architecture switch.
static bool f_can_start(const mb_image_hdr_t* h) {
    if (h->load_type == MB_LOAD_RAM) return true;
    return h->load_type == MB_LOAD_CHAIN && (h->arch == MB_ARCH_ANY || h->arch == sim.arch || sim.universal);
}

// the chip reboots on the other cores (a "reboot" outcome; the test powers on again)
static void f_switch_arch(uint8_t arch) {
    if (!sim.universal) return;
    sim.arch = arch;
    sim.arch_switches++;
    sim.reset_cause = MB_RESET_WATCHDOG;            // worst case: the switch reboot reads as a watchdog reset
    sim.outcome = SIM_REBOOT;
    longjmp(*sim.jmp, 1);
}

static int f_launch(const mb_image_hdr_t* hdr, uint32_t slot_off, uint32_t slot_size) {
    (void)slot_size;
    if (sim.launch_fails) return MB_E_UNSUPP;
    sim.outcome = SIM_BOOTED;
    sim.booted_ram = false;
    sim.booted_arch = sim.arch;
    sim.booted_off = slot_off;
    sim.booted_hdr = *hdr;
    sim.booted_slot = -1;
    for (int i = 0; i < layout.n_slots; i++) if (layout.slot[i].offset == slot_off) sim.booted_slot = i;
    longjmp(*sim.jmp, 1);
}

static void* f_ram_ptr(uint32_t addr, uint32_t len) {
    if (addr < SIM_RAM_BASE || len > SIM_LOADER_RAM - SIM_RAM_BASE || addr - SIM_RAM_BASE > SIM_LOADER_RAM - SIM_RAM_BASE - len) return NULL;
    return sim_ram + (addr - SIM_RAM_BASE);
}

static int f_launch_ram(const mb_image_hdr_t* hdr) {
    if (sim.launch_fails) return MB_E_UNSUPP;
    sim.outcome = SIM_BOOTED;
    sim.booted_ram = true;
    sim.booted_arch = hdr->arch == MB_ARCH_ANY ? sim.arch : hdr->arch;     // other arch: switch-and-reboot
    sim.booted_hdr = *hdr;
    sim.booted_slot = -1;
    // which slot did it come from (if any)? the newest log knows
    mb_bcl_t log;
    mb_bcl_load(&log, &sim_port);
    if (log.cur.last_slot < layout.n_slots) {
        mb_slot_info_t info;
        if (mb_image_read_header(&sim_port, log.cur.last_slot, &info) == MB_OK && !memcmp(info.hdr.sha256, hdr->sha256, 32))
            sim.booted_slot = log.cur.last_slot;
    }
    longjmp(*sim.jmp, 1);
}

static uint32_t f_time(void) { return sim.time_ms += 1; }
static void f_wdt(uint32_t ms) { sim.watchdog_ms = ms; }
static void f_wdt_off(void) { sim.watchdog_ms = 0; }
static bool f_button(void) { return sim.button; }
static bool f_console_open(uint32_t wait_ms) { (void)wait_ms; return sim.console; }

static int f_getc(uint32_t timeout_ms) {
    (void)timeout_ms;
    if (sim.in_pos < sim.in_len) return (uint8_t)sim.in[sim.in_pos++];
    sim.outcome = SIM_CONSOLE_IDLE;             // script exhausted: a host that went away
    longjmp(*sim.jmp, 1);
}

static void f_write(const char* s, size_t n) {
    if (sim.out_len + n >= sizeof(sim.out)) n = sizeof(sim.out) - 1 - sim.out_len;
    memcpy(sim.out + sim.out_len, s, n);
    sim.out_len += n;
    sim.out[sim.out_len] = 0;
}

static void f_reboot(void) { sim.outcome = SIM_REBOOT; longjmp(*sim.jmp, 1); }
static void f_rom(void) { sim.outcome = SIM_ROM; longjmp(*sim.jmp, 1); }
static uint32_t f_cause(void) { return sim.reset_cause; }
static const char* f_reason(void) { return sim.reset_cause & MB_RESET_WATCHDOG ? "sim watchdog" : "sim power-on"; }
static int f_self(void) { return sim.self_slot; }

mb_port_t sim_port = {
    .name = "sim", .target = "sim", .layout = &layout, .arch = MB_ARCH_ARM,
    .keys = &keyring, .require_signature = false,
    .flash_read = f_read, .flash_erase = f_erase, .flash_program = f_program,
    .can_start = f_can_start, .launch = f_launch, .ram_ptr = f_ram_ptr, .launch_ram = f_launch_ram,
    .switch_arch = f_switch_arch,
    .time_ms = f_time, .watchdog_arm = f_wdt, .watchdog_disarm = f_wdt_off, .button = f_button,
    .console_open = f_console_open, .getc = f_getc, .write = f_write,
    .reboot = f_reboot, .reboot_rom = f_rom, .reset_cause = f_cause, .reset_reason = f_reason, .self_slot = f_self,
};

void sim_reset(void) {
    memset(sim_flash, 0xFF, sizeof(sim_flash));
    memset(sim_ram, 0, sizeof(sim_ram));
    memset(&sim, 0, sizeof(sim));
    sim.arch = MB_ARCH_ARM;
    sim.reset_cause = MB_RESET_POWER;
    sim_port.require_signature = false;
    sim_port.keys = &keyring;
}

void sim_input(const void* data, size_t len) {
    if (len > sizeof(sim.in)) { fprintf(stderr, "sim_input: script too long\n"); exit(2); }
    memcpy(sim.in, data, len);
    sim.in_len = len;
    sim.in_pos = 0;
}

sim_outcome_t sim_power_on(void) {
    jmp_buf here;
    jmp_buf* prev = sim.jmp;
    sim.jmp = &here;
    sim.outcome = SIM_NONE;
    sim.watchdog_ms = 0;
    sim.out_len = 0;
    sim.out[0] = 0;
    sim.booted_slot = -1;
    sim.booted_ram = false;
    sim_port.arch = sim.arch;                       // the bootloader half for the cores the chip is on
    if (!setjmp(here)) {
        mb_main(&sim_port);
        sim.outcome = SIM_RETURNED;                  // mb_main must never return
    }
    sim.jmp = prev;
    return sim.outcome;
}

sim_outcome_t sim_guard(void (*fn)(void* ctx), void* ctx) {
    jmp_buf here;
    jmp_buf* prev = sim.jmp;
    sim.jmp = &here;
    sim.outcome = SIM_NONE;
    if (!setjmp(here)) fn(ctx);
    sim.jmp = prev;
    return sim.outcome;
}
