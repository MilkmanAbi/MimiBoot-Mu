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
// RFC 6979 A.2.5's P-256 example key: the tests' ECDSA signer (tests/gen_signed.py)
static const uint8_t p256_keys[1][64] = { {
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
} };
static const mb_keyring_p256_t p256_ring = { 1, p256_keys };

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

// two-stage mode (sim_two_stage): aux slots c and d become the stage-1 copies
static const mb_layout_t layout2 = {
    .flash_size = SIM_FLASH_SIZE, .sector_size = 4096, .page_size = 256,
    .boot = { 0x000000, 0x010000 },
    .log = { { 0x010000, 0x1000 }, { 0x011000, 0x1000 } },
    .cfg = { { 0x012000, 0x1000 }, { 0x013000, 0x1000 } },
    .n_slots = 5,
    .slot = { { 0x020000, 0x060000, MB_ROLE_AB, "a" }, { 0x080000, 0x060000, MB_ROLE_AB, "b" },
              { 0x0E0000, 0x060000, MB_ROLE_GOLDEN, "g" }, { 0x140000, 0x060000, MB_ROLE_STAGE1, "s1a" },
              { 0x1A0000, 0x050000, MB_ROLE_STAGE1, "s1b" } },
    .data = { 0x1F0000, SIM_FLASH_SIZE - 0x1F0000 },
};

// the stage-1 key in two-stage mode: tests/gen_signed.py's OTHER_SECRET (so the app key can't sign a stage 1)
static uint8_t s1_keys[1][32];
static const mb_keyring_t s1_ring = { 1, (const uint8_t (*)[32])s1_keys };

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

// like the real port: the stage 1 that is running can't write over itself
static bool running_stage1(uint32_t off, size_t len) {
    if (!sim_port.stage1_slot || sim.stage1_slot < 0) return false;
    const mb_slot_def_t* s = &sim_port.layout->slot[sim.stage1_slot];
    return off < s->offset + s->size && off + len > s->offset;
}

static int f_erase(uint32_t off, size_t len) {
    if (off % 4096 || len % 4096 || off + len > SIM_FLASH_SIZE) return MB_E_BADARG;
    if (running_stage1(off, len)) return MB_E_REFUSED;
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
    if (running_stage1(off, len)) return MB_E_REFUSED;
    if (sim.fail_writes) return MB_E_IO;
    if (sim.write_once)
        for (size_t i = 0; i < len; i++)
            if (sim_flash[off + i] != 0xFF) return MB_E_IO;
    const uint8_t* b = buf;
    if (cut_now()) {
        for (size_t i = 0; i < len / 2; i++) sim_flash[off + i] &= b[i];
        power_fail();
    }
    for (size_t i = 0; i < len; i++) sim_flash[off + i] &= b[i];     // NOR: bits only go 1 -> 0
    sim.programs++;
    return MB_OK;
}

// The protected floor store: the last 4 KB of the bootloader region, written
// 16 bytes at a time (as nRF/STM32 would), with the same power-cut injection.
static int floor_program(uint32_t off, const void* buf, size_t len) {
    if (off < 0xF000 || off + len > 0x10000 || off % 16 || len % 16) return MB_E_BADARG;
    if (sim.fail_writes || sim.floor_locked) return MB_E_IO;
    const uint8_t* b = buf;
    if (cut_now()) {
        for (size_t i = 0; i < len / 2; i++) sim_flash[off + i] &= b[i];
        power_fail();
    }
    for (size_t i = 0; i < len; i++) sim_flash[off + i] &= b[i];
    sim.programs++;
    return MB_OK;
}
static const mb_floor_store_t floor_store = { .off = 0xF000, .size = 0x1000, .entry = 16, .read = f_read, .program = floor_program };

// The same 4 KB as two 2 KB units that can be erased: compacting stores. A power
// cut in an erase leaves the first half of the range erased, the rest as it was.
static int floor_erase(uint32_t off, size_t len) {
    if (off < 0xF000 || off + len > 0x10000 || off % 0x800 || len % 0x800) return MB_E_BADARG;
    if (sim.fail_writes || sim.floor_locked) return MB_E_IO;
    if (cut_now()) {
        memset(sim_flash + off, 0xFF, len / 2);
        power_fail();
    }
    memset(sim_flash + off, 0xFF, len);
    sim.erases++;
    return MB_OK;
}
static const mb_floor_store_t floor_store2 = { .off = 0xF000, .size = 0x1000, .entry = 16, .read = f_read,
                                               .program = floor_program, .unit = 0x800, .erase = floor_erase };
void sim_store_two(bool on) { sim_port.floor = on ? &floor_store2 : &floor_store; }

static int f_fault_slot(void) {
    int s = sim.fault_slot;
    sim.fault_slot = -1;
    return s;
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
    for (int i = 0; i < sim_port.layout->n_slots; i++) if (sim_port.layout->slot[i].offset == slot_off) sim.booted_slot = i;
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
    if (log.cur.last_slot < sim_port.layout->n_slots) {
        mb_slot_info_t info;
        if (mb_image_read_header(&sim_port, log.cur.last_slot, &info) == MB_OK && !memcmp(info.hdr.sha256, hdr->sha256, 32))
            sim.booted_slot = log.cur.last_slot;
    }
    longjmp(*sim.jmp, 1);
}

static uint32_t f_time(void) { return sim.time_ms += 1; }
// the shortest period is an app making the watchdog reset it now (mb_client_panic without a mailbox)
static void f_wdt(uint32_t ms) {
    sim.watchdog_ms = ms;
    if (ms <= 1 && sim.jmp) { sim.reset_cause = MB_RESET_WATCHDOG; sim.outcome = SIM_REBOOT; longjmp(*sim.jmp, 1); }
}
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
static int f_stage1(void) { return sim.stage1_slot; }
// the "bootloader image" of the simulator, for boot records
static int f_loader_hash(uint8_t out[32]) {
    mb_sha256_t s;
    mb_sha256_init(&s);
    mb_sha256_update(&s, "the simulated bootloader", 24);
    mb_sha256_final(&s, out);
    return MB_OK;
}

// LMS keys (tests/gen_signed.py's fixed keys): set by the test, cleared by sim_reset
static uint8_t lms_keys[1][MB_LMS_PUB_MAX], s1_lms_keys[1][MB_LMS_PUB_MAX];
static const mb_keyring_lms_t lms_ring = { 1, (const uint8_t (*)[MB_LMS_PUB_MAX])lms_keys };
static const mb_keyring_lms_t s1_lms_ring = { 1, (const uint8_t (*)[MB_LMS_PUB_MAX])s1_lms_keys };
void sim_lms(const uint8_t* pub, const uint8_t* s1_pub) {
    if (pub) memcpy(lms_keys[0], pub, 56);
    if (s1_pub) memcpy(s1_lms_keys[0], s1_pub, 56);
    sim_port.lms_keys = pub ? &lms_ring : NULL;
    sim_port.stage1_lms_keys = s1_pub ? &s1_lms_ring : NULL;
}

void sim_two_stage(bool on, const uint8_t s1_public[32]) {
    sim_port.layout = on ? &layout2 : &layout;
    sim_port.stage1_slot = on ? f_stage1 : NULL;
    if (s1_public) memcpy(s1_keys[0], s1_public, 32);
    sim_port.stage1_keys = on ? &s1_ring : NULL;
    sim.stage1_slot = -1;
}

mb_port_t sim_port = {
    .name = "sim", .target = "sim", .layout = &layout, .arch = MB_ARCH_ARM,
    .keys = &keyring, .p256_keys = &p256_ring, .require_signature = false,
    .flash_read = f_read, .flash_erase = f_erase, .flash_program = f_program,
    .can_start = f_can_start, .launch = f_launch, .ram_ptr = f_ram_ptr, .launch_ram = f_launch_ram,
    .switch_arch = f_switch_arch,
    .time_ms = f_time, .watchdog_arm = f_wdt, .watchdog_disarm = f_wdt_off, .button = f_button,
    .console_open = f_console_open, .getc = f_getc, .write = f_write,
    .reboot = f_reboot, .reboot_rom = f_rom, .reset_cause = f_cause, .reset_reason = f_reason, .self_slot = f_self,
    .floor = &floor_store, .fault_slot = f_fault_slot, .loader_hash = f_loader_hash, .retains_ram = true,
};

void sim_reset(void) {
    memset(sim_flash, 0xFF, sizeof(sim_flash));
    memset(sim_ram, 0, sizeof(sim_ram));
    memset(&sim, 0, sizeof(sim));
    sim.arch = MB_ARCH_ARM;
    sim.reset_cause = MB_RESET_POWER;
    sim.fault_slot = -1;
    sim.stage1_slot = -1;
    sim_port.require_signature = false;
    sim_port.keys = &keyring;
    sim_port.floor = &floor_store;
    sim_port.layout = &layout;                      // one-stage unless a test asks (sim_two_stage)
    sim_port.stage1_slot = NULL;
    sim_port.stage1_keys = NULL;
    sim_port.revoke_keys = NULL;
    sim_port.enc_key = NULL;
    sim_port.lms_keys = NULL;
    sim_port.stage1_lms_keys = NULL;
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
