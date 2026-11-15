/*
 * MimiBoot host tests: the portable core against a simulated NOR flash.
 *
 *   crypto       CRC-32, SHA-256, SHA-512, Ed25519 (test_crypto.c)
 *   boot flows   first install, trial + confirm, rollback of an unconfirmed
 *                update, bad hash, anti-rollback, golden fallback, golden
 *                monotonicity, requests, no-write normal boots
 *   config       parsing, bad input, fuzzing, entries, args, power cuts on save
 *   handoff      written for the right image, validated, never stale
 *   signatures   signed by mbtool (Python), checked here; required / optional
 *   guard        crash-loop guard on watchdog resets
 *   RAM images   staged + hashed in RAM, other-architecture boots
 *   console      menu, commands, recv, ramboot, cfg recv
 *   OTA          an app receiving its own update through the client library
 *   power cuts   A/B updates replayed with the power cut at every flash op
 */
#include "tests/sim_port.h"
#include "client/mb_client.h"
#include "client/mb_ctl.h"
#include "tests/gen_signed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_crypto(void);
extern int crypto_fails, crypto_checks;

static int fails, checks;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { fails++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void hex(const uint8_t* b, int n, char* out) { for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]); }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

static uint8_t payload[0x60000];

static uint32_t make_payload(uint32_t seed, uint32_t size) {
    uint32_t x = seed * 2654435761u + 1;
    for (uint32_t i = 0; i < size; i++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; payload[i] = (uint8_t)x; }
    return size;
}

static mb_image_hdr_t make_header_ex(const char* name, uint32_t version, uint32_t secver, uint32_t size, uint32_t flags,
                                     uint8_t arch, uint32_t load_type, uint32_t load_addr, uint32_t handoff) {
    mb_image_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = MB_IMG_MAGIC;
    h.hdr_version = MB_IMG_HDR_VERSION;
    h.hdr_size = MB_IMG_HDR_SIZE;
    h.flags = flags;
    h.load_type = load_type;
    h.payload_offset = MB_IMG_PAYLOAD_OFF;
    h.payload_size = size;
    mb_sha256_t s;
    mb_sha256_init(&s);
    mb_sha256_update(&s, payload, size);
    mb_sha256_final(&s, h.sha256);
    h.version = version;
    h.security_version = secver;
    h.load_addr = load_addr;
    h.handoff_addr = handoff;
    h.arch = arch;
    strncpy(h.name, name, sizeof(h.name) - 1);
    strncpy(h.target, "sim", sizeof(h.target) - 1);
    mb_image_seal(&h);
    return h;
}

static mb_image_hdr_t make_header(const char* name, uint32_t version, uint32_t secver, uint32_t size, uint32_t flags) {
    return make_header_ex(name, version, secver, size, flags, MB_ARCH_ARM, MB_LOAD_CHAIN, 0, 0);
}

static void put_image(int slot, const mb_image_hdr_t* h) {
    uint32_t off = sim_port.layout->slot[slot].offset;
    memset(sim_flash + off, 0xFF, MB_IMG_PAYLOAD_OFF + h->payload_size);
    memcpy(sim_flash + off, h, sizeof(*h));
    memcpy(sim_flash + off + MB_IMG_PAYLOAD_OFF, payload, h->payload_size);
}

// write straight into flash (no op accounting): "picotool load"
static void install_raw(int slot, const char* name, uint32_t version, uint32_t secver, uint32_t seed, uint32_t size) {
    make_payload(seed, size);
    mb_image_hdr_t h = make_header(name, version, secver, size, slot == MB_SLOT_GOLDEN ? MB_IMG_F_GOLDEN : 0);
    put_image(slot, &h);
}

static bool slot_intact(int slot) {
    mb_slot_info_t info;
    if (mb_image_read_header(&sim_port, slot, &info) != MB_OK) return false;
    return mb_image_verify(&sim_port, slot, &info) == MB_OK;
}

static int boot(void) {
    sim_outcome_t o = sim_power_on();
    return o == SIM_BOOTED ? sim.booted_slot : -(int)o;
}

static void confirm_fn(void* ctx) {
    (void)ctx;
    mb_client_init(&sim_port);
    mb_client_confirm();
}

static void app_confirms(void) {
    sim.self_slot = sim.booted_slot;
    sim_guard(confirm_fn, NULL);
}

static mb_bcl_rec_t log_now(void) {
    mb_bcl_t b;
    mb_bcl_load(&b, &sim_port);
    return b.cur;
}

static uint32_t writes(void) { return sim.programs + sim.erases; }

static int save_cfg(const char* text) { return mb_config_save(&sim_port, text, strlen(text)); }

// ---------------------------------------------------------------------------

static void test_hashes(void) {
    printf("CRC-32 / SHA-256\n");
    CHECK(mb_crc32(0, "123456789", 9) == 0xCBF43926u, "crc32 check value %08x", mb_crc32(0, "123456789", 9));
    uint32_t c = mb_crc32(0, "1234", 4);
    CHECK(mb_crc32(c, "56789", 5) == 0xCBF43926u, "crc32 incremental");
    struct { const char* msg; const char* want; } v[] = {
        { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    };
    for (unsigned i = 0; i < 3; i++) {
        mb_sha256_t s;
        uint8_t d[32];
        char h[65];
        mb_sha256_init(&s);
        mb_sha256_update(&s, v[i].msg, strlen(v[i].msg));
        mb_sha256_final(&s, d);
        hex(d, 32, h);
        CHECK(!strcmp(h, v[i].want), "sha256(\"%s\") = %s", v[i].msg, h);
    }
    mb_sha256_t s;
    uint8_t d[32];
    char h[65];
    static char a[1100];
    memset(a, 'a', sizeof(a));
    mb_sha256_init(&s);
    size_t left = 1000000;
    for (size_t k = 1; left; k = k % 997 + 7) { size_t n = k < left ? k : left; mb_sha256_update(&s, a, n); left -= n; }
    mb_sha256_final(&s, d);
    hex(d, 32, h);
    CHECK(!strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), "sha256(1M a) = %s", h);
}

static void test_empty(void) {
    printf("empty flash\n");
    sim_reset();
    CHECK(boot() == -SIM_ROM, "nothing bootable, no console host -> ROM loader");
    sim.console = true;
    sim_input("", 0);
    sim_outcome_t o = sim_power_on();
    CHECK(o == SIM_CONSOLE_IDLE && strstr(sim.out, "nothing bootable"), "console says nothing bootable");
}

static void test_first_install(void) {
    printf("first install, trial, confirm\n");
    sim_reset();
    install_raw(MB_SLOT_A, "app", MB_VERSION(1, 0, 0), 1, 1, 50000);
    CHECK(boot() == MB_SLOT_A, "boots A");
    CHECK(sim.watchdog_ms == MB_DEFAULT_TRIAL_MS, "trial arms the watchdog (%u)", sim.watchdog_ms);
    mb_bcl_rec_t r = log_now();
    CHECK(r.slot[MB_SLOT_A].state == MB_ST_TRIAL && r.slot[MB_SLOT_A].tries_left == MB_DEFAULT_TRIES - 1, "A on trial");
    app_confirms();
    r = log_now();
    CHECK(r.slot[MB_SLOT_A].state == MB_ST_GOOD && r.active == MB_SLOT_A && r.min_security == 1, "A confirmed, active, floor 1");
    CHECK(boot() == MB_SLOT_A, "first normal boot");     // records "last boot: normal" once
    uint32_t w0 = writes();
    for (int i = 0; i < 20; i++) {
        CHECK(boot() == MB_SLOT_A, "normal boot %d", i);
        CHECK(sim.watchdog_ms == 0, "no watchdog on a confirmed image");
        app_confirms();                                   // apps call it every boot: must not write
    }
    CHECK(writes() == w0, "normal boots + repeat confirms write nothing (%u writes)", writes() - w0);
}

static void good_a(void) {
    sim_reset();
    install_raw(MB_SLOT_A, "app", MB_VERSION(1, 0, 0), 1, 1, 50000);
    boot();
    app_confirms();
    boot();
}

static void test_update_rollback(void) {
    printf("update never confirms -> rolled back\n");
    good_a();
    install_raw(MB_SLOT_B, "app", MB_VERSION(1, 1, 0), 1, 2, 60000);
    for (int i = 0; i < MB_DEFAULT_TRIES; i++) {
        CHECK(boot() == MB_SLOT_B, "trial %d of B", i + 1);
        CHECK(sim.watchdog_ms != 0, "watchdog armed");
    }
    CHECK(boot() == MB_SLOT_A, "after %d unconfirmed boots: back to A", MB_DEFAULT_TRIES);
    mb_bcl_rec_t r = log_now();
    CHECK(r.slot[MB_SLOT_B].state == MB_ST_BAD && r.slot[MB_SLOT_B].bad_reason == MB_BAD_TRIALS, "B bad (never confirmed)");
    CHECK(r.last_kind == MB_KIND_FALLBACK, "A booted as fallback (%d)", r.last_kind);
    CHECK(boot() == MB_SLOT_A, "and stays on A");

    printf("update confirms -> becomes active\n");
    good_a();
    install_raw(MB_SLOT_B, "app", MB_VERSION(1, 1, 0), 2, 3, 60000);
    CHECK(boot() == MB_SLOT_B, "trial B");
    app_confirms();
    r = log_now();
    CHECK(r.active == MB_SLOT_B && r.min_security == 2, "B active, floor raised to 2");
    CHECK(boot() == MB_SLOT_B && sim.watchdog_ms == 0, "B boots normally");
}

static void test_bad_hash(void) {
    printf("corrupted images\n");
    good_a();
    install_raw(MB_SLOT_B, "app", MB_VERSION(2, 0, 0), 1, 4, 60000);
    sim_flash[sim_port.layout->slot[MB_SLOT_B].offset + MB_IMG_PAYLOAD_OFF + 12345] ^= 0x10;
    CHECK(boot() == MB_SLOT_A, "flipped bit in B -> boots A");
    CHECK(log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_HASH, "B bad (hash)");
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 0, 0), 0, 9, 30000);
    sim_flash[sim_port.layout->slot[MB_SLOT_A].offset + MB_IMG_PAYLOAD_OFF + 7] ^= 1;
    CHECK(boot() == MB_SLOT_GOLDEN && log_now().last_kind == MB_KIND_GOLDEN, "A rotted too -> golden");
    sim_flash[sim_port.layout->slot[MB_SLOT_GOLDEN].offset + MB_IMG_PAYLOAD_OFF] ^= 1;
    CHECK(boot() == -SIM_ROM, "everything bad -> ROM loader");
    good_a();
    sim_flash[sim_port.layout->slot[MB_SLOT_A].offset + 40] ^= 1;
    CHECK(boot() == -SIM_ROM && log_now().slot[MB_SLOT_A].state == MB_ST_EMPTY, "header CRC broken -> empty");
}

static void test_antirollback(void) {
    printf("anti-rollback, targets, architectures\n");
    sim_reset();
    install_raw(MB_SLOT_A, "app", MB_VERSION(3, 0, 0), 5, 1, 40000);
    boot();
    app_confirms();
    install_raw(MB_SLOT_B, "app-old", MB_VERSION(2, 0, 0), 3, 2, 40000);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_ROLLBACK, "older security version refused");
    install_raw(MB_SLOT_B, "app-same", MB_VERSION(3, 0, 1), 5, 3, 40000);
    CHECK(boot() == MB_SLOT_B, "same security version is fine");
    // wrong target
    sim_reset();
    make_payload(5, 1000);
    mb_image_hdr_t h = make_header("other", 1, 0, 1000, 0);
    strcpy(h.target, "stm32");
    mb_image_seal(&h);
    put_image(MB_SLOT_A, &h);
    CHECK(boot() == -SIM_ROM && log_now().slot[MB_SLOT_A].bad_reason == MB_BAD_TARGET, "image for another chip refused");
    // an XIP image for the other architecture can't be chained into
    sim_reset();
    make_payload(6, 2000);
    h = make_header_ex("rv-xip", 1, 0, 2000, 0, MB_ARCH_RISCV, MB_LOAD_CHAIN, 0, 0);
    put_image(MB_SLOT_A, &h);
    CHECK(boot() == -SIM_ROM && log_now().slot[MB_SLOT_A].bad_reason == MB_BAD_TARGET, "XIP RISC-V on an Arm boot: can't start");
}

static void test_golden(void) {
    printf("golden monotonic\n");
    sim_reset();
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 0, 0), 0, 1, 20000);
    CHECK(boot() == MB_SLOT_GOLDEN && sim.watchdog_ms == 0, "golden alone boots, not as a trial");
    mb_bcl_rec_t r = log_now();
    CHECK(r.slot[MB_SLOT_GOLDEN].state == MB_ST_GOOD && r.golden_version == MB_VERSION(1, 0, 0), "golden recorded at v1.0.0");
    install_raw(MB_SLOT_GOLDEN, "rescue-evil", MB_VERSION(1, 0, 0), 0, 2, 20000);
    CHECK(boot() == -SIM_ROM && log_now().slot[MB_SLOT_GOLDEN].bad_reason == MB_BAD_GOLDEN_OLD, "same-version golden swap refused");
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(0, 9, 0), 0, 3, 20000);
    CHECK(boot() == -SIM_ROM, "older golden refused");
    install_raw(MB_SLOT_GOLDEN, "rescue2", MB_VERSION(1, 1, 0), 0, 4, 20000);
    CHECK(boot() == MB_SLOT_GOLDEN && log_now().golden_version == MB_VERSION(1, 1, 0), "newer golden accepted");
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 0, 0), 0, 1, 20000);
    CHECK(boot() == -SIM_ROM, "and the old one can't come back");
}

// ---------------------------------------------------------------------------
// protected floors: what an app that has been taken over can and can't undo
// ---------------------------------------------------------------------------

static uint32_t hw_floor(int which) {
    uint32_t v[MB_FLOOR_COUNT];
    mb_floor_get(&sim_port, v);
    return v[which];
}

// what a hostile app can do: write any log record it likes
static void forge_log(uint32_t min_security, uint32_t golden_version) {
    mb_bcl_t b;
    mb_bcl_load(&b, &sim_port);
    mb_bcl_rec_t r = b.cur;
    r.min_security = min_security;
    r.golden_version = golden_version;
    r.golden_id = 0;
    mb_bcl_commit(&b, &r);
}

static void wipe_log(void) {
    for (int i = 0; i < 2; i++)
        memset(sim_flash + sim_port.layout->log[i].offset, 0xFF, sim_port.layout->log[i].size);
}

typedef struct { int which; uint32_t value; int rc; } raise_t;
static void raise_fn(void* ctx) { raise_t* r = ctx; r->rc = mb_floor_raise(&sim_port, r->which, r->value); }

static void test_protected_floors(void) {
    printf("protected floors: confirmed images raise them, a hostile log can't lower them\n");
    sim_reset();
    install_raw(MB_SLOT_A, "app", MB_VERSION(1, 0, 0), 1, 1, 30000);
    boot();
    app_confirms();
    CHECK(hw_floor(MB_FLOOR_SECURITY) == 0, "a confirm alone writes only the log");
    CHECK(boot() == MB_SLOT_A && hw_floor(MB_FLOOR_SECURITY) == 1, "the next boot of the confirmed image raises the store to 1");
    install_raw(MB_SLOT_B, "app", MB_VERSION(2, 0, 0), 3, 2, 30000);
    CHECK(boot() == MB_SLOT_B, "trial of B (security 3)");
    CHECK(hw_floor(MB_FLOOR_SECURITY) == 1, "a trial doesn't raise the store");
    app_confirms();
    CHECK(boot() == MB_SLOT_B && hw_floor(MB_FLOOR_SECURITY) == 3, "confirmed B raised it to 3");
    uint32_t w0 = writes();
    for (int i = 0; i < 5; i++) boot();
    CHECK(writes() == w0, "steady state: no writes (%u)", writes() - w0);

    // A still holds the old security-1 image. The app forges a log with the
    // floor at 0 and A marked good and active.
    forge_log(0, 0);
    mb_client_init(&sim_port);
    mb_client_reject(MB_SLOT_B);
    {
        mb_bcl_t b;
        mb_bcl_load(&b, &sim_port);
        mb_bcl_rec_t r = b.cur;
        r.active = MB_SLOT_A;
        r.slot[MB_SLOT_A].state = MB_ST_GOOD;
        mb_bcl_commit(&b, &r);
    }
    CHECK(boot() != MB_SLOT_A && log_now().slot[MB_SLOT_A].bad_reason == MB_BAD_ROLLBACK, "forged log floor: old A still refused");
    CHECK(log_now().min_security == 0 || log_now().min_security >= 3, "log floor is never left below the store");

    printf("protected floors: a wiped log\n");
    sim_reset();
    install_raw(MB_SLOT_A, "app", MB_VERSION(1, 0, 0), 1, 1, 30000);
    install_raw(MB_SLOT_B, "app", MB_VERSION(2, 0, 0), 3, 2, 30000);
    boot();                                                     // B first (newer)
    app_confirms();
    boot();
    CHECK(hw_floor(MB_FLOOR_SECURITY) == 3, "store at 3");
    // the app erases the log and the new image, leaving only the old one
    wipe_log();
    memset(sim_flash + sim_port.layout->slot[MB_SLOT_B].offset, 0xFF, 0x1000);
    CHECK(boot() != MB_SLOT_A, "old image doesn't boot after a log wipe");
    CHECK(log_now().slot[MB_SLOT_A].bad_reason == MB_BAD_ROLLBACK, "refused as a rollback");

    printf("protected floors: console 'boot force' and ramboot respect them\n");
    sim.console = true;
    sim.button = true;
    sim_input("c\rboot a force\r", 15);
    sim_outcome_t o = sim_power_on();
    CHECK(o == SIM_CONSOLE_IDLE && strstr(sim.out, "not bootable"), "boot a force refused (%d)", o);
    sim.button = false;
    sim.console = false;
    make_payload(40, 4000);
    mb_image_hdr_t ram = make_header_ex("old-ram", MB_VERSION(1, 0, 0), 2, 4000, 0, MB_ARCH_ARM, MB_LOAD_RAM, SIM_RAM_BASE + 0x1000, 0);
    memcpy(sim_ram + 0x1000, payload, 4000);
    mb_bcl_t lg;
    mb_bcl_load(&lg, &sim_port);
    mb_config_t cfg;
    mb_config_builtin(&sim_port, &cfg);
    sim_port.require_signature = true;
    CHECK(mb_boot_ram(&sim_port, &lg, &cfg, &ram, "") == MB_E_REFUSED, "signatures required: RAM image below the floor refused");
    sim_port.require_signature = false;

    printf("protected floors: golden\n");
    sim_reset();
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 2, 0), 0, 5, 20000);
    CHECK(boot() == MB_SLOT_GOLDEN && hw_floor(MB_FLOOR_GOLDEN) == MB_VERSION(1, 2, 0), "golden 1.2 recorded in the store");
    wipe_log();
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 1, 0), 0, 6, 20000);
    CHECK(boot() == -SIM_ROM && log_now().slot[MB_SLOT_GOLDEN].bad_reason == MB_BAD_GOLDEN_OLD, "older golden refused after a log wipe");
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 2, 0), 0, 5, 20000);
    wipe_log();
    CHECK(boot() == MB_SLOT_GOLDEN, "the same golden version comes back fine");

    printf("protected floors: store full, torn entry, locked store\n");
    sim_reset();
    for (uint32_t v = 1; v <= 256; v++) {
        raise_t r = { MB_FLOOR_SECURITY, v, 0 };
        raise_fn(&r);
        if (r.rc != MB_OK) { CHECK(r.rc == MB_E_NOSPACE && v == 257, "store took %u entries", v - 1); break; }
    }
    raise_t full = { MB_FLOOR_SECURITY, 999, 0 };
    raise_fn(&full);
    CHECK(full.rc == MB_E_NOSPACE && hw_floor(MB_FLOOR_SECURITY) == 256, "full: NOSPACE, keeps 256 (%d, %u)", full.rc, hw_floor(0));
    install_raw(MB_SLOT_A, "app", MB_VERSION(9, 0, 0), 300, 1, 30000);
    boot();
    app_confirms();
    CHECK(boot() == MB_SLOT_A, "a full store doesn't stop the boot");

    sim_reset();
    raise_t a = { MB_FLOOR_SECURITY, 5, 0 };
    raise_fn(&a);
    sim.cut_at = sim.ops + 1;
    raise_t torn = { MB_FLOOR_SECURITY, 9, 0 };
    CHECK(sim_guard(raise_fn, &torn) == SIM_POWERCUT, "power cut in the middle of a raise");
    sim.cut_at = 0;
    CHECK(hw_floor(MB_FLOOR_SECURITY) == 5, "torn entry ignored: still 5");
    raise_t again = { MB_FLOOR_SECURITY, 9, 0 };
    raise_fn(&again);
    CHECK(again.rc == MB_OK && hw_floor(MB_FLOOR_SECURITY) == 9, "next raise lands after the torn entry: 9");
    raise_t lower = { MB_FLOOR_SECURITY, 2, 0 };
    raise_fn(&lower);
    CHECK(lower.rc == MB_OK && hw_floor(MB_FLOOR_SECURITY) == 9, "a lower value is a no-op");
    raise_t gold = { MB_FLOOR_GOLDEN, 7, 0 };
    raise_fn(&gold);
    CHECK(hw_floor(MB_FLOOR_GOLDEN) == 7 && hw_floor(MB_FLOOR_SECURITY) == 9, "the two floors are independent");

    sim_reset();
    sim.floor_locked = true;
    install_raw(MB_SLOT_A, "app", MB_VERSION(1, 0, 0), 4, 1, 30000);
    boot();
    app_confirms();
    CHECK(boot() == MB_SLOT_A && hw_floor(MB_FLOOR_SECURITY) == 0 && log_now().min_security == 4,
          "store can't be written: the boot goes on, the log keeps the floor");
    sim.floor_locked = false;

    sim_reset();
    sim_port.floor = NULL;
    install_raw(MB_SLOT_A, "app", MB_VERSION(1, 0, 0), 4, 1, 30000);
    boot();
    app_confirms();
    CHECK(boot() == MB_SLOT_A && log_now().min_security == 4, "a port without a store: log floor as before");

    printf("fault while checking a slot: marked bad, next one boots\n");
    good_a();
    install_raw(MB_SLOT_B, "app", MB_VERSION(2, 0, 0), 1, 3, 30000);
    sim.fault_slot = MB_SLOT_B;
    CHECK(boot() == MB_SLOT_A, "B faulted last time: A boots");
    CHECK(log_now().slot[MB_SLOT_B].state == MB_ST_BAD && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_FAULT, "B bad (fault)");
    CHECK(mb_checking_slot == MB_SLOT_NONE, "nothing being checked between boots");
    install_raw(MB_SLOT_B, "app", MB_VERSION(2, 0, 1), 1, 4, 30000);
    CHECK(boot() == MB_SLOT_B, "a new image in B gets its chance");
    sim_reset();
}

// ---------------------------------------------------------------------------
// fault hardening: a check that "passed" without leaving its proof is refused
// at launch (what a skipped branch in admit() would look like)
// ---------------------------------------------------------------------------

static void put_signed(int slot, const uint8_t* hdr, uint32_t seed, uint32_t size);

typedef struct { mb_slot_info_t info[MB_MAX_SLOTS]; mb_plan_t plan; mb_bcl_t log; mb_config_t cfg; int rc; } glitch_t;
static void glitch_boot(void* ctx) {
    glitch_t* g = ctx;
    g->rc = mb_boot(&sim_port, &g->log, &g->cfg, g->info, &g->plan);
}

static sim_outcome_t decide_and_boot(glitch_t* g, void (*tamper)(glitch_t*)) {
    mb_bcl_load(&g->log, &sim_port);
    mb_config_builtin(&sim_port, &g->cfg);
    mb_decide(&sim_port, &g->log, &g->cfg, g->info, 0, &g->plan);
    if (tamper) tamper(g);
    g->rc = 1;
    return sim_guard(glitch_boot, g);
}

static void no_hash_proof(glitch_t* g) { g->info[g->plan.choice.slot].proof_hash = 0; }
static void no_sig_proof(glitch_t* g) { g->info[g->plan.choice.slot].proof_sig = 0; }
static void unsigned_proof(glitch_t* g) { g->info[g->plan.choice.slot].proof_sig = MB_PROOF_UNSIGNED; }
static void sig_proof_bitflip(glitch_t* g) { g->info[g->plan.choice.slot].proof_sig ^= 0x00010000u; }
static void below_floor(glitch_t* g) { g->info[g->plan.choice.slot].hdr.security_version = 0; }

static void test_fault_hardening(void) {
    printf("fault hardening: launch refuses a check without its proof\n");
    static glitch_t g;
    good_a();
    CHECK(decide_and_boot(&g, NULL) == SIM_BOOTED && sim.booted_slot == MB_SLOT_A, "untouched: boots");
    CHECK(decide_and_boot(&g, no_hash_proof) != SIM_BOOTED && g.rc == MB_E_REFUSED, "hash check skipped: refused (%d)", g.rc);
    good_a();
    CHECK(decide_and_boot(&g, no_sig_proof) != SIM_BOOTED && g.rc == MB_E_REFUSED, "signature check skipped: refused");
    good_a();
    CHECK(decide_and_boot(&g, sig_proof_bitflip) != SIM_BOOTED, "a token with one bit flipped: refused");
    good_a();
    CHECK(decide_and_boot(&g, below_floor) != SIM_BOOTED, "rollback check skipped (image below the floor): refused");
    // required signatures: an "allowed unsigned" token isn't enough
    sim_reset();
    put_signed(MB_SLOT_A, signed_good_hdr, SIGNED_GOOD_SEED, SIGNED_GOOD_SIZE);
    sim_port.require_signature = true;
    CHECK(decide_and_boot(&g, NULL) == SIM_BOOTED, "signed image, signatures required: boots");
    CHECK(decide_and_boot(&g, unsigned_proof) != SIM_BOOTED, "required signatures + 'unsigned' token: refused");
    sim_port.require_signature = false;
}

static void test_requests(void) {
    printf("requests\n");
    good_a();
    install_raw(MB_SLOT_B, "app-b", MB_VERSION(1, 0, 1), 1, 2, 30000);
    boot();
    app_confirms();                                       // B active
    sim.self_slot = MB_SLOT_B;
    mb_client_init(&sim_port);
    mb_client_request(MB_REQ_BOOT_ONCE, MB_SLOT_A);
    CHECK(boot() == MB_SLOT_A && log_now().last_kind == MB_KIND_ONCE, "boot-once A");
    CHECK(boot() == MB_SLOT_B, "then back to active B");
    mb_client_request(MB_REQ_BOOTSEL, 0);
    CHECK(boot() == -SIM_ROM, "BOOTSEL request");
    CHECK(boot() == MB_SLOT_B, "consumed");
    mb_client_request(MB_REQ_MENU, 0);
    sim.console = true;
    sim_input("c\rexit\r", 7);
    CHECK(boot() == MB_SLOT_B && strstr(sim.out, "MimiBoot"), "menu request shows the menu; exit boots");
    sim.button = true;
    sim_input("1", 1);
    CHECK(boot() == MB_SLOT_B && strstr(sim.out, "booting b"), "key -> menu -> 1 (os entry: active B)");
    sim.console = false;
    CHECK(boot() == MB_SLOT_B, "key without a host times out into the normal boot");
    sim.button = false;
    sim.launch_fails = true;
    sim_outcome_t o = sim_power_on();
    sim.launch_fails = false;
    CHECK(o == SIM_ROM && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_LAUNCH, "every launch refused -> ROM, B launch-failed");
}

static void test_flash_mode(void) {
    printf("flash mode: the OS asks, MimiBoot waits for the host\n");
    good_a();
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    CHECK(mb_client_request(MB_REQ_FLASH, 0) == MB_OK, "request flash mode");
    // nobody connects: boots normally, request consumed
    CHECK(boot() == MB_SLOT_A && log_now().request == MB_REQ_NONE, "no host: normal boot");
    // a host connects: straight to the prompt (no menu, no countdown), installs, exits into the trial
    mb_client_request(MB_REQ_FLASH, 0);
    uint32_t size = make_payload(90, 40000);
    mb_image_hdr_t h = make_header("flashed", MB_VERSION(1, 9, 0), 1, size, 0);
    static uint8_t sc[60000];
    size_t n = (size_t)sprintf((char*)sc, "recv b\r");
    sc[n++] = 'H';
    memcpy(sc + n, &h, sizeof(h));
    n += sizeof(h);
    for (uint32_t off = 0; off < size; off += 1000) {
        uint16_t len = (uint16_t)(size - off < 1000 ? size - off : 1000);
        sc[n++] = 'D';
        for (int i = 0; i < 4; i++) sc[n++] = (uint8_t)(off >> (8 * i));
        sc[n++] = (uint8_t)len;
        sc[n++] = (uint8_t)(len >> 8);
        memcpy(sc + n, payload + off, len);
        n += len;
        uint32_t c = mb_crc32(0, payload + off, len);
        for (int i = 0; i < 4; i++) sc[n++] = (uint8_t)(c >> (8 * i));
    }
    sc[n++] = 'E';
    n += (size_t)sprintf((char*)sc + n, "exit\r");
    sim.console = true;
    sim_input(sc, n);
    CHECK(boot() == MB_SLOT_B && sim.watchdog_ms, "flashed B, exit: it boots as a trial");
    CHECK(strstr(sim.out, "MB FLASH READY") && !strstr(sim.out, "any key stops"), "flash-mode banner, no countdown");
    sim.console = false;
}

static void test_log_wear(void) {
    printf("log: 5000 commits\n");
    sim_reset();
    mb_bcl_t b;
    mb_bcl_load(&b, &sim_port);
    CHECK(b.fresh, "fresh log");
    for (uint32_t i = 1; i <= 5000; i++) {
        mb_bcl_rec_t r = b.cur;
        r.min_security = i;
        if (mb_bcl_commit(&b, &r) != MB_OK) { CHECK(0, "commit %u", i); break; }
        if (i % 97 == 0) {
            mb_bcl_load(&b, &sim_port);
            CHECK(b.cur.min_security == i && b.cur.seq == i, "reload at %u: %u seq %u", i, b.cur.min_security, b.cur.seq);
        }
    }
    mb_bcl_load(&b, &sim_port);
    CHECK(b.cur.min_security == 5000, "final state survives");
    CHECK(sim.erases > 320 && sim.erases < 345, "15 records per sector: ~333 swaps (%u)", sim.erases);
    sim.fail_writes = true;
    mb_bcl_rec_t r = b.cur;
    r.min_security = 9999;
    CHECK(mb_bcl_commit(&b, &r) != MB_OK, "write error reported");
    sim.fail_writes = false;
    mb_bcl_load(&b, &sim_port);
    CHECK(b.cur.min_security == 5000, "old state intact");

    printf("log write fails during a trial -> boot the good image instead\n");
    good_a();
    install_raw(MB_SLOT_B, "app", MB_VERSION(1, 1, 0), 1, 2, 30000);
    sim.fail_writes = true;
    CHECK(boot() == MB_SLOT_A, "trial can't be recorded: A");
    sim.fail_writes = false;
    CHECK(boot() == MB_SLOT_B, "flash works again: B gets its trial");
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

static const char* sample_cfg =
    "# MimiBoot config\n"
    "timeout 3\n"
    "default arm\n"
    "entry arm\n"
    "    title My OS (Arm)\n"
    "    slot ab\n"
    "    args console=usb quiet\n"
    "entry hazard3\r\n"
    "    title My OS (RISC-V)\n"
    "    slot c\n"
    "    arch riscv\n"
    "    args init=/bin/sh\n"
    "entry rescue\n"
    "    slot g\n";

static void test_config(void) {
    printf("config: parse, errors, fuzz\n");
    sim_reset();
    mb_config_t c;
    char err[64];
    CHECK(mb_config_parse(&sim_port, sample_cfg, strlen(sample_cfg), &c, err, sizeof(err)) == MB_OK && !c.errors, "sample parses (%s)", err);
    CHECK(c.n == 3 && c.def == 0 && c.timeout_s == 3, "3 entries, default 0, timeout 3");
    CHECK(c.e[1].slot == 3 && c.e[1].arch == MB_ARCH_RISCV && !strcmp(c.e[1].args, "init=/bin/sh"), "hazard3: slot c riscv args");
    CHECK(!strcmp(c.e[2].title, "rescue") && c.e[2].slot == MB_SLOT_GOLDEN, "rescue: title defaults to the name");
    CHECK(mb_config_find(&c, "hazard3") == 1 && mb_config_find(&c, "3") == 2 && mb_config_find(&c, "nope") < 0, "find");

    const char* bad = "timeout banana\nentry\nentry x\n  slot zz\nentry y\n  slot a\n  args aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nbogus 1\ndefault zz\n";
    CHECK(mb_config_parse(&sim_port, bad, strlen(bad), &c, err, sizeof(err)) == MB_OK, "bad lines skipped, y survives");
    CHECK(c.n == 1 && !strcmp(c.e[0].name, "y") && c.e[0].args[0] == 0 && c.errors >= 5, "x dropped (no slot), args too long, %d errors (%s)", c.errors, err);
    CHECK(mb_config_parse(&sim_port, "# nothing\n", 10, &c, err, sizeof(err)) != MB_OK && c.n >= 2 && c.e[0].slot == MB_SLOT_AB, "empty -> built-in");

    // fuzz: random bytes, random truncations of the sample, long lines
    uint32_t x = 12345;
    static char buf[MB_CFG_MAX + 1];
    int crashes = 0;
    for (int it = 0; it < 3000; it++) {
        size_t n;
        if (it % 3 == 0) { n = (size_t)(x % sizeof(buf)); for (size_t i = 0; i < n; i++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; buf[i] = (char)x; } }
        else if (it % 3 == 1) { n = strlen(sample_cfg) * (size_t)(x % 1000) / 1000; memcpy(buf, sample_cfg, n); x = x * 1103515245 + 12345; }
        else { n = sizeof(buf) - 1; memset(buf, 'a' + it % 26, n); buf[n / 2] = '\n'; x = x * 1103515245 + 12345; }
        mb_config_parse(&sim_port, buf, n, &c, err, sizeof(err));
        if (c.n < 1 || c.n > MB_MAX_ENTRIES || c.def < 0 || c.def >= c.n) crashes++;
        for (int i = 0; i < c.n; i++) if (c.e[i].slot != MB_SLOT_AB && c.e[i].slot >= sim_port.layout->n_slots) crashes++;
    }
    CHECK(crashes == 0, "3000 fuzzed configs always yield a sane config (%d bad)", crashes);

    printf("config: storage + power cuts\n");
    sim_reset();
    CHECK(mb_config_load(&sim_port, &c) == MB_OK && !c.from_flash, "no config: built-in");
    CHECK(save_cfg(sample_cfg) == MB_OK, "save");
    CHECK(mb_config_load(&sim_port, &c) == MB_OK && c.from_flash && c.n == 3 && c.seq == 1, "load it back");
    const char* v2 = "default b2\nentry b2\n slot b\n";
    int lost = 0;
    for (uint32_t cut = 1; cut <= 30; cut++) {
        sim_reset();
        save_cfg(sample_cfg);
        sim.ops = 0;
        sim.cut_at = cut;
        jmp_buf here;
        jmp_buf* prev = sim.jmp;
        sim.jmp = &here;
        volatile bool done = false;
        if (!setjmp(here)) { save_cfg(v2); done = true; }
        sim.jmp = prev;
        sim.cut_at = 0;
        mb_config_load(&sim_port, &c);
        bool is_old = c.n == 3, is_new = c.n == 1 && !strcmp(c.e[0].name, "b2");
        if (!(is_old || is_new) || (done && !is_new)) lost++;
    }
    CHECK(lost == 0, "a power cut mid-save leaves the old or the new config, never neither (%d)", lost);
}

static void test_entries(void) {
    printf("entries: default, aux, args, pending updates\n");
    good_a();
    make_payload(21, 30000);
    mb_image_hdr_t aux = make_header("aux-tool", MB_VERSION(0, 1, 0), 0, 30000, 0);
    put_image(3, &aux);                                   // slot c
    save_cfg("default tool\nentry os\n slot ab\n args mode=normal\nentry tool\n slot c\n args verbose=1\n");
    CHECK(boot() == 3 && log_now().slot[3].state == MB_ST_GOOD, "default entry boots aux slot c (GOOD: aux needs no confirm)");
    CHECK(sim.watchdog_ms == 0, "aux is not a trial");
    CHECK(log_now().last_entry == 1, "last_entry = tool");
    uint32_t w0 = writes();
    CHECK(boot() == 3 && boot() == 3 && writes() == w0, "repeat default boots write nothing");
    install_raw(MB_SLOT_B, "update", MB_VERSION(1, 1, 0), 1, 22, 30000);
    CHECK(boot() == 3 && log_now().slot[MB_SLOT_B].state == MB_ST_NEW, "pending A/B update waits while the default is aux");
    mb_client_init(&sim_port);
    sim.self_slot = 3;
    mb_client_init(&sim_port);
    w0 = writes();
    CHECK(mb_client_request_entry("os", "mode=test") == MB_OK && writes() - w0 == 1, "one-shot entry with args: 1 write");
    CHECK(boot() == MB_SLOT_B && sim.watchdog_ms, "the ab entry tries the update (trial)");
    CHECK(log_now().last_kind == MB_KIND_TRIAL && log_now().request == MB_REQ_NONE, "request consumed");
    CHECK(boot() == 3, "then the default again");
    // an entry whose arch doesn't match its image falls back
    save_cfg("default x\nentry x\n slot c\n arch riscv\n");
    CHECK(boot() == MB_SLOT_A && log_now().last_kind == MB_KIND_FALLBACK, "arch mismatch -> fallback to good A");
}

// ---------------------------------------------------------------------------
// handoff
// ---------------------------------------------------------------------------

#define HANDOFF_ADDR (SIM_RAM_BASE + 0x40000)

static mb_handoff_t* ram_handoff(void) { return (mb_handoff_t*)(sim_ram + (HANDOFF_ADDR - SIM_RAM_BASE)); }

static void test_handoff(void) {
    printf("handoff: args, binding, staleness\n");
    sim_reset();
    save_cfg("default os\nentry os\n slot ab\n args console=usb level=3\n");
    make_payload(31, 20000);
    mb_image_hdr_t h = make_header_ex("ho", MB_VERSION(1, 0, 0), 0, 20000, 0, MB_ARCH_ARM, MB_LOAD_CHAIN, 0, HANDOFF_ADDR);
    put_image(MB_SLOT_A, &h);
    CHECK(boot() == MB_SLOT_A, "boots");
    mb_handoff_t* ho = ram_handoff();
    CHECK(ho->magic == MB_HANDOFF_MAGIC && ho->image_id == mb_image_id(&h), "handoff written for this image");
    CHECK(!strcmp(ho->args, "console=usb level=3") && !strcmp(ho->entry_name, "os") && !strcmp(ho->slot_name, "a"), "args/entry/slot");
    CHECK(ho->kind == MB_KIND_TRIAL && ho->loader_version == MIMIBOOT_VERSION_NUM, "kind trial, loader version");
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    mb_client_set_handoff(ho);
    CHECK(mb_client_handoff() && !strcmp(mb_client_args(), "console=usb level=3"), "client takes it");
    CHECK(ho->magic == 0, "and consumes it");
    mb_client_set_handoff(ho);
    CHECK(!mb_client_handoff(), "a second read finds nothing (never stale)");
    CHECK(!strcmp(mb_client_args(), "console=usb level=3"), "flash fallback gives the entry's args");
    // a struct for another image (left over, or forged) is refused
    boot();
    ho->image_id ^= 1;
    ho->crc = mb_crc32(0, ho, offsetof(mb_handoff_t, crc));
    mb_client_set_handoff(ho);
    CHECK(!mb_client_handoff(), "handoff for another image id refused");
    // one-shot args reach the handoff, the next boot is back to the entry's
    mb_client_request_entry("os", "single");
    boot();
    mb_client_set_handoff(ram_handoff());
    CHECK(mb_client_handoff() && !strcmp(mb_client_args(), "single") && ram_handoff()->kind == MB_KIND_TRIAL, "one-shot args delivered");
    boot();
    mb_client_set_handoff(ram_handoff());
    CHECK(!strcmp(mb_client_args(), "console=usb level=3"), "next boot: the entry's args");
    // a handoff address in the bootloader's RAM is never written
    sim_reset();
    make_payload(32, 20000);
    h = make_header_ex("evil", MB_VERSION(1, 0, 0), 0, 20000, 0, MB_ARCH_ARM, MB_LOAD_CHAIN, 0, SIM_LOADER_RAM + 16);
    put_image(MB_SLOT_A, &h);
    memset(sim_ram + (SIM_LOADER_RAM - SIM_RAM_BASE), 0xAA, 256);
    CHECK(boot() == MB_SLOT_A && sim_ram[SIM_LOADER_RAM - SIM_RAM_BASE + 16] == 0xAA, "handoff into loader RAM: skipped");
}

// ---------------------------------------------------------------------------
// signatures (headers signed by tests/gen_signed.py with mbtool's code)
// ---------------------------------------------------------------------------

static void put_signed(int slot, const uint8_t* hdr, uint32_t seed, uint32_t size) {
    make_payload(seed, size);
    mb_image_hdr_t h;
    memcpy(&h, hdr, sizeof(h));
    put_image(slot, &h);
}

static void test_ecdsa_images(void) {
#if MB_FEAT_ECDSA
    printf("ECDSA P-256 images (mbtool-signed, micro-ecc-verified)\n");
    sim_reset();
    put_signed(MB_SLOT_A, signed_p256_hdr, SIGNED_P256_SEED, SIGNED_P256_SIZE);
    mb_slot_info_t info;
    mb_image_read_header(&sim_port, MB_SLOT_A, &info);
    CHECK((info.hdr.flags & MB_IMG_F_ECDSA) && mb_image_check_sig(&sim_port, &info) == MB_OK, "mbtool's P-256 signature verifies");
    sim_port.require_signature = true;
    CHECK(boot() == MB_SLOT_A, "required + P-256 signed: boots");
    app_confirms();
    put_signed(MB_SLOT_B, signed_p256_other_hdr, SIGNED_P256_OTHER_SEED, SIGNED_P256_OTHER_SIZE);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "P-256 key not trusted: refused");
    mb_image_hdr_t h;
    memcpy(&h, signed_p256_hdr, sizeof h);
    h.security_version = 7;                         // a signed field changed (CRC fixed up)
    mb_image_seal(&h);
    make_payload(SIGNED_P256_SEED, SIGNED_P256_SIZE);
    put_image(MB_SLOT_B, &h);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "P-256: field changed after signing refused");
    memcpy(&h, signed_p256_hdr, sizeof h);
    h.flags &= ~MB_IMG_F_ECDSA;                     // claim it's Ed25519: must not pass either way
    mb_image_seal(&h);
    put_image(MB_SLOT_B, &h);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "algorithm flag flipped: refused");
    // no P-256 keys in the build: a P-256 image is unsigned as far as it can tell
    const mb_keyring_p256_t* keep = sim_port.p256_keys;
    sim_port.p256_keys = NULL;
    sim_reset();
    sim_port.p256_keys = NULL;
    put_signed(MB_SLOT_A, signed_p256_hdr, SIGNED_P256_SEED, SIGNED_P256_SIZE);
    sim_port.require_signature = true;
    CHECK(boot() == -SIM_ROM, "no P-256 keys + required signatures: refused");
    sim_port.require_signature = false;
    sim_port.p256_keys = keep;
#endif
}

static void test_signatures(void) {
    printf("signatures (Python-signed, C-verified)\n");
    sim_reset();
    put_signed(MB_SLOT_A, signed_good_hdr, SIGNED_GOOD_SEED, SIGNED_GOOD_SIZE);
    mb_slot_info_t info;
    mb_image_read_header(&sim_port, MB_SLOT_A, &info);
    CHECK(mb_image_check_sig(&sim_port, &info) == MB_OK, "mbtool's signature verifies");
    sim_port.require_signature = true;
    CHECK(boot() == MB_SLOT_A, "required + signed: boots");
    CHECK(log_now().slot[MB_SLOT_A].flags & MB_SF_SIG_OK, "signature cached for this image");
    // unsigned, when required
    install_raw(MB_SLOT_B, "unsigned", MB_VERSION(3, 0, 0), 1, 40, 20000);
    app_confirms();
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "required: unsigned refused");
    // signed by a key we don't trust
    put_signed(MB_SLOT_B, signed_other_key_hdr, SIGNED_OTHER_KEY_SEED, SIGNED_OTHER_KEY_SIZE);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "unknown key refused");
    // a good signature with any signed field changed (CRC fixed up) fails
    mb_image_hdr_t h;
    memcpy(&h, signed_good_hdr, sizeof(h));
    h.security_version = 99;
    mb_image_seal(&h);
    make_payload(SIGNED_GOOD_SEED, SIGNED_GOOD_SIZE);
    put_image(MB_SLOT_B, &h);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "field changed after signing refused");
    // a running image forging the "signature checked" flag for an unsigned image
    install_raw(MB_SLOT_B, "forged", MB_VERSION(3, 0, 0), 1, 42, 20000);
    boot();                                               // B marked bad (unsigned)
    mb_bcl_t lg;
    mb_bcl_load(&lg, &sim_port);
    mb_bcl_rec_t fr = lg.cur;
    fr.slot[MB_SLOT_B].state = MB_ST_GOOD;
    fr.slot[MB_SLOT_B].flags |= MB_SF_SIG_OK;
    fr.active = MB_SLOT_B;
    mb_bcl_commit(&lg, &fr);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "required: a forged cache flag is ignored");
    // payload changed: same signed header, different bytes -> hash catches it
    sim_port.require_signature = false;
    sim_reset();
    put_signed(MB_SLOT_A, signed_good_hdr, SIGNED_GOOD_SEED, SIGNED_GOOD_SIZE);
    sim_flash[sim_port.layout->slot[MB_SLOT_A].offset + MB_IMG_PAYLOAD_OFF + 100] ^= 1;
    CHECK(boot() == -SIM_ROM && log_now().slot[MB_SLOT_A].bad_reason == MB_BAD_HASH, "signed header, payload changed: hash fails");
    // optional mode: unsigned is fine, a bad signature is still refused
    sim_reset();
    install_raw(MB_SLOT_A, "plain", MB_VERSION(1, 0, 0), 0, 41, 20000);
    CHECK(boot() == MB_SLOT_A, "optional: unsigned boots");
    put_signed(MB_SLOT_B, signed_other_key_hdr, SIGNED_OTHER_KEY_SEED, SIGNED_OTHER_KEY_SIZE);
    app_confirms();
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "optional: a bad signature still refused");
}

// ---------------------------------------------------------------------------
// crash-loop guard
// ---------------------------------------------------------------------------

static void test_guard(void) {
    printf("crash-loop guard\n");
    good_a();
    install_raw(MB_SLOT_B, "older-good", MB_VERSION(0, 9, 0), 1, 50, 30000);
    sim.self_slot = MB_SLOT_B;
    mb_client_init(&sim_port);
    boot();                                               // B trial
    app_confirms();
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    mb_client_request(MB_REQ_BOOT_ONCE, MB_SLOT_A);
    boot();
    app_confirms();                                       // A active again, both good
    CHECK(log_now().active == MB_SLOT_A, "A active, B good");
    sim.reset_cause = MB_RESET_WATCHDOG;
    for (int i = 1; i < MB_STRIKES_MAX; i++) CHECK(boot() == MB_SLOT_A && log_now().strikes == i, "watchdog reset %d: still A", i);
    CHECK(boot() == MB_SLOT_B && log_now().last_kind == MB_KIND_FALLBACK, "strike %d: A passed over, B boots", MB_STRIKES_MAX);
    sim.reset_cause = MB_RESET_POWER;
    CHECK(boot() == MB_SLOT_A && log_now().strikes == 0, "a normal reset clears the strikes: A again");
    // with nothing else to boot the suspect still runs
    good_a();
    sim.reset_cause = MB_RESET_WATCHDOG;
    for (int i = 0; i < MB_STRIKES_MAX + 2; i++) boot();
    CHECK(boot() == MB_SLOT_A, "only image: booted despite strikes");
    sim.self_slot = MB_SLOT_A;
    app_confirms();
    CHECK(log_now().strikes == 0, "confirm clears strikes");
    sim.reset_cause = MB_RESET_POWER;
}

// ---------------------------------------------------------------------------
// RAM images
// ---------------------------------------------------------------------------

static void test_ram_images(void) {
    printf("RAM images, architecture switch\n");
    sim_reset();
    install_raw(MB_SLOT_A, "app", MB_VERSION(1, 0, 0), 0, 1, 20000);
    make_payload(60, 50000);
    mb_image_hdr_t rv = make_header_ex("hazard3", MB_VERSION(1, 0, 0), 0, 50000, 0, MB_ARCH_RISCV, MB_LOAD_RAM, SIM_RAM_BASE + 0x1000,
                                       SIM_RAM_BASE + 0x30000);
    put_image(3, &rv);
    save_cfg("default arm\nentry arm\n slot ab\nentry rv\n slot c\n arch riscv\n args init=/bin/sh\n");
    boot();
    app_confirms();
    mb_client_init(&sim_port);
    sim.self_slot = MB_SLOT_A;
    mb_client_request_entry("rv", NULL);
    CHECK(boot() == 3 && sim.booted_ram && sim.booted_arch == MB_ARCH_RISCV, "RISC-V RAM image started through an arch switch");
    CHECK(!memcmp(sim_ram + 0x1000, payload, 50000), "payload copied to its load address");
    mb_handoff_t* ho = (mb_handoff_t*)(sim_ram + 0x30000);
    CHECK(ho->magic == MB_HANDOFF_MAGIC && !strcmp(ho->args, "init=/bin/sh") && ho->arch == MB_ARCH_RISCV, "handoff for the RISC-V image");
    // a RAM image that would land on the bootloader's RAM
    make_payload(61, 50000);
    mb_image_hdr_t evil = make_header_ex("overlap", MB_VERSION(1, 0, 0), 0, 50000, 0, MB_ARCH_ARM, MB_LOAD_RAM, SIM_LOADER_RAM - 1000, 0);
    put_image(4, &evil);
    save_cfg("default x\nentry x\n slot d\n");
    CHECK(boot() == MB_SLOT_A && log_now().slot[4].bad_reason == MB_BAD_LAUNCH, "overlapping RAM image refused, fallback to A");
    // RAM copy corrupted after the flash hash passed? (simulate: flash ok, but stage catches it via RAM hash)
    CHECK(slot_intact(3), "rv slot still intact");
}

static void test_universal(void) {
    printf("universal bootloader: XIP images for both architectures\n");
    sim_reset();
    sim.universal = true;
    install_raw(MB_SLOT_A, "pm-arm", MB_VERSION(16, 1, 0), 1, 1, 30000);
    make_payload(65, 40000);
    mb_image_hdr_t rv = make_header_ex("pm-riscv", MB_VERSION(16, 1, 0), 0, 40000, 0, MB_ARCH_RISCV, MB_LOAD_CHAIN, 0, 0);
    put_image(3, &rv);
    save_cfg("default arm\nentry arm\n slot ab\nentry rv\n slot c\n args hart=0\n");
    boot();
    app_confirms();                                       // A good, chip on Arm
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    mb_client_request_entry("rv", "hart=1");
    CHECK(sim_power_on() == SIM_REBOOT && sim.arch == MB_ARCH_RISCV && sim.arch_switches == 1, "Arm half hands over: switch to RISC-V");
    CHECK(log_now().request == MB_REQ_ENTRY_ONCE && !strcmp(log_now().args, "hart=1"), "request (with args) left for the other half");
    CHECK(boot() == 3 && sim.booted_arch == MB_ARCH_RISCV, "RISC-V half boots slot c on Hazard3");
    CHECK(log_now().last_entry == 1 && log_now().request == MB_REQ_NONE, "it consumed the request");
    CHECK(log_now().strikes == 0, "the handover reboot (reported as a watchdog reset) is no strike");
    // a reset on RISC-V: the default (Arm) entry -> switch back
    sim.reset_cause = MB_RESET_POWER;
    CHECK(sim_power_on() == SIM_REBOOT && sim.arch == MB_ARCH_ARM && sim.arch_switches == 2, "default is Arm: back over");
    CHECK(boot() == MB_SLOT_A && sim.booted_arch == MB_ARCH_ARM && log_now().strikes == 0, "Arm half boots A, no strikes");
    // real crashes still count once each, handovers in between or not
    sim.reset_cause = MB_RESET_WATCHDOG;
    CHECK(boot() == MB_SLOT_A && log_now().strikes == 1, "a real watchdog reset: one strike");
    sim.reset_cause = MB_RESET_POWER;
    // a trial A/B image for the other cores is counted once, on the side that boots it
    sim_reset();
    sim.universal = true;
    make_payload(66, 30000);
    mb_image_hdr_t rva = make_header_ex("rv-ab", MB_VERSION(1, 0, 0), 0, 30000, 0, MB_ARCH_RISCV, MB_LOAD_CHAIN, 0, 0);
    put_image(MB_SLOT_A, &rva);
    CHECK(sim_power_on() == SIM_REBOOT && log_now().slot[MB_SLOT_A].state == MB_ST_NEW, "switch first, no attempt spent yet");
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_A].tries_left == MB_DEFAULT_TRIES - 1, "one attempt spent, by the RISC-V half");
    // not universal: the same image can't start (and nobody loops)
    sim_reset();
    put_image(MB_SLOT_A, &rva);
    CHECK(boot() == -SIM_ROM && log_now().slot[MB_SLOT_A].bad_reason == MB_BAD_TARGET && !sim.arch_switches, "no other half: can't start here");
}

// ---------------------------------------------------------------------------
// console, recv, ramboot, cfg recv
// ---------------------------------------------------------------------------

static void test_console(void) {
    printf("console commands\n");
    good_a();
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 0, 0), 0, 7, 20000);
    sim.console = true;
    sim.button = true;
    const char* script = "c\rhelp\rls\rentries\rinfo a\rverify\rlog\rlayout\rmd 0x20000 32\rsha 0x20000 256\rkeys\rbogus\rreject g\rls\r";
    sim_input(script, strlen(script));
    sim_outcome_t o = sim_power_on();
    CHECK(o == SIM_CONSOLE_IDLE, "script ran to the end (%d)", o);
    CHECK(strstr(sim.out, "recv <slot>") && strstr(sim.out, "ramboot"), "help");
    CHECK(strstr(sim.out, "GOOD") && strstr(sim.out, "*active"), "ls");
    CHECK(strstr(sim.out, "built-in") && strstr(sim.out, "recovery"), "entries (built-in)");
    CHECK(strstr(sim.out, "sha256    "), "info");
    CHECK(strstr(sim.out, "a: sha256 OK") && strstr(sim.out, "g: sha256 OK") && strstr(sim.out, "b: no image"), "verify all");
    CHECK(strstr(sim.out, "security floor 1"), "log");
    CHECK(strstr(sim.out, "g      0x0e0000") && strstr(sim.out, "cfg0"), "layout");
    CHECK(strstr(sim.out, "020000  4d 49 4d 47"), "md shows MIMG");
    CHECK(strstr(sim.out, "flash 0x020000 +256"), "sha");
    CHECK(strstr(sim.out, "d75a980182b1"), "keys lists the trusted key");
    CHECK(strstr(sim.out, "unknown command 'bogus'"), "unknown");
    CHECK(strstr(sim.out, "g -> BAD"), "reject golden");
    CHECK(strstr(sim.out, "\033[33msecurity: unsigned images ALLOWED, hash every boot, rollback floors in the bootloader's flash"),
          "menu's security line: optional signatures shown as a warning");
    sim.button = false;
    sim.console = false;
    CHECK(log_now().slot[MB_SLOT_GOLDEN].state == MB_ST_BAD, "rejection stored");
    if (fails) printf("---- console output ----\n%s\n------------------------\n", sim.out);

    printf("menu: edit args with 'e'\n");
    good_a();
    save_cfg("default os\nentry os\n slot ab\n args a=1\n");
    sim.console = true;
    sim.button = true;
    // e, wipe the line (Ctrl-U), type new args, enter
    sim_input("e\x15" "debug=2\r", 10);
    CHECK(boot() == MB_SLOT_A && strstr(sim.out, "args: debug=2"), "boots with edited args");
    sim.button = false;
    sim.console = false;
}

static size_t put_frame(uint8_t* out, uint32_t off, const uint8_t* data, uint16_t len) {
    size_t n = 0;
    out[n++] = 'D';
    for (int i = 0; i < 4; i++) out[n++] = (uint8_t)(off >> (8 * i));
    out[n++] = (uint8_t)len;
    out[n++] = (uint8_t)(len >> 8);
    memcpy(out + n, data, len);
    n += len;
    uint32_t c = mb_crc32(0, data, len);
    for (int i = 0; i < 4; i++) out[n++] = (uint8_t)(c >> (8 * i));
    return n;
}

static size_t put_upload(uint8_t* script, size_t n, const mb_image_hdr_t* h, uint16_t frame, bool corrupt_one) {
    script[n++] = 'H';
    memcpy(script + n, h, sizeof(*h));
    n += sizeof(*h);
    for (uint32_t off = 0; off < h->payload_size; off += frame) {
        uint16_t len = (uint16_t)(h->payload_size - off < frame ? h->payload_size - off : frame);
        if (corrupt_one && off == 5 * frame) {
            size_t at = n;
            n += put_frame(script + n, off, payload + off, len);
            script[at + 20] ^= 0xFF;
        }
        n += put_frame(script + n, off, payload + off, len);
    }
    script[n++] = 'E';
    return n;
}

static uint8_t script[400000];

static void test_recv(void) {
    printf("recv: upload an image over the console\n");
    good_a();
    uint32_t size = make_payload(42, 100000);
    mb_image_hdr_t h = make_header("uploaded", MB_VERSION(1, 2, 0), 1, size, 0);
    size_t n = (size_t)sprintf((char*)script, "c\rrecv b\r");
    n = put_upload(script, n, &h, 1000, true);
    n += (size_t)sprintf((char*)script + n, "ls\r");
    sim.console = true;
    sim.button = true;
    sim_input(script, n);
    sim_power_on();
    sim.button = false;
    sim.console = false;
    CHECK(strstr(sim.out, "MB READY 1024 b"), "READY announces the frame size");
    CHECK(strstr(sim.out, "MB ERR crc 5000"), "corrupt frame rejected");
    CHECK(strstr(sim.out, "MB DONE") && slot_intact(MB_SLOT_B), "upload done, B intact");
    CHECK(boot() == MB_SLOT_B && sim.watchdog_ms, "uploaded image boots as a trial");

    printf("recv: aborted upload leaves the slot empty\n");
    good_a();
    n = (size_t)sprintf((char*)script, "c\rrecv b\r");
    script[n++] = 'H';
    memcpy(script + n, &h, sizeof(h));
    n += sizeof(h);
    n += put_frame(script + n, 0, payload, 1000);
    script[n++] = 'X';
    sim.console = true;
    sim.button = true;
    sim_input(script, n);
    sim_power_on();
    sim.button = false;
    sim.console = false;
    mb_slot_info_t info;
    CHECK(strstr(sim.out, "aborted") && mb_image_read_header(&sim_port, MB_SLOT_B, &info) != MB_OK, "aborted, B empty");
    CHECK(boot() == MB_SLOT_A, "still A");

    printf("recv: unsigned upload refused up front when signatures are required\n");
    good_a();
    sim_port.require_signature = true;
    n = (size_t)sprintf((char*)script, "c\rrecv b\r");
    n = put_upload(script, n, &h, 1000, false);
    sim.console = true;
    sim.button = true;
    sim_input(script, n);
    sim_power_on();
    sim.button = false;
    sim.console = false;
    sim_port.require_signature = false;
    CHECK(strstr(sim.out, "MB ERR refused (-8)"), "refused before erasing anything");

    printf("ramboot: run an image from RAM, flash untouched\n");
    good_a();
    size = make_payload(43, 30000);
    h = make_header_ex("ramtool", MB_VERSION(0, 1, 0), 0, size, 0, MB_ARCH_ARM, MB_LOAD_RAM, SIM_RAM_BASE + 0x2000, SIM_RAM_BASE + 0x20000);
    n = (size_t)sprintf((char*)script, "c\rramboot mode=lab x=1\r");
    n = put_upload(script, n, &h, 1024, false);
    sim.console = true;
    sim.button = true;
    sim_input(script, n);
    uint32_t w0 = writes();
    sim_outcome_t o = sim_power_on();
    sim.button = false;
    sim.console = false;
    CHECK(o == SIM_BOOTED && sim.booted_ram && sim.booted_slot == -1, "started from RAM");
    CHECK(writes() == w0, "no flash writes");
    mb_handoff_t* ho = (mb_handoff_t*)(sim_ram + 0x20000);
    CHECK(ho->magic == MB_HANDOFF_MAGIC && !strcmp(ho->args, "mode=lab x=1") && !strcmp(ho->slot_name, "ram"), "args reach it");

    printf("cfg recv\n");
    good_a();
    const char* text = "default os\nentry os\n slot ab\n args from=host\n";
    size_t tl = strlen(text);
    n = (size_t)sprintf((char*)script, "c\rcfg recv\r");
    script[n++] = (uint8_t)tl;
    script[n++] = (uint8_t)(tl >> 8);
    memcpy(script + n, text, tl);
    n += tl;
    uint32_t crc = mb_crc32(0, text, tl);
    for (int i = 0; i < 4; i++) script[n++] = (uint8_t)(crc >> (8 * i));
    n += (size_t)sprintf((char*)script + n, "cfg show\r");
    sim.console = true;
    sim.button = true;
    sim_input(script, n);
    sim_power_on();
    sim.button = false;
    sim.console = false;
    mb_config_t c;
    mb_config_load(&sim_port, &c);
    CHECK(strstr(sim.out, "MB DONE") && c.from_flash && !strcmp(c.e[0].args, "from=host"), "config uploaded and stored");
    CHECK(strstr(sim.out, "args from=host"), "cfg show prints it");
}

// ---------------------------------------------------------------------------
// OTA through the client library (what an OS's update command does)
// ---------------------------------------------------------------------------

typedef struct { const uint8_t* in; size_t len, pos; char out[4096]; size_t olen; } stream_t;

static int s_getc(void* io, uint32_t ms) {
    (void)ms;
    stream_t* s = io;
    return s->pos < s->len ? s->in[s->pos++] : -1;
}

static void s_puts(void* io, const char* str) {
    stream_t* s = io;
    size_t n = strlen(str);
    if (s->olen + n < sizeof(s->out)) { memcpy(s->out + s->olen, str, n); s->olen += n; s->out[s->olen] = 0; }
}

static stream_t ota_stream;
static void ota_fn(void* ctx) {
    (void)ctx;
    mb_client_init(&sim_port);
    mb_client_recv(mb_client_other_slot(), &ota_stream, s_getc, s_puts, 256);
}

static void test_ota(void) {
    printf("OTA: a running app receives its update\n");
    good_a();
    uint32_t size = make_payload(70, 80000);
    mb_image_hdr_t h = make_header("ota", MB_VERSION(1, 5, 0), 2, size, 0);
    size_t n = put_upload(script, 0, &h, 256, true);
    memset(&ota_stream, 0, sizeof(ota_stream));
    ota_stream.in = script;
    ota_stream.len = n;
    sim.self_slot = MB_SLOT_A;
    sim_guard(ota_fn, NULL);
    CHECK(strstr(ota_stream.out, "MB READY 256 b") && strstr(ota_stream.out, "MB DONE"), "received into B (%.60s)", ota_stream.out);
    CHECK(boot() == MB_SLOT_B && sim.watchdog_ms, "reboot: B on trial");
    app_confirms();
    CHECK(log_now().active == MB_SLOT_B && log_now().min_security == 2, "confirmed: B active");
    // the client refuses to overwrite the running slot
    mb_client_init(&sim_port);
    sim.self_slot = MB_SLOT_B;
    mb_client_init(&sim_port);
    CHECK(mb_client_install_begin(MB_SLOT_B, &h) == MB_E_REFUSED && mb_client_install_begin(MB_SLOT_GOLDEN, &h) == MB_E_REFUSED,
          "running slot and golden are off limits");
}

static void test_revocation(void) {
    printf("key revocation (REVOKE_KEYS)\n");
    static const mb_keyring_t revoke_ring = { 1, (const uint8_t (*)[32])s1_public };   // gen_signed's OTHER key
    sim_reset();
    sim_port.require_signature = true;
    put_signed(MB_SLOT_A, signed_good_hdr, SIGNED_GOOD_SEED, SIGNED_GOOD_SIZE);          // Ed25519 image key
    put_signed(MB_SLOT_GOLDEN, signed_p256_hdr, SIGNED_P256_SEED, SIGNED_P256_SIZE);     // P-256 image key
    CHECK(mb_key_revoke(&sim_port, REVOKE_ED_ID, revoke_ed_sig) == MB_E_UNSUPP, "a build without REVOKE_KEYS takes none");
    sim_port.revoke_keys = &revoke_ring;
    CHECK(boot() == MB_SLOT_A, "before: the Ed25519-signed image boots");
    CHECK(mb_key_revoke(&sim_port, REVOKE_P256_ID, revoke_by_image_key_sig) == MB_E_SIGNATURE,
          "a statement signed by an image key is refused");
    uint8_t bad[64];
    memcpy(bad, revoke_ed_sig, 64);
    bad[5] ^= 1;
    CHECK(mb_key_revoke(&sim_port, REVOKE_ED_ID, bad) == MB_E_SIGNATURE, "a damaged statement is refused");
    CHECK(mb_key_revoke(&sim_port, REVOKE_P256_ID, revoke_ed_sig) == MB_E_SIGNATURE, "a statement for another key is refused");
    CHECK(mb_key_revoke(&sim_port, 0x12345678u, revoke_ed_sig) == MB_E_BADARG, "a key this board doesn't have: refused");
    CHECK(mb_key_revoke(&sim_port, REVOKE_ED_ID, revoke_ed_sig) == MB_OK && mb_key_revoked(&sim_port, REVOKE_ED_ID),
          "the Ed25519 key revoked");
    CHECK(mb_key_revoke(&sim_port, REVOKE_ED_ID, revoke_ed_sig) == MB_OK &&
          mb_store_count(&sim_port, MB_STORE_KEY_REVOKED, REVOKE_ED_ID) == 1, "again: nothing more written");
    CHECK(boot() == MB_SLOT_GOLDEN && log_now().slot[MB_SLOT_A].bad_reason == MB_BAD_SIGNATURE,
          "after: the image signed with it is refused, the P-256 one boots");
    CHECK(mb_key_revoke(&sim_port, REVOKE_P256_ID, revoke_p256_sig) == MB_E_REFUSED,
          "the last trusted image key can't be revoked");
    sim.console = true;
    sim.button = true;
    sim_input("c\rkeys\r", 7);
    sim_power_on();
    sim.console = false;
    sim.button = false;
    CHECK(strstr(sim.out, "REVOKED") != NULL, "'keys' shows it");
    sim_port.revoke_keys = NULL;
    wipe_log();
    CHECK(boot() == MB_SLOT_A, "a build without REVOKE_KEYS ignores the entry (an app can't plant one)");
    sim_port.require_signature = false;
}

static void test_client_install(void) {
    printf("client install: odd chunks on write-once flash, a resend, order, abort, vacate\n");
    good_a();
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    uint32_t size = make_payload(71, 30001);
    mb_image_hdr_t h = make_header("chunks", MB_VERSION(1, 6, 0), 2, size, 0);
    sim.write_once = true;                                  // a page programmed twice fails, as on ECC flash
    CHECK(mb_client_install_begin(MB_SLOT_B, &h) == MB_OK, "begin");
    uint32_t off = 0, k = 0;
    int rc = MB_OK;
    while (off < size && rc == MB_OK) {
        uint32_t n = 37 + (k++ * 101) % 700;                // never page sized, never page aligned
        if (n > size - off) n = size - off;
        rc = mb_client_install_write(off, payload + off, n);
        if (rc == MB_OK && k == 5) rc = mb_client_install_write(off, payload + off, n);   // a retry of the same chunk
        off += n;
    }
    CHECK(rc == MB_OK, "odd-sized chunks and a resend: every page programmed once (%d)", rc);
    CHECK(mb_client_install_write(off + 512, payload, 16) != MB_OK, "a chunk past the end is refused");
    CHECK(mb_client_install_end() == MB_OK && slot_intact(MB_SLOT_B), "the image is complete and intact");
    sim.write_once = false;

    CHECK(mb_client_install_begin(MB_SLOT_B, &h) == MB_OK, "again");
    CHECK(mb_client_install_write(0, payload, 1000) == MB_OK && mb_client_install_write(2000, payload + 2000, 100) == MB_E_BADARG,
          "out of order: refused");
    CHECK(mb_client_install_end() == MB_E_CORRUPT, "end before the whole payload arrived: refused");
    mb_slot_info_t in;
    CHECK(mb_image_read_header(&sim_port, MB_SLOT_B, &in) != MB_OK, "... and b stays empty");
    CHECK(mb_client_install_begin(MB_SLOT_B, &h) == MB_OK && mb_client_install_write(0, payload, 4096) == MB_OK &&
          mb_client_install_abort() == MB_OK && mb_client_install_write(4096, payload + 4096, 10) == MB_E_BADARG,
          "abort: closed");
    CHECK(mb_image_read_header(&sim_port, MB_SLOT_B, &in) != MB_OK, "an aborted install leaves b empty");

    install_raw(MB_SLOT_B, "old", MB_VERSION(1, 0, 0), 2, 72, 20000);
    boot();                                                 // the log learns about it
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    CHECK(mb_client_vacate(MB_SLOT_B) == MB_OK && mb_image_read_header(&sim_port, MB_SLOT_B, &in) != MB_OK &&
          log_now().slot[MB_SLOT_B].state == MB_ST_EMPTY, "vacate: b has no header and no log record");
    CHECK(mb_client_vacate(MB_SLOT_A) == MB_E_BADARG && mb_client_vacate(MB_SLOT_GOLDEN) == MB_E_REFUSED,
          "not the running slot, not golden");
}

// ---------------------------------------------------------------------------
// measured boot: the boot record (mimiboot/mb_record.h)
// ---------------------------------------------------------------------------
#if MB_FEAT_BOOT_RECORD
static mb_boot_record_t* sim_record(uint32_t addr) { return (mb_boot_record_t*)(sim_ram + (addr - SIM_RAM_BASE)); }

static void test_boot_record(void) {
    printf("boot record: a signed image that asks for one gets what was checked and a measurement\n");
    good_a();
    put_signed(MB_SLOT_B, signed_record_hdr, SIGNED_RECORD_SEED, SIGNED_RECORD_SIZE);
    mb_boot_record_t* r = sim_record(SIGNED_RECORD_ADDR);
    memset(r, 0, sizeof(*r));
    sim_port.require_signature = true;
    CHECK(boot() == MB_SLOT_B, "b (new) boots as a trial");
    sim_port.require_signature = false;
    CHECK(r->magic == MB_RECORD_MAGIC && r->version == MB_RECORD_VERSION && r->size == sizeof(*r) &&
          r->crc == mb_crc32(0, r, offsetof(mb_boot_record_t, crc)), "written, intact");
    CHECK((r->flags & (MB_REC_SIGNED | MB_REC_HASHED | MB_REC_TRIAL | MB_REC_LOADER)) ==
          (MB_REC_SIGNED | MB_REC_HASHED | MB_REC_TRIAL | MB_REC_LOADER) && !(r->flags & MB_REC_RAM),
          "signed, hashed, trial, loader measured (flags %lx)", (unsigned long)r->flags);
    const mb_image_hdr_t* h = (const mb_image_hdr_t*)signed_record_hdr;
    CHECK(r->key_id == h->key_id && r->key_id != 0 && r->image_version == h->version && r->security_version == 2,
          "the key, the version, the security version");
    CHECK(!memcmp(r->image_sha256, h->sha256, 32), "the payload hash");
    uint8_t lh[32], m[32];
    mb_sha256_t s;
    mb_sha256_init(&s);
    mb_sha256_update(&s, "the simulated bootloader", 24);
    mb_sha256_final(&s, lh);
    mb_sha256_init(&s);
    mb_sha256_update(&s, "MimiBoot measure v1", 20);       // with its NUL
    mb_sha256_update(&s, lh, 32);
    mb_sha256_update(&s, signed_record_hdr, MB_IMG_SIGNED_BYTES);
    mb_sha256_final(&s, m);
    CHECK(!memcmp(r->loader_sha256, lh, 32) && !memcmp(r->measurement, m, 32), "the loader hash and the measurement recompute");

    printf("boot record: unsigned, into loader RAM, or not asked for\n");
    good_a();
    uint32_t size = make_payload(301, 20000);
    mb_image_hdr_t u = make_header("plain", MB_VERSION(1, 1, 0), 1, size, 0);
    u.record_addr = SIM_RAM_BASE + 0x31000;
    mb_image_seal(&u);
    put_image(MB_SLOT_B, &u);
    r = sim_record(u.record_addr);
    memset(r, 0, sizeof(*r));
    CHECK(boot() == MB_SLOT_B && r->magic == MB_RECORD_MAGIC && !(r->flags & MB_REC_SIGNED) && r->key_id == 0 &&
          (r->flags & MB_REC_HASHED), "unsigned: the record says so (no key)");
    good_a();
    size = make_payload(302, 20000);                        // a new image each time: the log remembers trials
    u = make_header("plain", MB_VERSION(1, 1, 0), 1, size, 0);
    u.record_addr = SIM_LOADER_RAM + 64;
    mb_image_seal(&u);
    put_image(MB_SLOT_B, &u);
    memset(sim_ram + (SIM_LOADER_RAM - SIM_RAM_BASE), 0xAA, 256);
    CHECK(boot() == MB_SLOT_B && sim_ram[SIM_LOADER_RAM - SIM_RAM_BASE + 64] == 0xAA, "into loader RAM: not written");
    good_a();
    size = make_payload(303, 20000);
    u = make_header("plain", MB_VERSION(1, 1, 0), 1, size, 0);
    put_image(MB_SLOT_B, &u);
    r = sim_record(SIM_RAM_BASE + 0x31000);
    memset(r, 0, sizeof(*r));
    CHECK(boot() == MB_SLOT_B && r->magic == 0, "not asked for: nothing written");
}
#else
static void test_boot_record(void) {}
#endif

#if MB_FEAT_ENC
// ---------------------------------------------------------------------------
// encrypted images (the envelope and AES are checked against imgtool in
// test_crypto.c; here: the upload paths around them)
// ---------------------------------------------------------------------------

static uint8_t dev_priv[32], dev_pub[32];

// What `mbtool pack --encrypt` does: a key envelope (TLV 0x33) for dev_pub
static size_t make_envelope(uint8_t* env, const uint8_t* pub, const uint8_t* key, size_t klen, uint8_t seed) {
    static const uint8_t base[32] = { 9 }, zero[16];
    uint8_t eph[32], shared[32], derived[64];
    for (int i = 0; i < 32; i++) eph[i] = (uint8_t)(seed * 31 + i * 7);
    env[0] = MB_ENC_TLV_X25519;
    env[1] = 0;
    env[2] = (uint8_t)(64 + klen);
    env[3] = 0;
    mb_x25519(env + 4, eph, base);
    mb_x25519(shared, eph, pub);
    mb_hkdf_sha256(shared, 32, "MCUBoot_ECIES_v1", 16, derived, klen + 32);
    mb_aes_t a;
    mb_aes_init(&a, derived, klen);
    memcpy(env + 68, key, klen);
    mb_aes_ctr(&a, zero, 0, env + 68, klen);
    mb_hmac_sha256(derived + klen, 32, env + 68, klen, env + 36);
    return 4 + 64 + klen;
}

static size_t put_key(uint8_t* out, const uint8_t* env, size_t len) {
    size_t n = 0;
    out[n++] = 'K';
    out[n++] = (uint8_t)len;
    out[n++] = (uint8_t)(len >> 8);
    memcpy(out + n, env, len);
    n += len;
    uint32_t c = mb_crc32(0, env, len);
    for (int i = 0; i < 4; i++) out[n++] = (uint8_t)(c >> (8 * i));
    return n;
}

static uint8_t cipher[0x60000];

// The console upload of an encrypted image: header, envelope, ciphertext frames
static size_t put_enc_upload(uint8_t* s, size_t n, const mb_image_hdr_t* h, const uint8_t* env, size_t envlen,
                             const uint8_t* key, size_t klen, uint16_t frame) {
    static const uint8_t zero[16];
    mb_aes_t a;
    mb_aes_init(&a, key, klen);
    memcpy(cipher, payload, h->payload_size);
    mb_aes_ctr(&a, zero, 0, cipher, h->payload_size);
    s[n++] = 'H';
    memcpy(s + n, h, sizeof(*h));
    n += sizeof(*h);
    n += put_key(s + n, env, envlen);
    for (uint32_t off = 0; off < h->payload_size; off += frame) {
        uint16_t len = (uint16_t)(h->payload_size - off < frame ? h->payload_size - off : frame);
        n += put_frame(s + n, off, cipher + off, len);
    }
    s[n++] = 'E';
    return n;
}

static void console_run(size_t n) {
    sim.console = true;
    sim.button = true;
    sim_input(script, n);
    sim_power_on();
    sim.button = false;
    sim.console = false;
}

static const uint8_t base[32] = { 9 };

// the simulated board's decryption key (tests/gen_smp.py derives the same one)
static void dev_key_init(void) {
    mb_sha256_t s;
    mb_sha256_init(&s);
    mb_sha256_update(&s, "MimiBoot test encryption key", 28);
    mb_sha256_final(&s, dev_priv);
    mb_x25519(dev_pub, dev_priv, base);
}

static void test_encrypted(void) {
    dev_key_init();
    uint8_t key[32], env[MB_ENC_ENV_MAX];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA5 ^ (i * 13));

    for (size_t klen = 16; klen <= 32; klen += 16) {
        printf("encrypted recv (AES-%u): decrypted on the way in, the slot holds plaintext\n", (unsigned)(klen * 8));
        good_a();
        sim_port.enc_key = dev_priv;
        uint32_t size = make_payload(80 + (uint32_t)klen, 50001);
        mb_image_hdr_t h = make_header("secret", MB_VERSION(2, 0, 0), 2, size, MB_IMG_F_ENCRYPTED);
        size_t el = make_envelope(env, dev_pub, key, klen, 1);
        size_t n = (size_t)sprintf((char*)script, "c\rrecv b\r");
        n = put_enc_upload(script, n, &h, env, el, key, klen, 1000);
        console_run(n);
        CHECK(strstr(sim.out, "MB KEY") && strstr(sim.out, "MB DONE") && slot_intact(MB_SLOT_B), "installed, b intact (plaintext)");
        uint32_t off = sim_port.layout->slot[MB_SLOT_B].offset + MB_IMG_PAYLOAD_OFF;
        CHECK(!memcmp(sim_flash + off, payload, size) && sim_flash[off + size] == 0xFF, "flash holds the plaintext, nothing past it");
        CHECK(boot() == MB_SLOT_B, "and it boots");
    }

    printf("encrypted recv: a bad envelope is refused before b is touched\n");
    struct { const char* what; uint8_t flip_at; bool other_device; } bad[] = {
        { "a flipped ephemeral key byte", 10, false }, { "a flipped tag byte", 40, false },
        { "a flipped wrapped-key byte", 70, false }, { "made for another device", 0, true },
    };
    for (unsigned i = 0; i < 4; i++) {
        good_a();
        install_raw(MB_SLOT_B, "keep", MB_VERSION(1, 0, 0), 1, 90, 20000);
        sim_port.enc_key = dev_priv;
        uint32_t size = make_payload(91, 9000);
        mb_image_hdr_t h = make_header("secret", MB_VERSION(2, 0, 0), 2, size, MB_IMG_F_ENCRYPTED);
        uint8_t other_pub[32], other_priv[32];
        memset(other_priv, 0x42, 32);
        mb_x25519(other_pub, other_priv, base);
        size_t el = make_envelope(env, bad[i].other_device ? other_pub : dev_pub, key, 16, 2);
        if (!bad[i].other_device) env[bad[i].flip_at] ^= 0x01;
        size_t n = (size_t)sprintf((char*)script, "c\rrecv b\r");
        n = put_enc_upload(script, n, &h, env, el, key, 16, 1000);
        uint32_t w0 = writes();
        console_run(n);
        CHECK(strstr(sim.out, "MB ERR") && !strstr(sim.out, "MB DONE"), "%s: refused", bad[i].what);
        mb_slot_info_t in;
        CHECK(writes() == w0 || (mb_image_read_header(&sim_port, MB_SLOT_B, &in) == MB_OK && !strcmp(in.hdr.name, "keep")),
              "%s: b still holds its image", bad[i].what);
        CHECK(slot_intact(MB_SLOT_B), "%s: ... intact", bad[i].what);
    }

    printf("encrypted recv: tampered ciphertext fails the hash, b left empty\n");
    good_a();
    sim_port.enc_key = dev_priv;
    uint32_t size = make_payload(92, 9000);
    mb_image_hdr_t h = make_header("secret", MB_VERSION(2, 0, 0), 2, size, MB_IMG_F_ENCRYPTED);
    size_t el = make_envelope(env, dev_pub, key, 16, 3);
    payload[4000] ^= 0x10;                      // encrypting a different plaintext = ciphertext with one bit off
    size_t n = (size_t)sprintf((char*)script, "c\rrecv b\r");
    n = put_enc_upload(script, n, &h, env, el, key, 16, 1000);
    console_run(n);
    mb_slot_info_t in;
    CHECK(strstr(sim.out, "MB ERR hash") && mb_image_read_header(&sim_port, MB_SLOT_B, &in) != MB_OK, "refused, b empty");

    printf("encrypted recv: a build without a key refuses, b untouched\n");
    good_a();
    install_raw(MB_SLOT_B, "keep", MB_VERSION(1, 0, 0), 1, 93, 20000);
    size = make_payload(94, 9000);
    h = make_header("secret", MB_VERSION(2, 0, 0), 2, size, MB_IMG_F_ENCRYPTED);
    n = (size_t)sprintf((char*)script, "c\rrecv b\r");
    n = put_enc_upload(script, n, &h, env, el, key, 16, 1000);
    console_run(n);
    CHECK(strstr(sim.out, "no decryption key") && slot_intact(MB_SLOT_B), "refused");

    printf("encrypted ramboot: decrypted into RAM and started\n");
    good_a();
    sim_port.enc_key = dev_priv;
    size = make_payload(95, 30000);
    h = make_header_ex("ramsecret", MB_VERSION(0, 1, 0), 0, size, MB_IMG_F_ENCRYPTED, MB_ARCH_ARM, MB_LOAD_RAM,
                       SIM_RAM_BASE + 0x2000, 0);
    el = make_envelope(env, dev_pub, key, 32, 4);
    n = (size_t)sprintf((char*)script, "c\rramboot\r");
    n = put_enc_upload(script, n, &h, env, el, key, 32, 1024);
    sim.console = true;
    sim.button = true;
    sim_input(script, n);
    sim_outcome_t o = sim_power_on();
    sim.button = false;
    sim.console = false;
    CHECK(o == SIM_BOOTED && sim.booted_ram && !memcmp(sim_ram + 0x2000, payload, size), "plaintext in RAM, started");

    printf("encrypted images and the client library: refused (the key stays in the bootloader)\n");
    good_a();
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    h = make_header("secret", MB_VERSION(2, 0, 0), 2, 9000, MB_IMG_F_ENCRYPTED);
    CHECK(mb_client_install_begin(MB_SLOT_B, &h) == MB_E_UNSUPP, "install_begin refuses");
    sim_port.enc_key = NULL;
}
#else
static void test_encrypted(void) {}
#endif

// ---------------------------------------------------------------------------
// power cuts
// ---------------------------------------------------------------------------

static void scenario(void* ctx) {
    (void)ctx;
    static uint8_t buf[2048];
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    uint32_t size = make_payload(77, 70000);
    mb_image_hdr_t h = make_header("app", MB_VERSION(1, 1, 0), 2, size, 0);
    mb_client_install_begin(MB_SLOT_B, &h);
    for (uint32_t off = 0; off < size; off += sizeof(buf)) {
        uint32_t n = size - off < sizeof(buf) ? size - off : (uint32_t)sizeof(buf);
        memcpy(buf, payload + off, n);
        mb_client_install_write(off, buf, n);
    }
    mb_client_install_end();
    mb_main(&sim_port);
}

static void scenario2(void* ctx) {
    (void)ctx;
    sim.self_slot = MB_SLOT_B;
    mb_client_init(&sim_port);
    mb_client_confirm();
    uint32_t size = make_payload(78, 65000);
    mb_image_hdr_t h = make_header("app", MB_VERSION(1, 2, 0), 2, size, 0);
    mb_client_install_begin(MB_SLOT_A, &h);
    mb_client_install_write(0, payload, size);
    mb_client_install_end();
    mb_main(&sim_port);
}

// OTA over the stream protocol, then the reboot
static void scenario3(void* ctx) {
    (void)ctx;
    ota_stream.pos = 0;
    ota_stream.olen = 0;
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    mb_client_recv(MB_SLOT_B, &ota_stream, s_getc, s_puts, 256);
    mb_main(&sim_port);
}

static uint8_t snapshot[SIM_FLASH_SIZE], snap2[SIM_FLASH_SIZE];

static bool survives(const char* what, uint32_t cut) {
    for (int k = 0; k < 8; k++) {
        sim.cut_at = 0;
        int s = boot();
        if (s < 0) { printf("  FAIL %s cut@%u: reset %d: no boot (outcome %d)\n", what, cut, k, -s); return false; }
        if (!slot_intact(s)) { printf("  FAIL %s cut@%u: reset %d booted a damaged %s\n", what, cut, k, mb_slot_name(&sim_port, s)); return false; }
        if (k == 3) app_confirms();
    }
    mb_bcl_t b;
    mb_bcl_load(&b, &sim_port);
    if (b.fresh) { printf("  FAIL %s cut@%u: boot log lost\n", what, cut); return false; }
    return true;
}

static int replay(void (*fn)(void*), const uint8_t* start, const char* what, uint32_t* total) {
    memcpy(sim_flash, start, SIM_FLASH_SIZE);
    sim.ops = 0;
    sim.cut_at = 0;
    sim_guard(fn, NULL);
    *total = sim.ops;
    int bad = 0;
    for (uint32_t cut = 1; cut <= *total; cut++) {
        memcpy(sim_flash, start, SIM_FLASH_SIZE);
        sim.ops = 0;
        sim.cut_at = cut;
        sim_guard(fn, NULL);
        if (!survives(what, cut)) bad++;
    }
    return bad;
}

static void test_power_cuts(void) {
    printf("power cut at every flash operation of A/B updates\n");
    good_a();
    save_cfg("default os\nentry os\n slot ab\n");
    memcpy(snapshot, sim_flash, sizeof(snapshot));
    uint32_t t1, t2, t3;
    int bad = replay(scenario, snapshot, "update B", &t1);
    memcpy(sim_flash, snapshot, sizeof(snapshot));
    sim.cut_at = 0;
    sim_guard(scenario, NULL);
    memcpy(snap2, sim_flash, sizeof(snap2));
    bad += replay(scenario2, snap2, "update A", &t2);
    // OTA over the stream protocol
    uint32_t size = make_payload(79, 60000);
    mb_image_hdr_t h = make_header("ota", MB_VERSION(1, 3, 0), 2, size, 0);
    memset(&ota_stream, 0, sizeof(ota_stream));
    ota_stream.in = script;
    ota_stream.len = put_upload(script, 0, &h, 256, false);
    bad += replay(scenario3, snapshot, "OTA B", &t3);
    printf("  %u + %u + %u flash ops replayed\n", t1, t2, t3);
    CHECK(bad == 0, "%d of %u cut points failed", bad, t1 + t2 + t3);

    printf("power cut during log commits (sector swaps)\n");
    bad = 0;
    for (uint32_t cut = 1; cut <= 200; cut++) {
        good_a();
        mb_bcl_t b;
        mb_bcl_load(&b, &sim_port);
        uint32_t before = b.cur.min_security;
        sim.ops = 0;
        sim.cut_at = cut;
        volatile uint32_t done = 0;
        jmp_buf here;
        jmp_buf* prev = sim.jmp;
        sim.jmp = &here;
        if (!setjmp(here)) {
            for (uint32_t i = 1; i <= 100; i++) {
                mb_bcl_rec_t r = b.cur;
                r.min_security = before + i;
                if (mb_bcl_commit(&b, &r) == MB_OK) done = before + i;
            }
        }
        sim.jmp = prev;
        sim.cut_at = 0;
        mb_bcl_load(&b, &sim_port);
        if (b.fresh || (b.cur.min_security != done && b.cur.min_security != done + 1)) {
            printf("  FAIL cut@%u: log says %u, last completed %u\n", cut, b.cur.min_security, done);
            bad++;
        }
    }
    CHECK(bad == 0, "%d log cut points lost state", bad);
}

// mimiboot_tests --image file.mimg: put a host-packed image into slot A and boot it
static int boot_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror(path); return 2; }
    sim_reset();
    size_t n = fread(sim_flash + sim_port.layout->slot[MB_SLOT_A].offset, 1, sim_port.layout->slot[MB_SLOT_A].size, f);
    fclose(f);
    int s = boot();
    mb_bcl_rec_t r = log_now();
    printf("%s: %zu bytes -> %s (state %d, reason %d)\n", path, n, s == MB_SLOT_A ? "booted A" : "NOT booted", r.slot[0].state,
           r.slot[0].bad_reason);
    return s == MB_SLOT_A ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Two-stage builds: stage 0's choice (core/mb_stage0.c) and stage 1's guards
// ---------------------------------------------------------------------------
#define S1A 3   /* sim_two_stage(): slot 3 = s1a, 4 = s1b */
#define S1B 4

// a payload with a vector table: SP, then a reset vector inside it as linked at `link`
static uint32_t stage1_payload(uint32_t seed, uint32_t size, uint32_t link) {
    make_payload(seed, size);
    uint32_t v[2] = { 0x20001000u, link + 0x101u };
    memcpy(payload, v, sizeof(v));
    return size;
}

static mb_image_hdr_t stage1_hdr(int slot, const char* name, uint32_t version, uint32_t secver, uint32_t seed) {
    uint32_t link = sim_port.layout->slot[slot].offset + MB_IMG_PAYLOAD_OFF;
    uint32_t size = stage1_payload(seed, 30000, link);
    mb_image_hdr_t h = make_header(name, version, secver, size, MB_IMG_F_STAGE1);
    h.entry = link;
    mb_image_seal(&h);
    return h;
}

static void put_stage1(int slot, uint32_t version, uint32_t secver, uint32_t seed) {
    mb_image_hdr_t h = stage1_hdr(slot, "stage1", version, secver, seed);
    put_image(slot, &h);
}

static uint32_t s1_id(int slot) {
    mb_slot_info_t in;
    mb_image_read_header(&sim_port, slot, &in);
    return (uint32_t)mb_image_id(&in.hdr);
}

static int choose(bool* trial) {
    mb_stage0_choice_t c;
    int rc = mb_stage0_choose(&sim_port, &c);
    if (trial) *trial = c.trial;
    return rc == MB_OK ? c.slot : -1;
}

typedef struct { int rc; } confirm_t;
static void stage1_confirm_fn(void* ctx) { ((confirm_t*)ctx)->rc = mb_stage1_confirm(&sim_port); }
static mb_image_hdr_t ram_s1;
static int ram_rc;
static void ram_boot_fn(void* ctx) { ram_rc = mb_boot_ram(&sim_port, ctx, NULL, &ram_s1, NULL); }

static void two_stage_fresh(void) {
    sim_reset();
    sim_two_stage(true, s1_public);
}

static void test_two_stage(void) {
    bool trial;
    printf("two-stage: stage 0 picks a stage 1\n");
    two_stage_fresh();
    CHECK(choose(NULL) == -1, "no stage 1 anywhere: nothing to start");
    put_stage1(S1A, MB_VERSION(1, 0, 0), 0, 31);
    CHECK(choose(&trial) == S1A && !trial, "one copy, never confirmed: started, not on trial");
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, s1_id(S1A)) == 0, "... and nothing counted (nothing to fall back to)");
    for (int i = 0; i < 10; i++) choose(NULL);
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, s1_id(S1A)) == 0, "... however often it boots (the store doesn't fill)");

    printf("two-stage: an update is tried, counted, and passed over after %d boots\n", MB_STAGE1_TRIES);
    sim.stage1_slot = S1A;
    confirm_t cf;
    sim_guard(stage1_confirm_fn, &cf);
    CHECK(cf.rc == MB_OK && mb_store_count(&sim_port, MB_STORE_S1_GOOD, s1_id(S1A)) == 1, "s1a confirms itself");
    sim_guard(stage1_confirm_fn, &cf);
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_GOOD, s1_id(S1A)) == 1, "a second confirm writes nothing");
    put_stage1(S1B, MB_VERSION(1, 1, 0), 0, 32);
    for (int i = 1; i <= MB_STAGE1_TRIES; i++) {
        CHECK(choose(&trial) == S1B && trial, "boot %d: the newer copy on trial", i);
        CHECK(mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, s1_id(S1B)) == i, "boot %d counted before it runs", i);
    }
    CHECK(choose(&trial) == S1A && !trial, "after %d boots without a confirm: back to the good copy", MB_STAGE1_TRIES);
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, s1_id(S1B)) == MB_STAGE1_TRIES, "the failed copy isn't counted further");

    printf("two-stage: a new copy that confirms wins\n");
    put_stage1(S1B, MB_VERSION(1, 2, 0), 0, 33);
    CHECK(choose(&trial) == S1B && trial, "a fresh image in s1b: on trial again");
    sim.stage1_slot = S1B;
    sim_guard(stage1_confirm_fn, &cf);
    CHECK(choose(&trial) == S1B && !trial, "confirmed: chosen, no longer counted");
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, s1_id(S1B)) == 1, "one boot was counted, none after");

    printf("two-stage: never bricked by its own bookkeeping\n");
    two_stage_fresh();
    put_stage1(S1A, MB_VERSION(1, 0, 0), 0, 34);
    put_stage1(S1B, MB_VERSION(2, 0, 0), 0, 35);
    for (int i = 0; i < 2 * MB_STAGE1_TRIES; i++) choose(NULL);    // neither ever confirms
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, s1_id(S1A)) == MB_STAGE1_TRIES &&
          mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, s1_id(S1B)) == MB_STAGE1_TRIES, "both copies used up their tries");
    CHECK(choose(&trial) == S1B && !trial, "both failed: the newer one still starts (uncounted)");
    two_stage_fresh();
    sim.floor_locked = true;    // the store can't be written
    put_stage1(S1A, MB_VERSION(1, 0, 0), 0, 36);
    put_stage1(S1B, MB_VERSION(2, 0, 0), 0, 37);
    CHECK(choose(&trial) == S1B && !trial, "store unwritable, no good copy known: the best one starts uncounted");
    sim.floor_locked = false;
    sim.stage1_slot = S1A;
    sim_guard(stage1_confirm_fn, &cf);
    sim.floor_locked = true;
    CHECK(choose(&trial) == S1A && !trial, "a trial that can't be counted doesn't start: the good copy does");
    sim.floor_locked = false;

    printf("two-stage: the store keeps room for floors\n");
    two_stage_fresh();
    int n = 0;
    while (mb_store_append(&sim_port, MB_STORE_S1_ATTEMPT, 0x1234) == MB_OK) n++;
    CHECK(n == 4096 / 16 - MB_STORE_RESERVE, "attempts stop %d entries short (%d written)", MB_STORE_RESERVE, n);
    CHECK(mb_floor_raise(&sim_port, MB_FLOOR_STAGE1, 7) == MB_OK, "a floor still goes in");
    CHECK(mb_store_append(&sim_port, MB_FLOOR_SECURITY, 1) == MB_E_UNSUPP, "floor tags can't be appended as counts");

    printf("two-stage: what makes a copy unusable\n");
    two_stage_fresh();
    put_stage1(S1A, MB_VERSION(1, 0, 0), 0, 38);
    mb_image_hdr_t h = stage1_hdr(S1B, "other-slot", MB_VERSION(3, 0, 0), 0, 39);
    h.entry = sim_port.layout->slot[S1A].offset + MB_IMG_PAYLOAD_OFF;      // claims to be linked for s1a
    mb_image_seal(&h);
    put_image(S1B, &h);
    CHECK(choose(NULL) == S1A, "a header for the other copy");
    h = stage1_hdr(S1B, "vectors", MB_VERSION(3, 0, 0), 0, 40);
    uint32_t far = 0x9000000;
    memcpy(payload + 4, &far, 4);                                           // reset vector outside the image
    memcpy(h.sha256, (uint8_t[32]){0}, 32);
    { mb_sha256_t s; mb_sha256_init(&s); mb_sha256_update(&s, payload, h.payload_size); mb_sha256_final(&s, h.sha256); }
    mb_image_seal(&h);
    put_image(S1B, &h);
    CHECK(choose(NULL) == S1A, "a reset vector outside the payload (built for somewhere else)");
    put_stage1(S1B, MB_VERSION(3, 0, 0), 0, 41);
    sim_flash[sim_port.layout->slot[S1B].offset + MB_IMG_PAYLOAD_OFF + 500] ^= 1;
    CHECK(choose(NULL) == S1A, "a payload that fails its hash");
    install_raw(MB_SLOT_A, "app", MB_VERSION(9, 0, 0), 0, 42, 30000);
    memcpy(sim_flash + sim_port.layout->slot[S1B].offset, sim_flash + sim_port.layout->slot[MB_SLOT_A].offset, 4096);
    CHECK(choose(NULL) == S1A, "an app image (no stage-1 flag) in a stage-1 slot");
    put_stage1(S1B, MB_VERSION(3, 0, 0), 0, 43);
    sim.fault_slot = S1B;
    CHECK(choose(NULL) == S1A, "the copy the CPU faulted on last time is left out for a boot");
    CHECK(choose(&trial) == S1B && trial, "... and tried again on the next");

    printf("two-stage: stage-1 anti-rollback\n");
    two_stage_fresh();
    put_stage1(S1A, MB_VERSION(1, 0, 0), 0, 44);
    put_stage1(S1B, MB_VERSION(2, 0, 0), 2, 45);
    CHECK(choose(NULL) == S1B, "security 2 on trial");
    sim.stage1_slot = S1B;
    sim_guard(stage1_confirm_fn, &cf);
    uint32_t fl[MB_FLOOR_COUNT];
    mb_floor_get(&sim_port, fl);
    CHECK(fl[MB_FLOOR_STAGE1] == 2, "its confirm raised the stage-1 floor to 2 (%u)", (unsigned)fl[MB_FLOOR_STAGE1]);
    sim_flash[sim_port.layout->slot[S1B].offset + MB_IMG_PAYLOAD_OFF + 9] ^= 1;
    CHECK(choose(NULL) == -1, "with s1b damaged, the old s1a (security 0) is not started");

    printf("two-stage: signatures (stage-1 keys only)\n");
    two_stage_fresh();
    sim_port.require_signature = true;
    put_stage1(S1A, MB_VERSION(1, 0, 0), 0, 46);
    CHECK(choose(NULL) == -1, "signatures required: an unsigned stage 1 is not started");
    stage1_payload(S1_SIGNED_SEED, S1_SIGNED_SIZE, sim_port.layout->slot[S1A].offset + MB_IMG_PAYLOAD_OFF);
    put_image(S1A, (const mb_image_hdr_t*)s1_signed_appkey_hdr);
    CHECK(choose(NULL) == -1, "signed with the app key: not started");
    put_image(S1A, (const mb_image_hdr_t*)s1_signed_s1key_hdr);
    CHECK(choose(NULL) == S1A, "signed with the stage-1 key: started");
    sim_port.require_signature = false;

    printf("two-stage: stage 1 never boots a stage-1 copy, nor a stage 1 from an app slot\n");
    two_stage_fresh();
    put_stage1(S1A, MB_VERSION(1, 0, 0), 0, 47);
    put_stage1(S1B, MB_VERSION(1, 1, 0), 0, 48);
    sim.stage1_slot = S1A;
    CHECK(boot() < 0, "only stage-1 copies in flash: nothing to boot");
    mb_image_hdr_t sa = stage1_hdr(MB_SLOT_A, "s1-in-a", MB_VERSION(1, 0, 0), 0, 49);
    put_image(MB_SLOT_A, &sa);
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 0, 0), 0, 50, 20000);
    CHECK(boot() == MB_SLOT_GOLDEN, "a stage 1 in slot A is refused; golden boots");
    CHECK(log_now().slot[MB_SLOT_A].state == MB_ST_BAD && log_now().slot[S1A].state == MB_ST_EMPTY,
          "A marked bad; the log keeps no record of the stage-1 copies");
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_GOOD, s1_id(S1A)) == 1, "starting golden confirmed the running stage 1");
    mb_bcl_t lg;
    mb_bcl_load(&lg, &sim_port);
    mb_slot_info_t info[MB_MAX_SLOTS];
    mb_plan_t plan;
    CHECK(mb_plan_slot(&sim_port, &lg, info, S1B, true, NULL, &plan) == MB_E_REFUSED, "'boot s1b force' refused");
    ram_s1 = make_header_ex("s1-ram", MB_VERSION(1, 0, 0), 0, make_payload(53, 4096), MB_IMG_F_STAGE1, MB_ARCH_ARM,
                            MB_LOAD_RAM, SIM_RAM_BASE + 0x1000, 0);
    memcpy(sim_ram + 0x1000, payload, 4096);
    sim_outcome_t ro = sim_guard(ram_boot_fn, &lg);
    CHECK(ro != SIM_BOOTED && ram_rc == MB_E_UNSUPP, "a stage 1 can't be RAM-booted (%d, %d)", ro, ram_rc);

    printf("two-stage: console and config guards\n");
    sim.console = true;
    sim.button = true;
    uint32_t size = make_payload(51, 20000);
    mb_image_hdr_t app = make_header("app", MB_VERSION(1, 0, 0), 0, size, 0);
    size_t m = (size_t)sprintf((char*)script, "c\rversion\rrecv s1a\rerase s1a\rconfirm s1b\rboot s1b\rrecv s1b\r");
    script[m++] = 'H';                          // refused at the header: no frames follow
    memcpy(script + m, &app, sizeof(app));
    m += sizeof(app);
    mb_image_hdr_t s1 = stage1_hdr(S1B, "stage1-up", MB_VERSION(1, 5, 0), 0, 52);
    m += (size_t)sprintf((char*)script + m, "recv s1b\r");
    m = put_upload(script, m, &s1, 1000, false);
    sim_input(script, m);
    sim_power_on();
    sim.console = false;
    sim.button = false;
    CHECK(strstr(sim.out, "stage 1 from s1a, v1.0.0, security 0"), "version names the running copy");
    CHECK(strstr(sim.out, "s1a is the stage 1 running now: update the other copy"), "recv/erase into the running copy refused");
    CHECK(strstr(sim.out, "s1b holds a copy of the bootloader (stage 1)"), "confirm/boot on a stage-1 slot refused");
    CHECK(strstr(sim.out, "MB ERR refused (-7)"), "an app image into a stage-1 slot refused");
    CHECK(strstr(sim.out, "MB DONE") && s1_id(S1B) == (uint32_t)mb_image_id(&s1), "a stage 1 for s1b goes into s1b");
    char err[80];
    mb_config_t cfg;
    const char* text = "default x\nentry x\n slot s1b\n";
    mb_config_parse(&sim_port, text, strlen(text), &cfg, err, sizeof(err));
    CHECK(cfg.errors && strstr(err, "stage-1 slot"), "a config entry can't name a stage-1 slot (%s)", err);
    sim_two_stage(false, NULL);
}

// ---------------------------------------------------------------------------
// the protected store as two units: compaction (core/mb_floor.c)
// ---------------------------------------------------------------------------

#define REV1 0x11111111u
#define REV2 0x22222222u

// What has to survive any compaction (the "before" state of store_scene())
static bool store_holds(uint32_t floor_at_least, uint32_t ida, uint32_t idb, char* why) {
    uint32_t fl[MB_FLOOR_COUNT];
    mb_floor_get(&sim_port, fl);
    int ga = mb_store_count(&sim_port, MB_STORE_S1_GOOD, ida), tb = mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, idb);
    int r1 = mb_store_count(&sim_port, MB_STORE_KEY_REVOKED, REV1), r2 = mb_store_count(&sim_port, MB_STORE_KEY_REVOKED, REV2);
    sprintf(why, "floor %lu golden %lu stage1 %lu, good(a) %d, tries(b) %d, revoked %d %d", (unsigned long)fl[0],
            (unsigned long)fl[1], (unsigned long)fl[3], ga, tb, r1, r2);
    return fl[MB_FLOOR_SECURITY] >= floor_at_least && fl[MB_FLOOR_GOLDEN] == 7 && fl[MB_FLOOR_STAGE1] == 2 &&
           ga == 1 && tb == 2 && r1 >= 1 && r2 >= 1;
}

// Two installed stage-1 copies with records, two revoked keys, other floors,
// and records of copies long gone
static void store_scene(uint32_t* ida, uint32_t* idb) {
    two_stage_fresh();
    sim_store_two(true);
    put_stage1(S1A, MB_VERSION(1, 0, 0), 0, 31);
    put_stage1(S1B, MB_VERSION(1, 1, 0), 0, 32);
    *ida = s1_id(S1A);
    *idb = s1_id(S1B);
    for (uint32_t gone = 1; gone <= 10; gone++) {               // earlier copies: good, then replaced
        mb_store_append(&sim_port, MB_STORE_S1_ATTEMPT, 0xD0000000u + gone);
        mb_store_append(&sim_port, MB_STORE_S1_GOOD, 0xD0000000u + gone);
    }
    mb_store_append(&sim_port, MB_STORE_S1_GOOD, *ida);
    mb_store_append(&sim_port, MB_STORE_S1_ATTEMPT, *idb);
    mb_store_append(&sim_port, MB_STORE_S1_ATTEMPT, *idb);
    mb_store_append(&sim_port, MB_STORE_KEY_REVOKED, REV1);
    mb_store_append(&sim_port, MB_STORE_KEY_REVOKED, REV2);
    mb_floor_raise(&sim_port, MB_FLOOR_GOLDEN, 7);
    mb_floor_raise(&sim_port, MB_FLOOR_STAGE1, 2);
}

static void test_store_compaction(void) {
    uint32_t ida, idb;
    char why[160];
    printf("store, two units: a full unit is compacted, nothing that matters is lost\n");
    store_scene(&ida, &idb);
    uint32_t e0 = sim.erases, v = 1;
    bool ok = true;
    for (; v <= 1000 && ok; v++) {                              // a thousand releases, each raising the floor
        raise_t r = { MB_FLOOR_SECURITY, v, 0 };
        raise_fn(&r);
        ok = r.rc == MB_OK;
    }
    CHECK(ok && hw_floor(MB_FLOOR_SECURITY) == 1000, "1000 floor raises in 128-entry units (stopped at %lu)", (unsigned long)v - 1);
    CHECK(sim.erases - e0 >= 16, "compacted along the way (%lu erases)", (unsigned long)(sim.erases - e0));
    CHECK(store_holds(1000, ida, idb, why), "after it all: %s", why);
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_GOOD, 0xD0000001u) == 0, "records of copies no longer installed: gone");
    for (int i = 0; i < 300; i++)                               // attempts of an installed copy stay capped, not lost
        mb_store_append(&sim_port, MB_STORE_S1_ATTEMPT, idb);
    CHECK(mb_store_count(&sim_port, MB_STORE_S1_ATTEMPT, idb) >= MB_STAGE1_TRIES, "counted attempts survive compactions");

    printf("store, two units: a power cut at every step of a compaction\n");
    store_scene(&ida, &idb);
    static uint8_t snap[0x1000];
    uint32_t fl_before = 0;
    int cuts = 0, bad = 0;
    for (v = 1; v <= 200; v++) {                                // find the raise that compacts
        memcpy(snap, sim_flash + 0xF000, sizeof snap);
        uint32_t e = sim.erases;
        raise_t r = { MB_FLOOR_SECURITY, v, 0 };
        raise_fn(&r);
        if (sim.erases != e) break;
        fl_before = v;
    }
    CHECK(v <= 200, "a compaction happened (at raise %lu)", (unsigned long)v);
    for (uint32_t k = 1; k < 400; k++) {
        memcpy(sim_flash + 0xF000, snap, sizeof snap);
        sim.cut_at = sim.ops + k;
        raise_t r = { MB_FLOOR_SECURITY, v, 0 };
        sim_outcome_t o = sim_guard(raise_fn, &r);
        sim.cut_at = 0;
        bool held = store_holds(fl_before, ida, idb, why);
        if (!held) { bad++; printf("    cut at op %lu: %s\n", (unsigned long)k, why); }
        if (o != SIM_POWERCUT) break;
        cuts++;
        raise_t again = { MB_FLOOR_SECURITY, v, 0 };            // and the next boot carries on
        raise_fn(&again);
        if (again.rc != MB_OK || !store_holds(v, ida, idb, why)) { bad++; printf("    after cut %lu: rc %d, %s\n", (unsigned long)k, again.rc, why); }
    }
    // erase, 3 floors + 5 records copied, the commit, the old unit's erase, the raise itself: 12 operations
    CHECK(cuts == 12 && bad == 0, "%d cuts, each leaving the old or the new store whole, and the next raise working (%d bad)", cuts, bad);

    printf("store, one unit (no erase): append-only as before\n");
    store_scene(&ida, &idb);
    sim_store_two(false);
    CHECK(mb_floor_raise(&sim_port, MB_FLOOR_SECURITY, 5) == MB_OK, "still works");
    sim_two_stage(false, NULL);
}

// ---------------------------------------------------------------------------
// mcumgr / SMP (core/mb_smp.c), with requests made by the smp package (tests/gen_smp.h)
// ---------------------------------------------------------------------------
#if MB_FEAT_SMP
#include "tests/gen_smp.h"
#include "tests/smp_rx.h"
#define HAS SMP_HAS

static size_t smp_n;
static void smp_add(const uint8_t* d, size_t n) { memcpy(script + smp_n, d, n); smp_n += n; }
#define SMP_ADD(a) smp_add(a, sizeof(a))
static sim_outcome_t smp_run(void) {
    sim.console = true;
    sim.button = true;
    sim_input(script, smp_n);
    sim_outcome_t o = sim_power_on();
    sim.console = false;
    sim.button = false;
    smp_n = 0;
    smp_collect();
    return o;
}

static void test_smp(void) {
    printf("SMP: echo (v2 and v1), parameters, bootloader info, list, an unknown command\n");
    good_a();
    SMP_ADD(smp_echo); SMP_ADD(smp_echo_v1); SMP_ADD(smp_params); SMP_ADD(smp_bootinfo); SMP_ADD(smp_list); SMP_ADD(smp_slot_info);
    CHECK(smp_run() == SIM_CONSOLE_IDLE, "the console stays up");
    CHECK(smp_rx_n == 6, "six replies (%d)", smp_rx_n);
    CHECK(HAS(0, "\x61r\x6bhi from smp") && smp_rx[0].m[0] == ((1 << 3) | 3), "echo: the text back, a v2 write reply");
    CHECK(HAS(1, "\x61r\x67v1 talk") && smp_rx[1].m[0] == 3, "a v1 request gets a v1 reply");
    CHECK(HAS(2, "\x68" "buf_size\x19\x04\x00") && HAS(2, "\x69" "buf_count\x01"), "parameters: 1024-byte buffer, one of it");
    CHECK(HAS(3, "\x6a" "bootloader\x68MimiBoot"), "bootloader info");
    CHECK(HAS(4, "\x66images") && HAS(4, "\x67version\x65" "1.0.0") && HAS(4, "\x69" "confirmed\xf5"), "list: slot a, 1.0.0, confirmed");
    CHECK(HAS(5, "\x62rc\x08"), "slot info: not supported");
    int clears = 0;
    for (const char* s = sim.out; (s = strstr(s, "\033[2J")) != NULL; s++) clears++;
    CHECK(clears == 1, "the menu drew once: SMP traffic doesn't redraw it (%d)", clears);

    printf("SMP: upload a MimiBoot image in odd-sized chunks, with a resync, then boot and confirm it\n");
    good_a();
    SMP_ADD(smp_upload);
    smp_run();
    const mb_slot_def_t* b = &sim_port.layout->slot[MB_SLOT_B];
    CHECK(smp_rx_n > 10 && HAS(1, "\x63off\x19\x01\x2c"), "the chunk at the wrong offset is answered with where we are (300)");
    CHECK(HAS(smp_rx_n - 1, "\x65match\xf5") && HAS(smp_rx_n - 1, "\x63off\x19\x23\x88"), "the last reply: all 9096 bytes, sha matches");
    bool any_err = false;
    for (int k = 0; k < smp_rx_n; k++) any_err |= HAS(k, "\x63" "err") || HAS(k, "\x62rc");
    CHECK(!any_err, "no errors along the way");
    CHECK(!memcmp(sim_flash + b->offset, smp_img_hdr, 256) && slot_intact(MB_SLOT_B), "slot b holds the image (header from mbtool)");
    int bs = boot();
    CHECK(bs == MB_SLOT_B && sim.watchdog_ms, "it boots as a trial (slot %d, b state %d reason %d, watchdog %u)", bs,
          log_now().slot[MB_SLOT_B].state, log_now().slot[MB_SLOT_B].bad_reason, (unsigned)sim.watchdog_ms);
    SMP_ADD(smp_confirm);
    smp_run();
    CHECK(log_now().slot[MB_SLOT_B].state == MB_ST_GOOD && log_now().active == MB_SLOT_B, "confirm by hash: GOOD, active");
    CHECK(HAS(0, "\x66images"), "the reply is the new list");

    printf("SMP: refused or failed uploads leave the slot empty\n");
    good_a();
    install_raw(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 0, 0), 0, 7, 20000);
    SMP_ADD(smp_upload_golden);
    smp_run();
    CHECK(HAS(0, "\x63" "err") && slot_intact(MB_SLOT_GOLDEN), "image 3 (golden): refused, golden untouched");
    SMP_ADD(smp_upload_bad);
    smp_run();
    mb_slot_info_t in;
    CHECK(HAS(smp_rx_n - 1, "\x63" "err") && mb_image_read_header(&sim_port, MB_SLOT_B, &in) != MB_OK,
          "a payload that doesn't match: error on the last chunk, b has no header");
    SMP_ADD(smp_upload_cut);
    smp_run();
    CHECK(smp_rx_n == 3 && mb_image_read_header(&sim_port, MB_SLOT_B, &in) != MB_OK, "an upload that stops: b stays empty");
    CHECK(boot() == MB_SLOT_A, "and the board boots a as before");

    printf("SMP: with signatures required, as recv checks them\n");
    good_a();
    sim_port.require_signature = true;
    install_raw(MB_SLOT_B, "previous", MB_VERSION(2, 0, 0), 1, 9, 20000);
    SMP_ADD(smp_upload_unsigned_first);
    smp_run();
    CHECK(HAS(0, "\x63" "err") && slot_intact(MB_SLOT_B), "an unsigned image is refused at its first page, before b is erased");
    SMP_ADD(smp_upload_signed);
    smp_run();
    any_err = false;
    for (int k = 0; k < smp_rx_n; k++) any_err |= HAS(k, "\x63" "err") || HAS(k, "\x62rc");
    CHECK(!any_err && HAS(smp_rx_n - 1, "\x65match\xf5") && slot_intact(MB_SLOT_B), "the signed one goes in");
    bs = boot();
    CHECK(bs == MB_SLOT_B && sim.booted_hdr.flags & MB_IMG_F_SIGNED, "and boots (signature checked again at boot)");
    sim_port.require_signature = false;

#if MB_FEAT_ENC
    printf("SMP: an encrypted image (mbtool's format) is decrypted on the way in\n");
    dev_key_init();
    good_a();
    sim_port.enc_key = dev_priv;
    SMP_ADD(smp_upload_enc);
    smp_run();
    any_err = false;
    for (int k = 0; k < smp_rx_n; k++) any_err |= HAS(k, "\x63" "err") || HAS(k, "\x62rc");
    make_payload(SMP_IMG_SEED, SMP_IMG_SIZE);
    CHECK(!any_err && HAS(smp_rx_n - 1, "\x65match\xf5"), "no errors; the file's sha (ciphertext) matches");
    CHECK(slot_intact(MB_SLOT_B) && !memcmp(sim_flash + b->offset + MB_IMG_PAYLOAD_OFF, payload, SMP_IMG_SIZE) &&
          sim_flash[b->offset + MB_IMG_PAYLOAD_OFF + SMP_IMG_SIZE] == 0xFF, "b holds the plaintext, nothing past it");
    CHECK(boot() == MB_SLOT_B, "and boots");

    printf("SMP: a bad envelope, or no key in the build: refused, b untouched\n");
    good_a();
    sim_port.enc_key = dev_priv;
    install_raw(MB_SLOT_B, "previous", MB_VERSION(2, 0, 0), 1, 9, 20000);
    SMP_ADD(smp_upload_enc_badenv);
    smp_run();
    CHECK(HAS(smp_rx_n - 1, "\x63" "err") && slot_intact(MB_SLOT_B), "a flipped envelope bit: refused before the erase");
    good_a();
    install_raw(MB_SLOT_B, "previous", MB_VERSION(2, 0, 0), 1, 9, 20000);
    SMP_ADD(smp_upload_enc);
    smp_run();
    CHECK(HAS(0, "\x63" "err") && slot_intact(MB_SLOT_B), "no key: refused at the first page");
    sim_port.enc_key = NULL;
#endif

#if MB_FEAT_LMS
    printf("SMP: an LMS-signed image, its signature in the header sector\n");
    good_a();
    sim_lms(lms_public, NULL);
    sim_port.require_signature = true;
    install_raw(MB_SLOT_B, "previous", MB_VERSION(2, 0, 0), 1, 9, 20000);
    SMP_ADD(smp_upload_lms_badsig);
    smp_run();
    CHECK(HAS(smp_rx_n - 1, "\x63" "err") && slot_intact(MB_SLOT_B), "a bad LMS signature: refused before b is erased");
    SMP_ADD(smp_upload_lms);
    smp_run();
    any_err = false;
    for (int k = 0; k < smp_rx_n; k++) any_err |= HAS(k, "\x63" "err") || HAS(k, "\x62rc");
    CHECK(!any_err && HAS(smp_rx_n - 1, "\x65match\xf5") && slot_intact(MB_SLOT_B), "the good one goes in");
    CHECK(boot() == MB_SLOT_B && (sim.booted_hdr.flags & MB_IMG_F_LMS), "b boots, its signature read from flash");
    sim_port.require_signature = false;
    sim_lms(NULL, NULL);
#endif

    printf("SMP: erase, reset\n");
    good_a();
    install_raw(MB_SLOT_B, "other", MB_VERSION(2, 0, 0), 1, 8, 20000);
    SMP_ADD(smp_erase_a);
    SMP_ADD(smp_erase_b);
    smp_run();
    CHECK(HAS(0, "\x63" "err") && slot_intact(MB_SLOT_A), "erasing the active good slot is refused");
    CHECK(!HAS(1, "\x63" "err") && mb_image_read_header(&sim_port, MB_SLOT_B, &in) != MB_OK, "slot b erased");
    SMP_ADD(smp_reset);
    CHECK(smp_run() == SIM_REBOOT && smp_rx_n == 1, "reset: the reply goes out, then the reboot");
}
#else
static void test_smp(void) {}
#endif

#include "tests/test_control.inc"


// ---------------------------------------------------------------------------
// LMS images (headers + signatures from tests/gen_signed.py, mbtool's own LMS signer)
// ---------------------------------------------------------------------------
#if MB_FEAT_LMS
// an LMS-signed image as a file lands in flash: header, the signature TLV at +256, payload
static void put_lms(int slot, const uint8_t* hdr, const uint8_t* sig, size_t siglen, uint32_t seed, uint32_t size) {
    put_signed(slot, hdr, seed, size);
    uint8_t* t = sim_flash + sim_port.layout->slot[slot].offset + MB_IMG_HDR_SIZE;
    t[0] = MB_TLV_LMS_SIG;
    t[1] = 0;
    t[2] = (uint8_t)siglen;
    t[3] = (uint8_t)(siglen >> 8);
    memcpy(t + 4, sig, siglen);
}

static size_t put_sig_frame(uint8_t* out, const uint8_t* sig, size_t len) {
    size_t n = 0;
    out[n++] = 'S';
    out[n++] = (uint8_t)len;
    out[n++] = (uint8_t)(len >> 8);
    memcpy(out + n, sig, len);
    n += len;
    uint32_t c = mb_crc32(0, out + 3, len);
    for (int i = 0; i < 4; i++) out[n++] = (uint8_t)(c >> (8 * i));
    return n;
}

// the console upload of an LMS-signed image: header, signature frame, payload frames
static size_t put_lms_upload(uint8_t* sc, size_t n, const uint8_t* hdr, const uint8_t* sig, size_t siglen, uint32_t size) {
    sc[n++] = 'H';
    memcpy(sc + n, hdr, MB_IMG_HDR_SIZE);
    n += MB_IMG_HDR_SIZE;
    n += put_sig_frame(sc + n, sig, siglen);
    for (uint32_t off = 0; off < size; off += 1000) {
        uint16_t len = (uint16_t)(size - off < 1000 ? size - off : 1000);
        n += put_frame(sc + n, off, payload + off, len);
    }
    sc[n++] = 'E';
    return n;
}

// the log forgets a slot's record
static void forget(int slot) {
    mb_bcl_t b;
    mb_bcl_load(&b, &sim_port);
    mb_bcl_rec_t r = b.cur;
    memset(&r.slot[slot], 0, sizeof r.slot[slot]);
    mb_bcl_commit(&b, &r);
}

static void test_lms_images(void) {
    printf("LMS images: mbtool-signed, checked from the slot's header sector\n");
    sim_reset();
    sim_lms(lms_public, NULL);
    put_lms(MB_SLOT_A, lms_good_hdr, lms_good_sig, sizeof lms_good_sig, LMS_GOOD_SEED, LMS_GOOD_SIZE);
    mb_slot_info_t info;
    mb_image_read_header(&sim_port, MB_SLOT_A, &info);
    CHECK((info.hdr.flags & MB_IMG_F_LMS) && info.hdr.key_id == LMS_KEY_ID, "header says LMS, key id from I");
    CHECK(mb_image_check_sig(&sim_port, &info) == MB_OK && info.proof_sig == MB_PROOF_SIG, "the signature verifies");
    sim_port.require_signature = true;
    CHECK(boot() == MB_SLOT_A && (log_now().slot[MB_SLOT_A].flags & MB_SF_SIG_OK), "required + LMS: boots, cached");
    app_confirms();
    put_lms(MB_SLOT_B, lms_other_key_hdr, lms_other_key_sig, sizeof lms_other_key_sig, LMS_OTHER_KEY_SEED,
            LMS_OTHER_KEY_SIZE);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "a key the board lacks: refused");
    put_lms(MB_SLOT_B, lms_newer_hdr, lms_newer_sig, sizeof lms_newer_sig, LMS_NEWER_SEED, LMS_NEWER_SIZE);
    sim_flash[sim_port.layout->slot[MB_SLOT_B].offset + MB_IMG_HDR_SIZE + 4 + 700] ^= 0x04;
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "a flipped bit in the signature: refused");
    // (a bad mark sticks to an image until the image changes; these checks reuse one, so the log forgets it each time)
    forget(MB_SLOT_B);
    put_signed(MB_SLOT_B, lms_newer_hdr, LMS_NEWER_SEED, LMS_NEWER_SIZE);       // no signature TLV at all
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "no signature in the header sector: refused");
    mb_image_hdr_t h;
    memcpy(&h, lms_newer_hdr, sizeof h);
    h.security_version = 9;                     // a signed field changed (CRC fixed up)
    mb_image_seal(&h);
    forget(MB_SLOT_B);
    put_lms(MB_SLOT_B, (const uint8_t*)&h, lms_newer_sig, sizeof lms_newer_sig, LMS_NEWER_SEED, LMS_NEWER_SIZE);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "a field changed after signing: refused");
    memcpy(&h, lms_newer_hdr, sizeof h);
    h.flags &= ~MB_IMG_F_LMS;                   // claim it's Ed25519 (with a zero signature)
    mb_image_seal(&h);
    forget(MB_SLOT_B);
    put_lms(MB_SLOT_B, (const uint8_t*)&h, lms_newer_sig, sizeof lms_newer_sig, LMS_NEWER_SEED, LMS_NEWER_SIZE);
    CHECK(boot() == MB_SLOT_A && log_now().slot[MB_SLOT_B].bad_reason == MB_BAD_SIGNATURE, "LMS flag dropped: refused");
    forget(MB_SLOT_B);
    put_lms(MB_SLOT_B, lms_newer_hdr, lms_newer_sig, sizeof lms_newer_sig, LMS_NEWER_SEED, LMS_NEWER_SIZE);
    CHECK(boot() == MB_SLOT_B && sim.watchdog_ms, "a good LMS update: boots as a trial");
    sim_lms(NULL, NULL);
    sim_reset();
    put_lms(MB_SLOT_A, lms_good_hdr, lms_good_sig, sizeof lms_good_sig, LMS_GOOD_SEED, LMS_GOOD_SIZE);
    sim_port.require_signature = true;
    CHECK(boot() == -SIM_ROM, "no LMS keys in the build + required signatures: refused");
    sim_port.require_signature = false;
    forget(MB_SLOT_A);
    CHECK(boot() == MB_SLOT_A, "no LMS keys, signatures optional: boots as unsigned");

    printf("LMS: console upload ('S' frame), checked before the erase, kept in the slot\n");
    good_a();
    sim_lms(lms_public, NULL);
    install_raw(MB_SLOT_B, "previous", MB_VERSION(2, 0, 0), 1, 9, 20000);
    make_payload(LMS_NEWER_SEED, LMS_NEWER_SIZE);
    static uint8_t bad[4000];
    memcpy(bad, lms_newer_sig, sizeof lms_newer_sig);
    bad[200] ^= 1;
    size_t n = (size_t)sprintf((char*)script, "c\rrecv b\r");
    n = put_lms_upload(script, n, lms_newer_hdr, bad, sizeof lms_newer_sig, LMS_NEWER_SIZE);
    console_run(n);
    CHECK(strstr(sim.out, "MB SIG") && strstr(sim.out, "MB ERR refused") && slot_intact(MB_SLOT_B) &&
          mb_image_read_header(&sim_port, MB_SLOT_B, &info) == MB_OK && !(info.hdr.flags & MB_IMG_F_LMS),
          "a bad signature: refused, b not erased");
    n = (size_t)sprintf((char*)script, "c\rrecv b\r");
    n = put_lms_upload(script, n, lms_newer_hdr, lms_newer_sig, sizeof lms_newer_sig, LMS_NEWER_SIZE);
    console_run(n);
    const uint8_t* t = sim_flash + sim_port.layout->slot[MB_SLOT_B].offset + MB_IMG_HDR_SIZE;
    CHECK(strstr(sim.out, "MB DONE") && t[0] == MB_TLV_LMS_SIG && !memcmp(t + 4, lms_newer_sig, sizeof lms_newer_sig) &&
          t[4 + sizeof lms_newer_sig] == 0xFF, "uploaded: the signature sits in b's header sector");
    sim_port.require_signature = true;
    CHECK(boot() == MB_SLOT_B, "and it boots with signatures required");
    sim_port.require_signature = false;
    good_a();
    sim_lms(NULL, NULL);
    make_payload(LMS_NEWER_SEED, LMS_NEWER_SIZE);
    n = (size_t)sprintf((char*)script, "c\rrecv b\r");
    n = put_lms_upload(script, n, lms_newer_hdr, lms_newer_sig, sizeof lms_newer_sig, LMS_NEWER_SIZE);
    console_run(n);
    CHECK(strstr(sim.out, "MB DONE"), "a build without LMS keys takes it as unsigned (signatures optional)");

    printf("LMS: ramboot (the signature from the 'S' frame), signatures required\n");
    good_a();
    sim_lms(lms_public, NULL);
    sim_port.require_signature = true;
    make_payload(LMS_RAM_SEED, LMS_RAM_SIZE);
    memcpy(bad, lms_ram_sig, sizeof lms_ram_sig);
    bad[333] ^= 2;
    n = (size_t)sprintf((char*)script, "c\rramboot\r");
    n = put_lms_upload(script, n, lms_ram_hdr, bad, sizeof lms_ram_sig, LMS_RAM_SIZE);
    console_run(n);
    CHECK(!sim.booted_ram && strstr(sim.out, "MB ERR refused"), "a bad signature: refused");
    n = (size_t)sprintf((char*)script, "c\rramboot\r");
    n = put_lms_upload(script, n, lms_ram_hdr, lms_ram_sig, sizeof lms_ram_sig, LMS_RAM_SIZE);
    sim.console = true;
    sim.button = true;
    sim_input(script, n);
    sim_outcome_t ro = sim_power_on();
    sim.button = false;
    sim.console = false;
    CHECK(ro == SIM_BOOTED && sim.booted_ram && !memcmp(sim_ram + (LMS_RAM_ADDR - SIM_RAM_BASE), payload, LMS_RAM_SIZE),
          "the good one: checked again at launch, started from RAM");
    sim_port.require_signature = false;

    printf("LMS: client install (install_sig, begin, write, end)\n");
    good_a();
    sim_lms(lms_public, NULL);
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    mb_image_hdr_t nh;
    memcpy(&nh, lms_newer_hdr, sizeof nh);
    make_payload(LMS_NEWER_SEED, LMS_NEWER_SIZE);
    CHECK(mb_client_install_sig(bad, sizeof lms_newer_sig) == MB_OK && mb_client_install_begin(MB_SLOT_B, &nh) == MB_E_SIGNATURE,
          "a bad signature: refused at begin");
    CHECK(mb_client_install_sig(lms_newer_sig, sizeof lms_newer_sig) == MB_OK && mb_client_install_begin(MB_SLOT_B, &nh) == MB_OK,
          "the right one: begin");
    mb_upload_sig.buf[0] ^= 0xFF;               // (the RAM copy is used up: what boots is the flash copy)
    CHECK(mb_client_install_write(0, payload, LMS_NEWER_SIZE) == MB_OK && mb_client_install_end() == MB_OK,
          "payload written, checked, header last");
    CHECK(boot() == MB_SLOT_B, "the client-installed LMS image boots");
    good_a();
    sim_lms(lms_public, NULL);
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    make_payload(LMS_NEWER_SEED, LMS_NEWER_SIZE);
    mb_client_install_sig(lms_newer_sig, sizeof lms_newer_sig);
    mb_client_install_begin(MB_SLOT_B, &nh);
    sim_flash[sim_port.layout->slot[MB_SLOT_B].offset + MB_IMG_HDR_SIZE + 4 + 50] ^= 0x80;   // the flash copy went bad
    mb_client_install_write(0, payload, LMS_NEWER_SIZE);
    CHECK(mb_client_install_end() == MB_E_SIGNATURE && mb_image_read_header(&sim_port, MB_SLOT_B, &info) != MB_OK,
          "the copy in flash doesn't verify: no header, b stays empty");

    printf("LMS: key revocation\n");
    static const mb_keyring_t revoke_ring = { 1, (const uint8_t (*)[32])s1_public };   // gen_signed's OTHER key
    sim_reset();
    sim_lms(lms_public, NULL);
    sim_port.require_signature = true;
    sim_port.revoke_keys = &revoke_ring;
    put_lms(MB_SLOT_A, lms_good_hdr, lms_good_sig, sizeof lms_good_sig, LMS_GOOD_SEED, LMS_GOOD_SIZE);
    put_signed(MB_SLOT_GOLDEN, signed_good_hdr, SIGNED_GOOD_SEED, SIGNED_GOOD_SIZE);
    CHECK(boot() == MB_SLOT_A, "before: the LMS image boots");
    CHECK(mb_key_revoke(&sim_port, LMS_KEY_ID, revoke_lms_sig) == MB_OK && mb_key_revoked(&sim_port, LMS_KEY_ID),
          "the LMS key is revoked by its key id");
    CHECK(boot() == MB_SLOT_GOLDEN && log_now().slot[MB_SLOT_A].bad_reason == MB_BAD_SIGNATURE,
          "after: the LMS image is refused, the Ed25519 golden boots");
    sim_port.revoke_keys = NULL;
    sim_port.require_signature = false;

    printf("LMS: stage 0 takes an LMS-signed stage 1 (stage-1 keys only)\n");
    sim_reset();
    sim_two_stage(true, s1_public);
    sim_lms(lms_public, NULL);                  // an app LMS key: not enough for a stage 1
    sim_port.require_signature = true;
    put_lms(3, s1_lms_hdr, s1_lms_sig, sizeof s1_lms_sig, S1_LMS_SEED, S1_LMS_SIZE);
    // (stage1_payload: the vector table in front, as test_two_stage builds them)
    make_payload(S1_LMS_SEED, S1_LMS_SIZE);
    uint32_t v[2] = { 0x20001000u, sim_port.layout->slot[3].offset + MB_IMG_PAYLOAD_OFF + 0x101 };
    memcpy(sim_flash + sim_port.layout->slot[3].offset + MB_IMG_PAYLOAD_OFF, v, 8);
    CHECK(choose(NULL) == -1, "an LMS stage 1, but no stage-1 LMS key: refused");
    sim_lms(lms_public, lms_s1_public);
    CHECK(choose(NULL) == 3, "with the stage-1 LMS key: started");
    sim_port.require_signature = false;
    sim_lms(NULL, NULL);
    sim_two_stage(false, NULL);
}
#endif


// ---------------------------------------------------------------------------
// OS hooks: handoff v2, the RAM mailbox, crashes, slots (MB_FEAT_OS_HOOKS)
// ---------------------------------------------------------------------------
#if MB_FEAT_OS_HOOKS
// an image whose handoff buffer is v2-sized (what mbtool writes for apps built with today's headers)
static mb_image_hdr_t put_v2(int slot, const char* name, uint32_t version, uint32_t seed, uint16_t hsize) {
    make_payload(seed, 20000);
    mb_image_hdr_t h = make_header_ex(name, version, 1, 20000, slot == MB_SLOT_GOLDEN ? MB_IMG_F_GOLDEN : 0, MB_ARCH_ARM,
                                      MB_LOAD_CHAIN, 0, HANDOFF_ADDR);
    h.handoff_size = hsize;
    mb_image_seal(&h);
    put_image(slot, &h);
    return h;
}

// the app side, as it starts: init, take the handoff
static void app_start(int slot) {
    sim.self_slot = slot;
    mb_client_init(&sim_port);
    mb_client_set_handoff(ram_handoff());
}

typedef struct { int reason; const char* msg; } reboot_t;
static void reboot_fn(void* ctx) { reboot_t* r = ctx; mb_client_reboot(r->reason, r->msg); }
static void panic_fn(void* ctx) { mb_client_panic((const char*)ctx); }
static void fault_fn(void* ctx) { (void)ctx; mb_client_fault(0x00012345u, 0x00023457u, 0x00000400u); }

// reset from the app (the next power_on sees a soft reset, as the hardware would say)
static sim_outcome_t app_reset(void (*fn)(void*), void* ctx) {
    sim.reset_cause = MB_RESET_SOFT;
    sim_outcome_t o = sim_guard(fn, ctx);
    return o;
}

static char ctl_out[4096];
static void ctl_print(void* ctx, const char* s) {
    (void)ctx;
    strncat(ctl_out, s, sizeof(ctl_out) - strlen(ctl_out) - 1);
}
static void ctl_reboot_fn(void* ctx) { mb_ctl_line((char*)ctx, ctl_print, NULL); }
// MBCTL_SHOW=1 prints what mbctl says (to read it as a person would)
static int mb_ctl_show(char* line) {
    char copy[64];
    snprintf(copy, sizeof copy, "%s", line);
    int rc = mb_ctl_line(line, ctl_print, NULL);
    if (getenv("MBCTL_SHOW")) printf("\n$ mbctl %s\n%s", copy, ctl_out);
    return rc;
}

static void test_os_hooks(void) {
    printf("OS hooks: handoff v2 (what the image learns)\n");
    sim_reset();
    sim.reset_cause = MB_RESET_POWER;
    mb_image_hdr_t ha = put_v2(MB_SLOT_A, "os", MB_VERSION(1, 0, 0), 51, MB_HANDOFF_V2_SIZE);
    CHECK(boot() == MB_SLOT_A, "boots");
    mb_handoff_t* ho = ram_handoff();
    CHECK(ho->version == 2 && ho->size == MB_HANDOFF_V2_SIZE && ho->crc2 == mb_crc32(0, ho, offsetof(mb_handoff_t, crc2)),
          "a v2 block, both CRCs");
    CHECK(ho->crc == mb_crc32(0, ho, offsetof(mb_handoff_t, crc)), "its v1 part checks out alone (old readers)");
    CHECK((ho->caps & MB_CAP_MAILBOX) && (ho->features & MB_HF_MAILBOX) && (ho->features & MB_HF_CONTROL), "caps and features");
    CHECK(ho->prev.reason == MB_END_POWER_ON && !(ho->prev.flags & MB_ENDF_NOTED), "previous run: power-on (from the reset cause)");
    CHECK((ho->hflags & MB_HO_TRIAL) && ho->trial_ms == MB_DEFAULT_TRIAL_MS && ho->tries_left > 0, "a trial boot says so");
    app_start(MB_SLOT_A);
    mb_client_loader_t li;
    CHECK(mb_client_loader_info(&li) == MB_OK && li.handoff_version == 2 && li.version == MIMIBOOT_VERSION_NUM,
          "loader_info from the handoff");
    CHECK(mb_client_transport() == MB_VIA_MAILBOX, "requests can go through RAM");
    mb_client_confirm();

    printf("OS hooks: an image with a v1 buffer gets v1, nothing written past it\n");
    put_v2(MB_SLOT_B, "old", MB_VERSION(0, 9, 0), 52, 0);         // (handoff_size 0: built before v2)
    memset(sim_ram + (HANDOFF_ADDR - SIM_RAM_BASE), 0xAA, MB_HANDOFF_V2_SIZE);
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    mb_client_request(MB_REQ_BOOT_ONCE, MB_SLOT_B);
    CHECK(boot() == MB_SLOT_B && ho->version == 1 && ho->size == MB_HANDOFF_V1_SIZE, "a v1 block");
    bool untouched = true;
    for (unsigned i = MB_HANDOFF_V1_SIZE; i < MB_HANDOFF_V2_SIZE; i++)
        untouched &= sim_ram[HANDOFF_ADDR - SIM_RAM_BASE + i] == 0xAA;
    CHECK(untouched, "bytes 160..319 untouched");
    app_start(MB_SLOT_B);
    mb_end_t e;
    CHECK(mb_client_handoff() && mb_client_last_end(&e) == MB_E_UNSUPP && mb_client_transport() != MB_VIA_MAILBOX,
          "the client takes v1: no previous-run record, no mailbox");

    printf("OS hooks: reboot into the menu through RAM, no flash write\n");
    app_confirms();                                                 // B good (and preferred) ...
    sim.self_slot = MB_SLOT_B;
    mb_client_init(&sim_port);
    mb_client_request(MB_REQ_BOOT_ONCE, MB_SLOT_A);
    CHECK(boot() == MB_SLOT_A, "A once");
    app_confirms();                                                 // ... then A again: both good, A preferred
    CHECK(boot() == MB_SLOT_A, "A");
    app_start(MB_SLOT_A);
    CHECK(mb_client_next(MB_CONTROL_MENU, NULL, NULL, MB_VIA_AUTO) == MB_VIA_MAILBOX, "queued in RAM");
    uint32_t w = writes();
    reboot_t rb = { MB_END_REBOOT, "menu please" };
    CHECK(app_reset(reboot_fn, &rb) == SIM_REBOOT, "the app resets");
    sim.console = true;
    sim_input("c\rlast\rexit\r", 12);
    CHECK(boot() == MB_SLOT_A && strstr(sim.out, "MimiBoot"), "the menu came up; exit boots A");
    CHECK(strstr(sim.out, "last run ended: reboot (the OS said so)") && strstr(sim.out, "menu please"), "the console's 'last'");
    sim.console = false;
    CHECK(writes() == w, "and nothing was written to flash (%u writes)", (unsigned)(writes() - w));
    CHECK(ho->prev.reason == MB_END_REBOOT && (ho->prev.flags & MB_ENDF_NOTED) && !strcmp(ho->prev.msg, "menu please"),
          "the next handoff says why the last run ended");
    CHECK(boot() == MB_SLOT_A && ho->prev.reason == MB_END_UNKNOWN, "used once: a plain reset after it is 'unknown'");

    printf("OS hooks: boot another slot once, with args, through RAM\n");
    app_start(MB_SLOT_A);
    CHECK(mb_client_next(MB_CONTROL_SLOT, "b", "safe=1", MB_VIA_AUTO) == MB_VIA_MAILBOX, "queued");
    rb.reason = MB_END_UPDATE;
    rb.msg = "trying b";
    app_reset(reboot_fn, &rb);
    CHECK(boot() == MB_SLOT_B && log_now().last_kind == MB_KIND_ONCE && !strcmp(ho->args, "safe=1"), "B once, with its args");
    CHECK(boot() == MB_SLOT_A, "then A again");

    printf("OS hooks: what the bootloader ignores\n");
    app_start(MB_SLOT_A);
    mb_client_next(MB_CONTROL_SLOT, "b", NULL, MB_VIA_AUTO);
    app_reset(reboot_fn, &rb);
    mb_mailbox_t* m = (mb_mailbox_t*)ram_handoff();
    m->image_id ^= 1;
    m->crc = mb_crc32(0, m, offsetof(mb_mailbox_t, crc));
    CHECK(boot() == MB_SLOT_A && log_now().last_kind != MB_KIND_ONCE, "a mailbox from another image: ignored");
    app_start(MB_SLOT_A);
    mb_client_next(MB_CONTROL_SLOT, "b", NULL, MB_VIA_AUTO);
    app_reset(reboot_fn, &rb);
    m->end.msg[0] ^= 1;                                             // CRC now wrong
    CHECK(boot() == MB_SLOT_A, "a damaged one: ignored");
    app_start(MB_SLOT_A);
    mb_control_request_t q;
    memset(&q, 0, sizeof q);
    q.version = MB_CONTROL_API_VERSION;
    q.size = sizeof q;
    q.action = MB_CONTROL_SLOT;
    q.slot = 9;                                                     // no such slot
    CHECK(mb_client_next_boot(&q, MB_VIA_AUTO) == MB_VIA_MAILBOX, "(the client passes what it can't know)");
    app_reset(reboot_fn, &rb);
    sim.console = true;
    sim_input("c\rexit\r", 7);
    boot();
    sim.console = false;
    CHECK(strstr(sim.out, "MimiBoot") != NULL, "a bad request (the log's own check refuses it): stops in the menu");

    printf("OS hooks: a request in flash comes before one in RAM\n");
    app_start(MB_SLOT_A);
    mb_client_next(MB_CONTROL_MENU, NULL, NULL, MB_VIA_AUTO);       // RAM
    CHECK(mb_client_request(MB_REQ_BOOT_ONCE, MB_SLOT_B) == MB_OK, "and B once in the log (written directly)");
    app_reset(reboot_fn, &rb);
    CHECK(boot() == MB_SLOT_B, "flash wins: B once (no menu)");
    boot();

    printf("OS hooks: panics count as crashes; enough in a row and the other image boots\n");
    install_raw(MB_SLOT_B, "older", MB_VERSION(0, 9, 5), 1, 53, 20000);
    sim.self_slot = MB_SLOT_A;
    mb_client_init(&sim_port);
    mb_client_request(MB_REQ_BOOT_ONCE, MB_SLOT_B);
    boot();
    app_confirms();                                                 // B good
    sim.self_slot = MB_SLOT_B;
    mb_client_init(&sim_port);
    mb_client_request(MB_REQ_BOOT_ONCE, MB_SLOT_A);
    CHECK(boot() == MB_SLOT_A, "A");
    app_confirms();                                                 // A good and active again
    CHECK(boot() == MB_SLOT_A, "A active");
    app_start(MB_SLOT_A);
    CHECK(app_reset(panic_fn, "out of heap") == SIM_REBOOT, "panic resets");
    CHECK(boot() == MB_SLOT_A && log_now().strikes == 1, "one strike");
    CHECK(ho->prev.reason == MB_END_PANIC && (ho->prev.flags & MB_ENDF_CRASH) && ho->prev.pc && !strcmp(ho->prev.msg, "out of heap"),
          "the next boot knows: panic, where, why");
    app_start(MB_SLOT_A);
    app_reset(fault_fn, NULL);
    CHECK(boot() == MB_SLOT_A && log_now().strikes == 2 && ho->prev.reason == MB_END_FAULT && ho->prev.pc == 0x12345u &&
          ho->prev.info == 0x400u, "a fault: strike two, its registers handed on");
    int got = MB_SLOT_A;
    for (int i = 2; i < MB_STRIKES_MAX && got == MB_SLOT_A; i++) {
        app_start(MB_SLOT_A);
        app_reset(panic_fn, "again");
        got = boot();
    }
    CHECK(got == MB_SLOT_B, "after %d crashes in a row: the other good image (B)", MB_STRIKES_MAX);

    printf("OS hooks: without a mailbox, a panic goes through the watchdog and still counts\n");
    sim_reset();
    install_raw(MB_SLOT_B, "older", MB_VERSION(0, 9, 5), 1, 53, 20000);
    boot();
    app_confirms();                                                 // B good
    put_v2(MB_SLOT_A, "v1buf", MB_VERSION(1, 1, 0), 54, 0);         // A: a v1 buffer, no mailbox
    boot();
    app_confirms();
    got = MB_SLOT_A;
    for (int i = 0; i < MB_STRIKES_MAX && got == MB_SLOT_A; i++) {
        app_start(MB_SLOT_A);
        CHECK(app_reset(panic_fn, "no box") == SIM_REBOOT && sim.reset_cause == MB_RESET_WATCHDOG, "panic %d: a watchdog reset", i + 1);
        got = boot();
    }
    CHECK(got == MB_SLOT_B, "counted all the same: B after %d", MB_STRIKES_MAX);

    printf("OS hooks: slots, rollback on demand, entries\n");
    sim_reset();
    install_raw(MB_SLOT_B, "first", MB_VERSION(1, 0, 0), 1, 55, 20000);
    boot();
    app_confirms();
    put_v2(MB_SLOT_A, "second", MB_VERSION(1, 1, 0), 56, MB_HANDOFF_V2_SIZE);
    boot();
    app_confirms();                                                 // A active, B good
    app_start(MB_SLOT_A);
    mb_client_slot_t si;
    CHECK(mb_client_slot_info(MB_SLOT_A, &si) == MB_OK && si.present && si.running && si.active && si.state == MB_ST_GOOD &&
          si.version == MB_VERSION(1, 1, 0) && !strcmp(si.image_name, "second"), "slot a: running, active, good");
    CHECK(mb_client_slot_info(MB_SLOT_B, &si) == MB_OK && si.present && !si.running && !si.active && si.state == MB_ST_GOOD,
          "slot b: good, standing by");
    CHECK(mb_client_slot_info(MB_SLOT_GOLDEN, &si) == MB_OK && !si.present, "golden: empty");
    CHECK(mb_client_rollback() == MB_OK && log_now().active == MB_SLOT_B, "rollback: B is preferred");
    CHECK(boot() == MB_SLOT_B, "and boots");
    sim.self_slot = MB_SLOT_B;
    mb_client_init(&sim_port);
    CHECK(mb_client_set_active(MB_SLOT_A) == MB_OK && boot() == MB_SLOT_A, "and forward again");
    // a floor above both (security 1): neither may become the preferred one
    mb_bcl_t lb;
    mb_bcl_load(&lb, &sim_port);
    mb_bcl_rec_t r = lb.cur;
    r.min_security = 2;
    mb_bcl_commit(&lb, &r);
    sim.self_slot = MB_SLOT_B;
    mb_client_init(&sim_port);
    CHECK(mb_client_set_active(MB_SLOT_A) == MB_E_REFUSED, "an image below the rollback floor can't be made active");
    CHECK(mb_client_set_active(MB_SLOT_GOLDEN) == MB_E_BADARG, "golden isn't an A/B slot");
    save_cfg("default os\nentry os\n title The OS\n slot ab\nentry rescue\n title Rescue\n slot g\n");
    mb_client_entry_t ent[4];
    int ne = mb_client_entries(ent, 4);
    CHECK(ne == 2 && !strcmp(ent[0].name, "os") && ent[0].is_default && !strcmp(ent[1].title, "Rescue"), "the config's entries");
    CHECK(mb_client_poweroff("bye") == MB_E_UNSUPP, "power-off: this port can't");
    (void)ha;

    printf("OS hooks: mbctl, the shell commands\n");
    r.min_security = 1;                                             // (floor back where the images are)
    mb_bcl_load(&lb, &sim_port);
    r = lb.cur;
    r.min_security = 1;
    mb_bcl_commit(&lb, &r);
    CHECK(boot() == MB_SLOT_A, "A");
    app_start(MB_SLOT_A);
    ctl_out[0] = 0;
    char line[64];
    strcpy(line, "mbctl status");
    CHECK(mb_ctl_show(line) == MB_OK && strstr(ctl_out, "running   slot a: \"second\" 1.1.0") &&
          strstr(ctl_out, "handoff v2") && strstr(ctl_out, "through RAM"), "status (%s)", ctl_out);
    ctl_out[0] = 0;
    strcpy(line, "slots");
    CHECK(mb_ctl_show(line) == MB_OK && strstr(ctl_out, "a   >*  second") && strstr(ctl_out, "(empty)"),
          "slots (%s)", ctl_out);
    ctl_out[0] = 0;
    strcpy(line, "entries");
    CHECK(mb_ctl_show(line) == MB_OK && strstr(ctl_out, "* os") && strstr(ctl_out, "Rescue"), "entries");
    ctl_out[0] = 0;
    strcpy(line, "info");
    CHECK(mb_ctl_show(line) == MB_OK && strstr(ctl_out, "mailbox") && strstr(ctl_out, "control"), "info (%s)", ctl_out);
    ctl_out[0] = 0;
    strcpy(line, "next slot q");
    CHECK(mb_ctl_line(line, ctl_print, NULL) == MB_E_BADARG, "a slot that doesn't exist: refused");
    put_v2(MB_SLOT_GOLDEN, "rescue", MB_VERSION(1, 0, 0), 57, MB_HANDOFF_V2_SIZE);
    boot();                                                         // (golden seen and verified once)
    CHECK(sim.booted_slot == MB_SLOT_A, "A again");
    app_start(MB_SLOT_A);
    ctl_out[0] = 0;
    strcpy(line, "reboot entry rescue level=2 -- testing");
    CHECK(sim_guard(ctl_reboot_fn, line) == SIM_REBOOT && strstr(ctl_out, "next boot: entry rescue, through RAM"),
          "reboot entry rescue (%s)", ctl_out);
    sim.reset_cause = MB_RESET_SOFT;
    uint32_t w2 = writes();
    CHECK(boot() == MB_SLOT_GOLDEN && !strcmp(ram_handoff()->args, "level=2") && !strcmp(ram_handoff()->entry_name, "rescue"),
          "golden, as the rescue entry, with the args");
    CHECK(!strcmp(ram_handoff()->prev.msg, "testing") && ram_handoff()->prev.reason == MB_END_REBOOT, "and the reason given");
    CHECK(log_now().request == MB_REQ_NONE, "consumed (%u flash writes: the boot record)", (unsigned)(writes() - w2));
    ctl_out[0] = 0;
    strcpy(line, "frobnicate");
    CHECK(mb_ctl_line(line, ctl_print, NULL) == MB_E_BADARG && strstr(ctl_out, "unknown command"), "an unknown command: help");
    printf("OS hooks: a panic with a menu request: one strike, however often it decides\n");
    {
        sim_reset();
        put_v2(MB_SLOT_A, "pm", MB_VERSION(1, 0, 0), 59, MB_HANDOFF_V2_SIZE);
        boot();
        app_confirms();
        CHECK(boot() == MB_SLOT_A && log_now().strikes == 0, "A good, no strikes");
        app_start(MB_SLOT_A);
        mb_client_next(MB_CONTROL_MENU, NULL, NULL, MB_VIA_AUTO);
        app_reset(panic_fn, "panic, then the menu");
        sim.console = true;
        sim_input("c\rexit\r", 7);
        CHECK(boot() == MB_SLOT_A && strstr(sim.out, "MimiBoot"), "the menu, then exit: A");
        sim.console = false;
        CHECK(log_now().strikes == 1, "one strike, not one per decision (%u)", (unsigned)log_now().strikes);
        sim.reset_cause = MB_RESET_WATCHDOG;                        // the same through the watchdog: the menu by key
        sim.console = true;
        sim.button = true;
        sim_input("c\rexit\r", 7);
        boot();
        sim.button = false;
        sim.console = false;
        CHECK(log_now().strikes == 2, "a watchdog reset then the menu: one more (%u)", (unsigned)log_now().strikes);
        sim.reset_cause = MB_RESET_SOFT;
    }
    printf("OS hooks: the built-in recovery entry with args (golden only, as a fresh board)\n");
    {
        sim_reset();
        put_v2(MB_SLOT_GOLDEN, "g-only", MB_VERSION(1, 0, 0), 58, MB_HANDOFF_V2_SIZE);
        CHECK(boot() == MB_SLOT_GOLDEN, "golden boots");
        app_start(MB_SLOT_GOLDEN);
        CHECK(mb_client_next(MB_CONTROL_ENTRY, "recovery", "hop=2", MB_VIA_AUTO) == MB_VIA_MAILBOX, "queued in RAM");
        reboot_t rr = { MB_END_UPDATE, "hop" };
        app_reset(reboot_fn, &rr);
        CHECK(boot() == MB_SLOT_GOLDEN && !strcmp(ho->args, "hop=2") && ho->prev.reason == MB_END_UPDATE,
              "golden again, with the args (args [%s])", ho->args);
    }
}
#endif

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3 && !strcmp(argv[1], "--image")) return boot_file(argv[2]);
    printf("MimiBoot %s \"%s\" host tests\n", MIMIBOOT_VERSION, MIMIBOOT_CODENAME);
    test_hashes();
    test_crypto();
    test_empty();
    test_first_install();
    test_update_rollback();
    test_bad_hash();
    test_antirollback();
    test_golden();
    test_protected_floors();
    test_fault_hardening();
    test_requests();
    test_flash_mode();
    test_log_wear();
    test_config();
    test_entries();
    test_handoff();
    test_signatures();
    test_ecdsa_images();
    test_guard();
    test_ram_images();
    test_universal();
    test_console();
    test_recv();
    test_ota();
    test_client_install();
    test_revocation();
    test_encrypted();
    test_boot_record();
    test_power_cuts();
    test_two_stage();
    test_store_compaction();
    test_smp();
#if MB_FEAT_OS_HOOKS
    test_os_hooks();
#endif
#if MB_FEAT_LMS
    test_lms_images();
#endif
    test_control_ext();
    printf("\n%d checks, %d failed\n", checks + crypto_checks, fails + crypto_fails);
    return fails + crypto_fails ? 1 : 0;
}
