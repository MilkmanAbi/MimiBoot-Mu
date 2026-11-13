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

#include "tests/test_night.inc"

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
    test_requests();
    test_flash_mode();
    test_log_wear();
    test_config();
    test_entries();
    test_handoff();
    test_signatures();
    test_guard();
    test_ram_images();
    test_universal();
    test_console();
    test_recv();
    test_ota();
    test_power_cuts();
    test_night();
    printf("\n%d checks, %d failed\n", checks + crypto_checks, fails + crypto_fails);
    return fails + crypto_fails ? 1 : 0;
}
