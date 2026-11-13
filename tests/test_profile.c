/*
 * Smoke test for one feature profile (tests/test_profiles.py builds this once
 * per profile with a different mb_config.h): whatever is switched off, the
 * core must still pick and boot what it can.
 */
#include "tests/sim_port.h"
#include <stdio.h>
#include <string.h>

static int fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

__attribute__((unused)) static void payload(uint8_t* b, uint32_t n, uint32_t seed) {
    uint32_t x = seed * 2654435761u + 1;
    for (uint32_t i = 0; i < n; i++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; b[i] = (uint8_t)x; }
}

#if MB_FEAT_IMG_NATIVE
static void put_native(int slot, uint32_t seed, uint32_t version) {
    static uint8_t body[3000];
    payload(body, sizeof body, seed);
    mb_image_hdr_t h;
    memset(&h, 0, sizeof h);
    h.magic = MB_IMG_MAGIC; h.hdr_version = MB_IMG_HDR_VERSION; h.hdr_size = MB_IMG_HDR_SIZE;
    h.load_type = MB_LOAD_CHAIN; h.payload_offset = MB_IMG_PAYLOAD_OFF; h.payload_size = sizeof body;
    h.version = version; h.arch = MB_ARCH_ARM;
    memcpy(h.name, "profile", 8); memcpy(h.target, "sim", 4);
    mb_sha256_t s; mb_sha256_init(&s); mb_sha256_update(&s, body, sizeof body); mb_sha256_final(&s, h.sha256);
    mb_image_seal(&h);
    CHECK(mb_slot_erase(&sim_port, slot, sizeof body) == MB_OK, "erase");
    CHECK(mb_slot_write(&sim_port, slot, 0, body, sizeof body) == MB_OK, "write");
    CHECK(mb_slot_write_header(&sim_port, slot, &h) == MB_OK, "header");
}
#endif

#if MB_FEAT_IMG_MCUBOOT
// A minimal MCUboot image: 0x200 header, body, TLV info + SHA256 TLV.
static void put_mcuboot(int slot, uint32_t seed) {
    uint32_t off = sim_port.layout->slot[slot].offset;
    uint8_t img[0x200 + 1024 + 4 + 36];
    memset(img, 0, sizeof img);
    uint32_t magic = 0x96f3b83du, hs = 0x200, isz = 1024;
    memcpy(img, &magic, 4);
    img[8] = (uint8_t)hs; img[9] = (uint8_t)(hs >> 8);
    memcpy(img + 12, &isz, 4);
    img[20] = 1; img[21] = 2; img[22] = 3;          // v1.2.3
    payload(img + hs, isz, seed);
    uint8_t* t = img + hs + isz;
    t[0] = 0x07; t[1] = 0x69; t[2] = 40; t[3] = 0;  // info 0x6907, total 4 + 36
    t[4] = 0x10; t[5] = 0; t[6] = 32; t[7] = 0;     // SHA256
    mb_sha256_t s; mb_sha256_init(&s); mb_sha256_update(&s, img, hs + isz); mb_sha256_final(&s, t + 8);
    memset(sim_flash + off, 0xFF, 0x2000);
    memcpy(sim_flash + off, img, sizeof img);
}
#endif

int main(void) {
    printf("profile:%s%s%s%s%s%s%s\n", MB_FEAT_CONSOLE ? " console" : "", MB_FEAT_SIGNATURES ? " sig" : "",
           MB_FEAT_CFG_FILE ? " cfg" : "", MB_FEAT_CONTROL ? " control" : "", MB_FEAT_IMG_NATIVE ? " native" : "",
           MB_FEAT_IMG_MCUBOOT ? " mcuboot" : "", MB_FEAT_IMG_RAW ? " raw" : "");

    // nothing installed: no boot, and the core neither crashes nor loops forever
    sim_reset();
    sim_outcome_t o = sim_power_on();
    CHECK(o != SIM_BOOTED && o != SIM_RETURNED, "empty flash booted something (%d)", o);

#if MB_FEAT_IMG_NATIVE
    // golden only: boots without a trial; then an A/B update is tried first
    sim_reset();
    put_native(MB_SLOT_GOLDEN, 7, MB_VERSION(1, 0, 0));
    CHECK(sim_power_on() == SIM_BOOTED && sim.booted_slot == MB_SLOT_GOLDEN, "golden (slot %d)", sim.booted_slot);
    put_native(MB_SLOT_A, 9, MB_VERSION(2, 0, 0));
    CHECK(sim_power_on() == SIM_BOOTED && sim.booted_slot == MB_SLOT_A, "update in A (slot %d)", sim.booted_slot);
    // never confirmed: with trials it is rolled back after MB_DEFAULT_TRIES boots,
    // without them it stays (firmware that doesn't know about MimiBoot)
    for (int i = 0; i < MB_DEFAULT_TRIES + 1; i++) sim_power_on();
    CHECK(sim.outcome == SIM_BOOTED && sim.booted_slot == (MB_FEAT_AB_TRIAL ? MB_SLOT_GOLDEN : MB_SLOT_A),
          "unconfirmed update after %d boots: slot %d", MB_DEFAULT_TRIES + 1, sim.booted_slot);
    if (!MB_FEAT_AB_TRIAL) put_native(MB_SLOT_A, 9, MB_VERSION(2, 0, 0));    // same image: no-op rewrite
    // corrupt the payload of an image that has already booted
    sim_flash[sim_port.layout->slot[MB_SLOT_A].offset + MB_IMG_PAYLOAD_OFF + 10] ^= 1;
#if MB_BOOT_VERIFY == MB_BOOT_VERIFY_EVERY || MB_FEAT_AB_TRIAL
    CHECK(sim_power_on() == SIM_BOOTED && sim.booted_slot == MB_SLOT_GOLDEN, "corrupt A skipped (slot %d)", sim.booted_slot);
#else
    // BOOT_VERIFY once / never: the documented trade-off - an image already
    // checked (or never checked) boots on its header alone
    CHECK(sim_power_on() == SIM_BOOTED && sim.booted_slot == MB_SLOT_A, "header-only boot of the known A (slot %d)", sim.booted_slot);
#endif
#if MB_BOOT_VERIFY != MB_BOOT_VERIFY_EVERY
    // a *new* image that is corrupt before its first boot
    sim_reset();
    put_native(MB_SLOT_GOLDEN, 7, MB_VERSION(1, 0, 0));
    put_native(MB_SLOT_A, 21, MB_VERSION(3, 0, 0));
    sim_flash[sim_port.layout->slot[MB_SLOT_A].offset + MB_IMG_PAYLOAD_OFF + 99] ^= 1;
    o = sim_power_on();
#if MB_BOOT_VERIFY == MB_BOOT_VERIFY_ONCE
    CHECK(o == SIM_BOOTED && sim.booted_slot == MB_SLOT_GOLDEN, "once: the first boot hashes, corrupt new A refused (slot %d)", sim.booted_slot);
    mb_bcl_t lg;
    mb_bcl_load(&lg, &sim_port);
    CHECK(lg.cur.slot[MB_SLOT_GOLDEN].flags & MB_SF_HASH_OK, "once: golden's hash recorded as checked");
    CHECK(lg.cur.slot[MB_SLOT_A].state == MB_ST_BAD, "once: the corrupt new A is marked bad");
#else
    CHECK(o == SIM_BOOTED && sim.booted_slot == MB_SLOT_A, "never: header checks only (slot %d)", sim.booted_slot);
#endif
#endif
#endif

#if MB_FEAT_IMG_MCUBOOT
    sim_reset();
    put_mcuboot(MB_SLOT_A, 3);
    CHECK(sim_power_on() == SIM_BOOTED && sim.booted_slot == MB_SLOT_A, "mcuboot in A (slot %d)", sim.booted_slot);
    CHECK(sim.booted_hdr.payload_offset == 0x200 && sim.booted_hdr.version == MB_VERSION(1, 2, 3), "mcuboot hdr");
    sim_flash[sim_port.layout->slot[MB_SLOT_A].offset + 0x200 + 5] ^= 0x80;     // flip a code byte
    o = sim_power_on();                             // same flash, same log: the trial image is re-hashed
#if MB_BOOT_VERIFY == MB_BOOT_VERIFY_EVERY
    CHECK(o != SIM_BOOTED || sim.booted_slot != MB_SLOT_A, "corrupt mcuboot image booted");
#else
    CHECK(o == SIM_BOOTED && sim.booted_slot == MB_SLOT_A, "hash checked once: known mcuboot image boots on its header");
#endif
#endif

#if MB_FEAT_IMG_RAW
    sim_reset();
    uint32_t vt[2] = { 0x20008000u, 0x00040101u };
    memcpy(sim_flash + sim_port.layout->slot[MB_SLOT_GOLDEN].offset, vt, sizeof vt);
    CHECK(sim_power_on() == SIM_BOOTED && sim.booted_slot == MB_SLOT_GOLDEN, "raw golden (slot %d)", sim.booted_slot);
#endif

    printf("%d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
