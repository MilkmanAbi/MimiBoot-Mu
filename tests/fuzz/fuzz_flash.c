/*
 * Fuzz target: whatever is in flash, the boot decision must not crash, read
 * out of bounds or boot something it shouldn't parse. The input fills, in
 * order: the boot log, the config copies, the start of slots a, b and golden
 * (header sector + some payload: MimiBoot headers, MCUboot headers and TLVs),
 * and the protected store; what it doesn't reach stays erased.
 * Byte 0: bit 0 fix up the CRCs of MimiBoot headers and log records (so the
 * fuzzer gets past them), bit 1 signatures required, bit 2 two-stage layout
 * (slots c/d become stage-1 copies, stage 0's choice runs too), bit 3 the
 * store as two units, then a floor raise and a counted entry (which compact a
 * full unit, whatever the fuzzer put in it), bit 5 the RAM mailbox: the first
 * bytes go into slot a's handoff buffer as a mailbox (magic, size, image id and
 * CRC made right), slot a counts as the image that ran last, and the boot reads
 * it before deciding (its request goes through the control service's checks).
 */
#include "tests/sim_port.h"
#include "tests/gen_signed.h"
#include <stddef.h>
#include <string.h>

static const struct { uint32_t off, len; } region[] = {
    { 0x010000, 0x2000 },       /* log0, log1 */
    { 0x012000, 0x2000 },       /* cfg0, cfg1 */
    { 0x020000, 0x2000 },       /* slot a: header sector + 4 KB of payload */
    { 0x080000, 0x2000 },       /* slot b */
    { 0x0E0000, 0x2000 },       /* golden */
    { 0x140000, 0x2000 },       /* c (two-stage: s1a) */
    { 0x00F000, 0x1000 },       /* the protected store (one unit, or two of 2 KB) */
};

static void fix_crcs(void) {
    for (size_t r = 2; r < 6; r++) {
        mb_image_hdr_t* h = (mb_image_hdr_t*)(sim_flash + region[r].off);
        if (h->magic != MB_IMG_MAGIC) continue;
        h->payload_size %= 0x3000;          // small payloads: hashing doesn't eat the fuzzer's time
        mb_image_seal(h);
    }
    for (uint32_t o = 0x10000; o < 0x12000; o += MB_BCL_REC_SIZE) {
        mb_bcl_rec_t* rec = (mb_bcl_rec_t*)(sim_flash + o);
        if (rec->magic == MB_BCL_REC_MAGIC) rec->crc = mb_crc32(0, rec, offsetof(mb_bcl_rec_t, crc));
    }
}

#define MBOX_ADDR (SIM_RAM_BASE + 0x40000)
static bool mailbox;

static void decide(void* ctx) {
    (void)ctx;
    static mb_bcl_t log;
    static mb_config_t cfg;
    static mb_slot_info_t info[MB_MAX_SLOTS];
    static mb_plan_t plan;
    mb_bcl_load(&log, &sim_port);
    mb_config_load(&sim_port, &cfg);
    if (mailbox) {
        mb_bcl_rec_t r = log.cur;
        r.last_slot = MB_SLOT_A;
        mb_mailbox_take(&sim_port, &r);
    }
    mb_decide(&sim_port, &log, &cfg, info, 0, &plan);
    if (plan.choice.slot != MB_SLOT_NONE) mb_boot(&sim_port, &log, &cfg, info, &plan);   // launches: longjmps out
}

int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) {
    if (n < 1) return 0;
    static bool once;
    if (!once) { sim_reset(); once = true; }
    for (size_t r = 0; r < sizeof(region) / sizeof(region[0]); r++)      // only what this target writes
        memset(sim_flash + region[r].off, 0xFF, region[r].len);
    sim.fault_slot = -1;
    sim.stage1_slot = -1;
    sim.reset_cause = MB_RESET_POWER;
    sim.out_len = 0;
    sim_two_stage((d[0] & 4) != 0, NULL);
    sim_store_two((d[0] & 8) != 0);
    sim_port.require_signature = (d[0] & 2) != 0;
    sim_lms((d[0] & 16) ? lms_public : NULL, NULL);     // bit 4: LMS keys (signatures read from slot header sectors)
    size_t i = 1;
    mailbox = (d[0] & 32) != 0;
    mb_mailbox_t m;
    memset(&m, 0, sizeof(m));
    if (mailbox) {                                      // the mailbox first, then the flash regions
        size_t k = n - i < sizeof(m) ? n - i : sizeof(m);
        memcpy(&m, d + i, k);
        i += k;
    }
    for (size_t r = 0; r < sizeof(region) / sizeof(region[0]) && i < n; r++) {
        size_t k = n - i < region[r].len ? n - i : region[r].len;
        memcpy(sim_flash + region[r].off, d + i, k);
        i += k;
    }
    if (d[0] & 1) fix_crcs();
    if (mailbox) {
        mb_image_hdr_t* h = (mb_image_hdr_t*)(sim_flash + region[2].off);
        h->magic = MB_IMG_MAGIC;
        h->hdr_version = MB_IMG_HDR_VERSION;
        h->hdr_size = MB_IMG_HDR_SIZE;
        h->payload_offset = MB_IMG_PAYLOAD_OFF;
        h->payload_size = h->payload_size % 0x3000 + 1;
        h->handoff_addr = MBOX_ADDR;
        h->handoff_size = MB_HANDOFF_V2_SIZE;
        mb_image_seal(h);
        m.magic = MB_MAILBOX_MAGIC;
        m.version = MB_MAILBOX_VERSION;
        m.size = sizeof(m);
        m.image_id = mb_image_id(h);
        m.crc = mb_crc32(0, &m, offsetof(mb_mailbox_t, crc));
        memcpy(sim_ram + (MBOX_ADDR - SIM_RAM_BASE), &m, sizeof(m));
    }
    if (d[0] & 4) {
        mb_stage0_choice_t c;
        mb_stage0_choose(&sim_port, &c);
    }
    uint32_t fl[MB_FLOOR_COUNT];
    mb_floor_get(&sim_port, fl);
    if (d[0] & 8) {
        mb_floor_raise(&sim_port, MB_FLOOR_SECURITY, fl[MB_FLOOR_SECURITY] + 1);
        mb_store_append(&sim_port, MB_STORE_S1_ATTEMPT, 0x12345678u);
        uint32_t after[MB_FLOOR_COUNT];
        mb_floor_get(&sim_port, after);
        for (int w = 0; w < MB_FLOOR_COUNT; w++)     // a compaction never lowers a floor
            if (after[w] < fl[w]) __builtin_trap();
    }
    sim_guard(decide, NULL);
    sim_two_stage(false, NULL);
    sim_store_two(false);
    sim_port.require_signature = false;
    return 0;
}
