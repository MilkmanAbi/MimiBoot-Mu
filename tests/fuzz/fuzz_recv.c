/*
 * Fuzz target: the console upload protocol (core/mb_recv.c) into a flash slot.
 * The first 256 bytes become the image header (magic, version, size and CRC
 * made right, so the fuzzer gets past them); the rest is a list of
 * [off32][len16][data] frames, each sent with a correct CRC (byte 0 bit 0
 * clear) or as given.
 */
#include "tests/sim_port.h"
#include "tests/gen_signed.h"
#include <string.h>

static uint8_t script[1 << 18];
static size_t sn;
static void put(uint8_t b) { if (sn < sizeof(script)) script[sn++] = b; }
static void put32(uint32_t v) { for (int i = 0; i < 4; i++) put((uint8_t)(v >> (8 * i))); }

static int r_getc(void* io, uint32_t ms) { (void)io; return sim_port.getc(ms); }
static void r_puts(void* io, const char* s) { (void)io; sim_port.write(s, strlen(s)); }

static const uint8_t dev_key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

static void run(void* ctx) {
    mb_slot_sink_t* sink = ctx;
    mb_recv_t r = { .ctx = sink, .getc = r_getc, .puts = r_puts, .max_frame = 1024, .where = "b",
                    .enc_key = sim_port.enc_key,
                    .begin = mb_sink_slot_begin, .data = mb_sink_slot_data, .end = mb_sink_slot_end };
    mb_recv(&r, NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) {
    if (n < 1 + sizeof(mb_image_hdr_t)) return 0;
    static bool once;
    if (!once) { sim_reset(); once = true; }
    bool raw_crc = d[0] & 1;
    sim_port.require_signature = (d[0] & 2) != 0;
    mb_image_hdr_t h;
    memcpy(&h, d + 1, sizeof(h));
    h.magic = MB_IMG_MAGIC;
    h.hdr_version = MB_IMG_HDR_VERSION;
    h.hdr_size = MB_IMG_HDR_SIZE;
    h.payload_offset = MB_IMG_PAYLOAD_OFF;
    h.payload_size %= 0x50000;                          // inside slot b
    memcpy(h.target, "sim", 4);
    // byte 0 bit 2: an encrypted image (the board has a key; bit 3: or not), envelope from the input
    bool encrypted = (d[0] & 4) != 0;
    h.flags = encrypted ? (h.flags | MB_IMG_F_ENCRYPTED) : (h.flags & ~(uint32_t)MB_IMG_F_ENCRYPTED);
    sim_port.enc_key = (d[0] & 8) ? NULL : dev_key;
    // bit 4: LMS-signed (an 'S' frame from the input); bit 5: the board has an LMS key
    bool lms = (d[0] & 16) != 0;
    h.flags = lms ? (h.flags | MB_IMG_F_LMS) : (h.flags & ~(uint32_t)MB_IMG_F_LMS);
    sim_lms((d[0] & 32) ? lms_public : NULL, NULL);
    mb_image_seal(&h);
    sn = 0;
    put('H');
    for (size_t i = 0; i < sizeof(h); i++) put(((const uint8_t*)&h)[i]);
    size_t i = 1 + sizeof(h);
    if (encrypted && i < n) {                           // 'K' len envelope crc
        size_t len = d[i++] % (MB_ENC_ENV_MAX + 8);
        if (len > n - i) len = n - i;
        put('K');
        put((uint8_t)len);
        put(0);
        for (size_t k = 0; k < len; k++) put(d[i + k]);
        put32(raw_crc ? 0 : mb_crc32(0, d + i, len));
        i += len;
    }
    if (lms && i + 2 <= n) {                            // 'S' len signature crc
        size_t len = (size_t)(d[i] | d[i + 1] << 8) % (MB_LMS_SIG_MAX + 64);
        i += 2;
        if (len > n - i) len = n - i;
        put('S');
        put((uint8_t)len);
        put((uint8_t)(len >> 8));
        for (size_t k = 0; k < len; k++) put(d[i + k]);
        put32(raw_crc ? 0 : mb_crc32(0, d + i, len));
        i += len;
    }
    while (i + 6 <= n) {
        uint32_t off = (uint32_t)d[i] | (uint32_t)d[i + 1] << 8 | (uint32_t)d[i + 2] << 16 | (uint32_t)d[i + 3] << 24;
        size_t len = (size_t)(d[i + 4] | d[i + 5] << 8);
        i += 6;
        if (len > n - i) len = n - i;
        put('D');
        put32(off % (h.payload_size + 1));
        put((uint8_t)len);
        put((uint8_t)(len >> 8));
        for (size_t k = 0; k < len; k++) put(d[i + k]);
        put32(raw_crc ? 0 : mb_crc32(0, d + i, len));
        i += len;
    }
    put('E');
    sim_input(script, sn);
    mb_slot_sink_t sink = { .p = &sim_port, .slot = MB_SLOT_B };
    sim_guard(run, &sink);
    sim_port.require_signature = false;
    sim_port.enc_key = NULL;
    return 0;
}
