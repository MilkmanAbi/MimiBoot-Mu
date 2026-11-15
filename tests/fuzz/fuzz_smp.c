/*
 * Fuzz target: SMP (mcumgr) on the console, core/mb_smp.c.
 *
 * Input byte 0 picks the mode: bit 0 raw (the bytes go to the console as they
 * are: the line and base64 decoder), else each [len16 LE][message] piece is
 * wrapped as a valid SMP serial packet (length, CRC, base64 lines) so the
 * fuzzer reaches the CBOR parser and the handlers; bit 1 a locked console,
 * bit 2 two-stage layout. Flash is the simulator's (uploads write it).
 */
#include "tests/sim_port.h"
#include "tests/gen_signed.h"
#include <string.h>

static uint8_t script[1 << 18];
static size_t sn;
static mb_bcl_t log_;
static bool locked;

static void put(uint8_t b) { if (sn < sizeof(script)) script[sn++] = b; }

static uint16_t crc16(const uint8_t* d, size_t n) {
    uint16_t c = 0;
    while (n--) { c ^= (uint16_t)(*d++ << 8); for (int i = 0; i < 8; i++) c = c & 0x8000 ? (uint16_t)(c << 1 ^ 0x1021) : (uint16_t)(c << 1); }
    return c;
}

static void packet(const uint8_t* m, size_t n) {
    static uint8_t raw[4200];
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (n > 4096) n = 4096;
    raw[0] = (uint8_t)((n + 2) >> 8);
    raw[1] = (uint8_t)(n + 2);
    memcpy(raw + 2, m, n);
    uint16_t c = crc16(m, n);
    raw[2 + n] = (uint8_t)(c >> 8);
    raw[3 + n] = (uint8_t)c;
    size_t len = n + 4, col = 0;
    bool first = true;
    for (size_t i = 0; i < len; i += 3) {
        if (col == 0) { put(first ? 0x06 : 0x04); put(first ? 0x09 : 0x14); first = false; }
        uint32_t v = (uint32_t)raw[i] << 16 | (i + 1 < len ? (uint32_t)raw[i + 1] << 8 : 0) | (i + 2 < len ? raw[i + 2] : 0);
        put((uint8_t)b64[v >> 18 & 63]);
        put((uint8_t)b64[v >> 12 & 63]);
        put(i + 1 < len ? (uint8_t)b64[v >> 6 & 63] : '=');
        put(i + 2 < len ? (uint8_t)b64[v & 63] : '=');
        col += 4;
        if (col >= 124) { put('\n'); col = 0; }
    }
    if (col) put('\n');
}

static void run(void* ctx) {
    (void)ctx;
    for (;;) {
        int c = sim_port.getc(10);
        if (c == 0x06 || c == 0x04) {
            int d = sim_port.getc(10);
            mb_smp_frame(&sim_port, &log_, locked, c == 0x06 && d == 0x09);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) {
    if (n < 1) return 0;
    static bool once;
    if (!once) { sim_reset(); once = true; }
    memset(sim_flash + 0x10000, 0xFF, 0x4000);         // log + config: fresh each run (slots keep what uploads wrote)
    sim.fault_slot = -1;
    sim.stage1_slot = -1;
    sim_two_stage((d[0] & 4) != 0, NULL);
    locked = (d[0] & 2) != 0;
    // bit 3: the board has a decryption key (the host tests' one, so the encrypted uploads
    // in tests/gen_smp.h, which seed this, really decrypt)
    static uint8_t dev_key[32];
    static bool keyed;
    if (!keyed) {
        mb_sha256_t s;
        mb_sha256_init(&s);
        mb_sha256_update(&s, "MimiBoot test encryption key", 28);
        mb_sha256_final(&s, dev_key);
        keyed = true;
    }
    sim_port.enc_key = (d[0] & 8) ? dev_key : NULL;
    sim_lms((d[0] & 16) ? lms_public : NULL, NULL);     // bit 4: the board has gen_signed's LMS key
    mb_bcl_load(&log_, &sim_port);
    sn = 0;
    if (d[0] & 1) {
        for (size_t i = 1; i < n; i++) put(d[i]);
    } else {
        size_t i = 1;
        while (i + 2 <= n) {
            size_t len = d[i] | (size_t)d[i + 1] << 8;
            i += 2;
            if (len > n - i) len = n - i;
            packet(d + i, len);
            i += len;
        }
    }
    sim_input(script, sn);
    sim_guard(run, NULL);
    sim_two_stage(false, NULL);
    return 0;
}
