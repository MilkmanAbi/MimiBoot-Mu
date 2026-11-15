/*
 * MimiBoot host tests: the SMP replies in the simulator's console output,
 * decoded (base64, length, CRC-16/XMODEM) into header + CBOR. Shared by
 * test_mimiboot.c and test_auth.c.
 */
#ifndef MIMIBOOT_TEST_SMP_RX_H
#define MIMIBOOT_TEST_SMP_RX_H

#include "tests/sim_port.h"
#include <string.h>

typedef struct { uint8_t m[1100]; uint32_t n; } smp_msg_t;
static smp_msg_t smp_rx[48];
static int smp_rx_n;

static int smp_b64v(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
}

static uint16_t smp_xmodem(const uint8_t* d, size_t n) {
    uint16_t c = 0;
    while (n--) {
        c ^= (uint16_t)(*d++ << 8);
        for (int i = 0; i < 8; i++) c = c & 0x8000 ? (uint16_t)(c << 1 ^ 0x1021) : (uint16_t)(c << 1);
    }
    return c;
}

// every reply packet in sim.out, CRC checked, as header + CBOR
static void smp_collect(void) {
    static uint8_t buf[1200];
    uint32_t bn = 0;
    smp_rx_n = 0;
    for (size_t i = 0; i + 1 < sim.out_len; i++) {
        bool first = sim.out[i] == 0x06 && sim.out[i + 1] == 0x09, cont = sim.out[i] == 0x04 && sim.out[i + 1] == 0x14;
        if (!first && !cont) continue;
        if (first) bn = 0;
        uint32_t acc = 0;
        int bits = 0;
        for (i += 2; i < sim.out_len && sim.out[i] != '\n'; i++) {
            int v = smp_b64v((unsigned char)sim.out[i]);
            if (v < 0) { bits = 0; continue; }
            acc = acc << 6 | (uint32_t)v;
            bits += 6;
            if (bits >= 8) { bits -= 8; if (bn < sizeof(buf)) buf[bn++] = (uint8_t)(acc >> bits); }
        }
        uint32_t want = bn >= 2 ? ((uint32_t)buf[0] << 8 | buf[1]) + 2 : 0;
        if (bn >= 12 && bn == want && !smp_xmodem(buf + 2, want - 2) && smp_rx_n < 48) {
            memcpy(smp_rx[smp_rx_n].m, buf + 2, want - 4);
            smp_rx[smp_rx_n++].n = want - 4;
        }
    }
}

// does reply k's CBOR contain these bytes?
static bool smp_has(int k, const char* pat, size_t n) {
    if (k < 0 || k >= smp_rx_n) return false;
    for (uint32_t i = 8; i + n <= smp_rx[k].n; i++)
        if (!memcmp(smp_rx[k].m + i, pat, n)) return true;
    return false;
}
#define SMP_HAS(k, lit) smp_has(k, lit, sizeof(lit) - 1)

#endif
