/*
 * MimiBoot - LMS signature verification (RFC 8554, NIST SP 800-208), MB_FEAT_LMS
 *
 * Single-level LMS with SHA-256 (n = m = 32) or SHA-256/192 (24), any tree
 * height 5..25 and Winternitz width 1/2/4/8. Hash-based: its security rests on
 * SHA-256 alone, so it stays sound against quantum computers (CNSA 2.0 lists it
 * for firmware signing). Verification only; signing is stateful and lives in
 * tools/mb_lms.py.
 *
 * The signature is read through a callback, in order, a few bytes at a time,
 * so a boot check streams it straight from the slot's header sector: about
 * 300 bytes of stack, no signature buffer. Cost: one SHA-256 block per chain
 * step, about p * (2^w - 1) / 2 on average (W4: ~560 blocks per check, W8:
 * ~4400), plus the Merkle path.
 */
#include "core/mimiboot.h"
#include <string.h>

mb_upload_sig_t mb_upload_sig;      /* (one byte without LMS: uploads refuse LMS images before using it) */

#if !MB_FEAT_LMS
int mb_lms_read_ram(void* ctx, uint32_t off, void* buf, size_t n) { (void)ctx; (void)off; (void)buf; (void)n; return MB_E_UNSUPP; }
size_t mb_lms_pub_len(const uint8_t* pub) { (void)pub; return 0; }
size_t mb_lms_sig_len(const uint8_t* pub) { (void)pub; return 0; }
uint32_t mb_lms_key_id(const uint8_t* pub) { (void)pub; return 0; }
bool mb_lms_verify(const void* msg, size_t msg_len, const uint8_t* pub, mb_lms_read_t rd, void* ctx, uint32_t sig_len) {
    (void)msg; (void)msg_len; (void)pub; (void)rd; (void)ctx; (void)sig_len;
    return false;
}
#else

#define D_PBLC 0x8080u
#define D_MESG 0x8181u
#define D_LEAF 0x8282u
#define D_INTR 0x8383u

typedef struct { uint8_t n, w, ls; uint16_t p; } ots_t;

static uint32_t be32(const uint8_t* b) { return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3]; }
static void put32(uint8_t* b, uint32_t v) { b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; }

// LMOTS typecodes 1..4: SHA-256 n = 32, w = 1/2/4/8; 5..8: SHA-256/192 n = 24 (SP 800-208)
static bool ots_params(uint32_t t, ots_t* o) {
    static const uint16_t p32[4] = {265, 133, 67, 34};
    static const uint8_t ls32[4] = {7, 6, 4, 0};
    static const uint16_t p24[4] = {200, 101, 51, 26};
    static const uint8_t ls24[4] = {8, 6, 4, 0};
    if (t >= 1 && t <= 4) { o->n = 32; o->w = (uint8_t)(1u << (t - 1)); o->p = p32[t - 1]; o->ls = ls32[t - 1]; return true; }
    if (t >= 5 && t <= 8) { o->n = 24; o->w = (uint8_t)(1u << (t - 5)); o->p = p24[t - 5]; o->ls = ls24[t - 5]; return true; }
    return false;
}

// LMS typecodes 5..9: m = 32, h = 5/10/15/20/25; 0x0A..0x0E: m = 24
static bool lms_params(uint32_t t, uint8_t* m, uint8_t* h) {
    if (t >= 5 && t <= 9) { *m = 32; *h = (uint8_t)(5 * (t - 4)); return true; }
    if (t >= 0x0A && t <= 0x0E) { *m = 24; *h = (uint8_t)(5 * (t - 9)); return true; }
    return false;
}

size_t mb_lms_sig_len(const uint8_t* pub) {
    uint8_t m, h;
    ots_t o;
    if (!lms_params(be32(pub), &m, &h) || !ots_params(be32(pub + 4), &o) || o.n != m) return 0;
    return 4 + (4 + (size_t)o.n + (size_t)o.p * o.n) + 4 + (size_t)h * m;
}

size_t mb_lms_pub_len(const uint8_t* pub) {
    uint8_t m, h;
    return lms_params(be32(pub), &m, &h) ? 24u + m : 0;
}

uint32_t mb_lms_key_id(const uint8_t* pub) {
    // the first 4 bytes of I (the type codes in front are the same for every key)
    return (uint32_t)pub[8] | (uint32_t)pub[9] << 8 | (uint32_t)pub[10] << 16 | (uint32_t)pub[11] << 24;
}

static unsigned coef(const uint8_t* s, unsigned i, unsigned w) {
    return (s[i * w / 8] >> (8 - (w * (i % (8 / w)) + w))) & ((1u << w) - 1);
}

bool mb_lms_verify(const void* msg, size_t msg_len, const uint8_t* pub, mb_lms_read_t rd, void* ctx, uint32_t sig_len) {
    uint8_t m, h;
    ots_t o;
    uint32_t lt = be32(pub), ot = be32(pub + 4);
    if (!lms_params(lt, &m, &h) || !ots_params(ot, &o) || o.n != m) return false;
    if (sig_len != mb_lms_sig_len(pub)) return false;
    const uint8_t* I = pub + 8;
    const uint8_t* T1 = pub + 24;
    const unsigned n = o.n, w = o.w, top = (1u << w) - 1;
    // blk = I || u32(q) || u16(i) || u8(j) || tmp[n]: one chain step, one SHA-256 block
    uint8_t blk[16 + 4 + 2 + 1 + 32], Q[32 + 2], tmp[32], head[4];
    uint32_t at = 0;
    mb_sha256_t s;

    if (rd(ctx, at, head, 4) != MB_OK) return false;
    at += 4;
    uint32_t q = be32(head);
    if (q >= (1u << h)) return false;
    if (rd(ctx, at, head, 4) != MB_OK || be32(head) != ot) return false;
    at += 4;
    memcpy(blk, I, 16);
    put32(blk + 16, q);

    // Q = H(I || q || D_MESG || C || message), then the checksum after it
    if (rd(ctx, at, tmp, n) != MB_OK) return false;     // C
    at += n;
    mb_sha256_init(&s);
    mb_sha256_update(&s, blk, 20);
    uint8_t d[2] = {(uint8_t)(D_MESG >> 8), (uint8_t)D_MESG};
    mb_sha256_update(&s, d, 2);
    mb_sha256_update(&s, tmp, n);
    mb_sha256_update(&s, msg, msg_len);
    mb_sha256_final(&s, Q);         // (only the first n bytes count)
    unsigned sum = 0;
    for (unsigned i = 0; i < 8 * n / w; i++) sum += top - coef(Q, i, w);
    sum <<= o.ls;
    Q[n] = (uint8_t)(sum >> 8);
    Q[n + 1] = (uint8_t)sum;

    // Kc = H(I || q || D_PBLC || z[0] || ... || z[p-1]), each z the end of a chain
    mb_sha256_t kc;
    mb_sha256_init(&kc);
    mb_sha256_update(&kc, blk, 20);
    d[0] = (uint8_t)(D_PBLC >> 8);
    d[1] = (uint8_t)D_PBLC;
    mb_sha256_update(&kc, d, 2);
    for (unsigned i = 0; i < o.p; i++) {
        if (rd(ctx, at, blk + 23, n) != MB_OK) return false;     // y[i]
        at += n;
        blk[20] = (uint8_t)(i >> 8);
        blk[21] = (uint8_t)i;
        for (unsigned j = coef(Q, i, w); j < top; j++) {
            blk[22] = (uint8_t)j;
            mb_sha256_init(&s);
            mb_sha256_update(&s, blk, 23 + n);
            mb_sha256_final(&s, tmp);
            memcpy(blk + 23, tmp, n);
        }
        mb_sha256_update(&kc, blk + 23, n);
    }
    mb_sha256_final(&kc, tmp);      // Kc

    if (rd(ctx, at, head, 4) != MB_OK || be32(head) != lt) return false;
    at += 4;
    // up the tree: leaf node 2^h + q, then h path nodes
    uint32_t node = (1u << h) + q;
    uint8_t nb[16 + 4 + 2];
    memcpy(nb, I, 16);
    put32(nb + 16, node);
    nb[20] = (uint8_t)(D_LEAF >> 8);
    nb[21] = (uint8_t)D_LEAF;
    mb_sha256_init(&s);
    mb_sha256_update(&s, nb, 22);
    mb_sha256_update(&s, tmp, m);
    mb_sha256_final(&s, tmp);
    uint8_t sib[32];
    nb[20] = (uint8_t)(D_INTR >> 8);
    nb[21] = (uint8_t)D_INTR;
    for (unsigned i = 0; i < h; i++) {
        if (rd(ctx, at, sib, m) != MB_OK) return false;
        at += m;
        put32(nb + 16, node >> 1);
        mb_sha256_init(&s);
        mb_sha256_update(&s, nb, 22);
        mb_sha256_update(&s, (node & 1) ? sib : tmp, m);
        mb_sha256_update(&s, (node & 1) ? tmp : sib, m);
        mb_sha256_final(&s, tmp);
        node >>= 1;
    }
    if (at != sig_len) return false;
    // compared twice, independently (fault injection): one skipped branch doesn't pass a forgery
    if (mb_ct_diff(tmp, T1, m) != 0) return false;
    return mb_ct_diff(T1, tmp, m) == 0;
}

int mb_lms_read_ram(void* ctx, uint32_t off, void* buf, size_t n) {
    const mb_lms_ram_t* r = ctx;
    if (off > r->len || n > r->len - off) return MB_E_CORRUPT;
    memcpy(buf, r->sig + off, n);
    return MB_OK;
}

#endif /* MB_FEAT_LMS */
