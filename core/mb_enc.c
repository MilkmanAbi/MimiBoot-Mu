/*
 * MimiBoot - encrypted images: AES-CTR, HMAC-SHA256, HKDF, the key envelope
 * (see mimiboot.h for the scheme; X25519 is in mb_ed25519.c, next to the
 * field arithmetic it shares with Ed25519)
 *
 * AES is the constant-time bitsliced implementation from BearSSL ("aes_ct",
 * Thomas Pornin, MIT licence, notice below), cut down to encryption, which is
 * all CTR mode needs. No tables are indexed by secret data, so the key and the
 * keystream don't leak through cache or flash-accelerator timing. The S-box
 * is Boyar and Peralta's circuit.
 *
 * ----
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ----
 */
#include "core/mimiboot.h"
#include <string.h>

mb_aes_t mb_upload_key;

#if MB_FEAT_ENC

static void wipe(void* p, size_t n) {
    volatile uint8_t* v = p;
    while (n--) *v++ = 0;
}

static uint32_t dec32le(const uint8_t* b) { return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24; }
static void enc32le(uint8_t* b, uint32_t v) { b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24); }

// ---------------------------------------------------------------------------
// AES (BearSSL aes_ct: two blocks at a time, bitsliced over eight words)
// ---------------------------------------------------------------------------

static void sbox(uint32_t* q) {
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t y1, y2, y3, y4, y5, y6, y7, y8, y9;
    uint32_t y10, y11, y12, y13, y14, y15, y16, y17, y18, y19;
    uint32_t y20, y21;
    uint32_t z0, z1, z2, z3, z4, z5, z6, z7, z8, z9;
    uint32_t z10, z11, z12, z13, z14, z15, z16, z17;
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t t10, t11, t12, t13, t14, t15, t16, t17, t18, t19;
    uint32_t t20, t21, t22, t23, t24, t25, t26, t27, t28, t29;
    uint32_t t30, t31, t32, t33, t34, t35, t36, t37, t38, t39;
    uint32_t t40, t41, t42, t43, t44, t45, t46, t47, t48, t49;
    uint32_t t50, t51, t52, t53, t54, t55, t56, t57, t58, t59;
    uint32_t t60, t61, t62, t63, t64, t65, t66, t67;
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7;

    x0 = q[7]; x1 = q[6]; x2 = q[5]; x3 = q[4];
    x4 = q[3]; x5 = q[2]; x6 = q[1]; x7 = q[0];

    // top linear transformation
    y14 = x3 ^ x5; y13 = x0 ^ x6; y9 = x0 ^ x3; y8 = x0 ^ x5;
    t0 = x1 ^ x2; y1 = t0 ^ x7; y4 = y1 ^ x3; y12 = y13 ^ y14;
    y2 = y1 ^ x0; y5 = y1 ^ x6; y3 = y5 ^ y8; t1 = x4 ^ y12;
    y15 = t1 ^ x5; y20 = t1 ^ x1; y6 = y15 ^ x7; y10 = y15 ^ t0;
    y11 = y20 ^ y9; y7 = x7 ^ y11; y17 = y10 ^ y11; y19 = y10 ^ y8;
    y16 = t0 ^ y11; y21 = y13 ^ y16; y18 = x0 ^ y16;

    // non-linear section
    t2 = y12 & y15; t3 = y3 & y6; t4 = t3 ^ t2; t5 = y4 & x7;
    t6 = t5 ^ t2; t7 = y13 & y16; t8 = y5 & y1; t9 = t8 ^ t7;
    t10 = y2 & y7; t11 = t10 ^ t7; t12 = y9 & y11; t13 = y14 & y17;
    t14 = t13 ^ t12; t15 = y8 & y10; t16 = t15 ^ t12; t17 = t4 ^ t14;
    t18 = t6 ^ t16; t19 = t9 ^ t14; t20 = t11 ^ t16; t21 = t17 ^ y20;
    t22 = t18 ^ y19; t23 = t19 ^ y21; t24 = t20 ^ y18;

    t25 = t21 ^ t22; t26 = t21 & t23; t27 = t24 ^ t26; t28 = t25 & t27;
    t29 = t28 ^ t22; t30 = t23 ^ t24; t31 = t22 ^ t26; t32 = t31 & t30;
    t33 = t32 ^ t24; t34 = t23 ^ t33; t35 = t27 ^ t33; t36 = t24 & t35;
    t37 = t36 ^ t34; t38 = t27 ^ t36; t39 = t29 & t38; t40 = t25 ^ t39;

    t41 = t40 ^ t37; t42 = t29 ^ t33; t43 = t29 ^ t40; t44 = t33 ^ t37;
    t45 = t42 ^ t41;
    z0 = t44 & y15; z1 = t37 & y6; z2 = t33 & x7; z3 = t43 & y16;
    z4 = t40 & y1; z5 = t29 & y7; z6 = t42 & y11; z7 = t45 & y17;
    z8 = t41 & y10; z9 = t44 & y12; z10 = t37 & y3; z11 = t33 & y4;
    z12 = t43 & y13; z13 = t40 & y5; z14 = t29 & y2; z15 = t42 & y9;
    z16 = t45 & y14; z17 = t41 & y8;

    // bottom linear transformation
    t46 = z15 ^ z16; t47 = z10 ^ z11; t48 = z5 ^ z13; t49 = z9 ^ z10;
    t50 = z2 ^ z12; t51 = z2 ^ z5; t52 = z7 ^ z8; t53 = z0 ^ z3;
    t54 = z6 ^ z7; t55 = z16 ^ z17; t56 = z12 ^ t48; t57 = t50 ^ t53;
    t58 = z4 ^ t46; t59 = z3 ^ t54; t60 = t46 ^ t57; t61 = z14 ^ t57;
    t62 = t52 ^ t58; t63 = t49 ^ t58; t64 = z4 ^ t59; t65 = t61 ^ t62;
    t66 = z1 ^ t63; s0 = t59 ^ t63; s6 = t56 ^ ~t62; s7 = t48 ^ ~t60;
    t67 = t64 ^ t65; s3 = t53 ^ t66; s4 = t51 ^ t66; s5 = t47 ^ t65;
    s1 = t64 ^ ~s3; s2 = t55 ^ ~t67;

    q[7] = s0; q[6] = s1; q[5] = s2; q[4] = s3;
    q[3] = s4; q[2] = s5; q[1] = s6; q[0] = s7;
}

#define SWAPN(cl, ch, s, x, y) do { \
        uint32_t a_ = (x), b_ = (y); \
        (x) = (a_ & (uint32_t)(cl)) | ((b_ & (uint32_t)(cl)) << (s)); \
        (y) = ((a_ & (uint32_t)(ch)) >> (s)) | (b_ & (uint32_t)(ch)); \
    } while (0)

static void ortho(uint32_t* q) {
    SWAPN(0x55555555, 0xAAAAAAAA, 1, q[0], q[1]);
    SWAPN(0x55555555, 0xAAAAAAAA, 1, q[2], q[3]);
    SWAPN(0x55555555, 0xAAAAAAAA, 1, q[4], q[5]);
    SWAPN(0x55555555, 0xAAAAAAAA, 1, q[6], q[7]);
    SWAPN(0x33333333, 0xCCCCCCCC, 2, q[0], q[2]);
    SWAPN(0x33333333, 0xCCCCCCCC, 2, q[1], q[3]);
    SWAPN(0x33333333, 0xCCCCCCCC, 2, q[4], q[6]);
    SWAPN(0x33333333, 0xCCCCCCCC, 2, q[5], q[7]);
    SWAPN(0x0F0F0F0F, 0xF0F0F0F0, 4, q[0], q[4]);
    SWAPN(0x0F0F0F0F, 0xF0F0F0F0, 4, q[1], q[5]);
    SWAPN(0x0F0F0F0F, 0xF0F0F0F0, 4, q[2], q[6]);
    SWAPN(0x0F0F0F0F, 0xF0F0F0F0, 4, q[3], q[7]);
}

static uint32_t sub_word(uint32_t x) {
    uint32_t q[8];
    for (int i = 0; i < 8; i++) q[i] = x;
    ortho(q);
    sbox(q);
    ortho(q);
    return q[0];
}

bool mb_aes_init(mb_aes_t* a, const uint8_t* key, size_t len) {
    static const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
    if (len != 16 && len != 32) return false;
    uint32_t rounds = len == 16 ? 10 : 14;
    int nk = (int)(len >> 2), nkf = (int)((rounds + 1) << 2);
    uint32_t skey[120], comp[60], tmp = 0;
    for (int i = 0; i < nk; i++) {
        tmp = dec32le(key + (i << 2));
        skey[(i << 1) + 0] = tmp;
        skey[(i << 1) + 1] = tmp;
    }
    for (int i = nk, j = 0, k = 0; i < nkf; i++) {
        if (j == 0) {
            tmp = (tmp << 24) | (tmp >> 8);
            tmp = sub_word(tmp) ^ rcon[k];
        } else if (nk > 6 && j == 4) {
            tmp = sub_word(tmp);
        }
        tmp ^= skey[(i - nk) << 1];
        skey[(i << 1) + 0] = tmp;
        skey[(i << 1) + 1] = tmp;
        if (++j == nk) { j = 0; k++; }
    }
    for (int i = 0; i < nkf; i += 4) ortho(skey + (i << 1));
    for (int i = 0, j = 0; i < nkf; i++, j += 2) comp[i] = (skey[j] & 0x55555555) | (skey[j + 1] & 0xAAAAAAAA);
    // expanded form, as the rounds use it
    for (int u = 0, v = 0; u < nkf; u++, v += 2) {
        uint32_t x = comp[u] & 0x55555555, y = comp[u] & 0xAAAAAAAA;
        a->sk[v + 0] = x | (x << 1);
        a->sk[v + 1] = y | (y >> 1);
    }
    a->rounds = rounds;
    wipe(skey, sizeof(skey));
    wipe(comp, sizeof(comp));
    return true;
}

void mb_aes_clear(mb_aes_t* a) { wipe(a, sizeof(*a)); }

static void add_round_key(uint32_t* q, const uint32_t* sk) { for (int i = 0; i < 8; i++) q[i] ^= sk[i]; }

static void shift_rows(uint32_t* q) {
    for (int i = 0; i < 8; i++) {
        uint32_t x = q[i];
        q[i] = (x & 0x000000FF)
             | ((x & 0x0000FC00) >> 2) | ((x & 0x00000300) << 6)
             | ((x & 0x00F00000) >> 4) | ((x & 0x000F0000) << 4)
             | ((x & 0xC0000000) >> 6) | ((x & 0x3F000000) << 2);
    }
}

static uint32_t rotr16(uint32_t x) { return (x << 16) | (x >> 16); }

static void mix_columns(uint32_t* q) {
    uint32_t q0 = q[0], q1 = q[1], q2 = q[2], q3 = q[3], q4 = q[4], q5 = q[5], q6 = q[6], q7 = q[7];
    uint32_t r0 = (q0 >> 8) | (q0 << 24), r1 = (q1 >> 8) | (q1 << 24), r2 = (q2 >> 8) | (q2 << 24);
    uint32_t r3 = (q3 >> 8) | (q3 << 24), r4 = (q4 >> 8) | (q4 << 24), r5 = (q5 >> 8) | (q5 << 24);
    uint32_t r6 = (q6 >> 8) | (q6 << 24), r7 = (q7 >> 8) | (q7 << 24);
    q[0] = q7 ^ r7 ^ r0 ^ rotr16(q0 ^ r0);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr16(q1 ^ r1);
    q[2] = q1 ^ r1 ^ r2 ^ rotr16(q2 ^ r2);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr16(q3 ^ r3);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr16(q4 ^ r4);
    q[5] = q4 ^ r4 ^ r5 ^ rotr16(q5 ^ r5);
    q[6] = q5 ^ r5 ^ r6 ^ rotr16(q6 ^ r6);
    q[7] = q6 ^ r6 ^ r7 ^ rotr16(q7 ^ r7);
}

// Encrypt two blocks: in[0..15] and in[16..31] -> out (may alias)
static void aes2(const mb_aes_t* a, const uint8_t in[32], uint8_t out[32]) {
    uint32_t q[8];
    for (int i = 0; i < 4; i++) {
        q[i << 1] = dec32le(in + (i << 2));
        q[(i << 1) + 1] = dec32le(in + 16 + (i << 2));
    }
    ortho(q);
    add_round_key(q, a->sk);
    for (uint32_t u = 1; u < a->rounds; u++) {
        sbox(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, a->sk + (u << 3));
    }
    sbox(q);
    shift_rows(q);
    add_round_key(q, a->sk + (a->rounds << 3));
    ortho(q);
    for (int i = 0; i < 4; i++) {
        enc32le(out + (i << 2), q[i << 1]);
        enc32le(out + 16 + (i << 2), q[(i << 1) + 1]);
    }
    wipe(q, sizeof(q));
}

void mb_aes_block(const mb_aes_t* a, const uint8_t in[16], uint8_t out[16]) {
    uint8_t b[32];
    memcpy(b, in, 16);
    memcpy(b + 16, in, 16);
    aes2(a, b, b);
    memcpy(out, b, 16);
    wipe(b, sizeof(b));
}

void mb_aes_ctr(const mb_aes_t* a, const uint8_t nonce[16], uint32_t off, uint8_t* buf, size_t n) {
    uint8_t ctr[32], ks[32];
    uint32_t c0 = (uint32_t)nonce[12] << 24 | (uint32_t)nonce[13] << 16 | (uint32_t)nonce[14] << 8 | nonce[15];
    uint32_t blk = off >> 4;
    size_t skip = off & 15;
    memcpy(ctr, nonce, 12);
    memcpy(ctr + 16, nonce, 12);
    while (n) {
        for (int k = 0; k < 2; k++) {
            uint32_t c = c0 + blk + (uint32_t)k;
            ctr[16 * k + 12] = (uint8_t)(c >> 24);
            ctr[16 * k + 13] = (uint8_t)(c >> 16);
            ctr[16 * k + 14] = (uint8_t)(c >> 8);
            ctr[16 * k + 15] = (uint8_t)c;
        }
        aes2(a, ctr, ks);
        for (size_t i = skip; i < 32 && n; i++, n--) *buf++ ^= ks[i];
        skip = 0;
        blk += 2;
    }
    wipe(ks, sizeof(ks));
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (RFC 2104), HKDF-SHA256 (RFC 5869)
// ---------------------------------------------------------------------------

typedef struct { mb_sha256_t in; uint8_t opad[64]; } hmac_t;

static void hmac_init(hmac_t* h, const uint8_t* key, size_t key_len) {
    uint8_t k[64], ipad[64];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        mb_sha256_t s;
        mb_sha256_init(&s);
        mb_sha256_update(&s, key, key_len);
        mb_sha256_final(&s, k);
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; h->opad[i] = k[i] ^ 0x5c; }
    mb_sha256_init(&h->in);
    mb_sha256_update(&h->in, ipad, 64);
    wipe(k, sizeof(k));
    wipe(ipad, sizeof(ipad));
}

static void hmac_final(hmac_t* h, uint8_t out[32]) {
    uint8_t inner[32];
    mb_sha256_final(&h->in, inner);
    mb_sha256_t o;
    mb_sha256_init(&o);
    mb_sha256_update(&o, h->opad, 64);
    mb_sha256_update(&o, inner, 32);
    mb_sha256_final(&o, out);
    wipe(inner, sizeof(inner));
    wipe(h, sizeof(*h));
}

void mb_hmac_sha256(const uint8_t* key, size_t key_len, const void* msg, size_t len, uint8_t out[32]) {
    hmac_t h;
    hmac_init(&h, key, key_len);
    mb_sha256_update(&h.in, msg, len);
    hmac_final(&h, out);
}

void mb_hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const void* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    static const uint8_t salt[32];              // "no salt": HashLen zero bytes
    uint8_t prk[32], t[32];
    mb_hmac_sha256(salt, sizeof(salt), ikm, ikm_len, prk);
    size_t got = 0;
    for (uint8_t ctr = 1; got < okm_len; ctr++) {
        hmac_t h;
        hmac_init(&h, prk, 32);
        if (ctr > 1) mb_sha256_update(&h.in, t, 32);
        mb_sha256_update(&h.in, info, info_len);
        mb_sha256_update(&h.in, &ctr, 1);
        hmac_final(&h, t);
        size_t k = okm_len - got < 32 ? okm_len - got : 32;
        memcpy(okm + got, t, k);
        got += k;
    }
    wipe(prk, sizeof(prk));
    wipe(t, sizeof(t));
}

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

int mb_enc_unwrap(mb_aes_t* a, const uint8_t* env, size_t n, const uint8_t priv[32]) {
    if (!priv || n < 4 || env[0] != MB_ENC_TLV_X25519 || env[1] != 0) return MB_E_CORRUPT;
    size_t len = (size_t)env[2] | (size_t)env[3] << 8;
    if (len + 4 != n || (len != 32 + 32 + 16 && len != 32 + 32 + 32)) return MB_E_CORRUPT;
    size_t klen = len - 64;
    const uint8_t* epk = env + 4, *tag = env + 4 + 32, *ckey = env + 4 + 64;
    uint8_t shared[32], derived[32 + 32], mac[32], key[32];
    static const uint8_t zero[16];
    int rc = MB_E_SIGNATURE;
    if (!mb_x25519(shared, priv, epk)) goto out;
    mb_hkdf_sha256(shared, 32, "MCUBoot_ECIES_v1", 16, derived, klen + 32);
    mb_hmac_sha256(derived + klen, 32, ckey, klen, mac);
    if (mb_ct_diff(mac, tag, 32) != 0) goto out;
    if (!mb_aes_init(a, derived, klen)) goto out;
    memcpy(key, ckey, klen);
    mb_aes_ctr(a, zero, 0, key, klen);          // the wrapped key, with a zero counter
    mb_aes_clear(a);
    rc = mb_aes_init(a, key, klen) ? MB_OK : MB_E_SIGNATURE;
out:
    wipe(shared, sizeof(shared));
    wipe(derived, sizeof(derived));
    wipe(key, sizeof(key));
    return rc;
}

#else /* !MB_FEAT_ENC */
int mb_enc_unwrap(mb_aes_t* a, const uint8_t* env, size_t n, const uint8_t priv[32]) {
    (void)a; (void)env; (void)n; (void)priv;
    return MB_E_UNSUPP;
}
void mb_aes_ctr(const mb_aes_t* a, const uint8_t nonce[16], uint32_t off, uint8_t* buf, size_t n) {
    (void)a; (void)nonce; (void)off; (void)buf; (void)n;
}
void mb_aes_clear(mb_aes_t* a) { (void)a; }
#endif
