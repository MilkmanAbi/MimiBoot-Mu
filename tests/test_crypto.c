/*
 * MimiBoot crypto known-answer tests: SHA-512 (FIPS 180-4 examples) and
 * Ed25519 (RFC 8032 section 7.1 vectors), plus the negative cases a
 * verifier has to get right. Called from test_mimiboot.c.
 */
#include "core/mimiboot.h"
#include "tests/wycheproof_ed25519.h"
#include "tests/wycheproof_p256.h"
#include <stdio.h>
#include <string.h>

int crypto_fails, crypto_checks;
#define CK(cond, ...) do { crypto_checks++; if (!(cond)) { crypto_fails++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void unhex(const char* h, uint8_t* out) {
    for (size_t i = 0; h[2 * i]; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void tohex(const uint8_t* b, int n, char* out) { for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]); }

#if MB_FEAT_LMS
#include "tests/gen_lms.h"
extern uint32_t mb_sha256_blocks;

static size_t unhex_n(const char* h, uint8_t* out, size_t cap) {
    size_t n = strlen(h) / 2;
    if (n > cap) return 0;
    unhex(h, out);
    return n;
}

typedef struct { const uint8_t* sig; uint32_t len; int fail_at; } lms_rd_t;    /* a reader that can fail */
static int failing_read(void* ctx, uint32_t off, void* buf, size_t n) {
    lms_rd_t* r = ctx;
    if (r->fail_at >= 0 && off + n > (uint32_t)r->fail_at) return MB_E_IO;
    if (off + n > r->len) return MB_E_CORRUPT;
    memcpy(buf, r->sig + off, n);
    return MB_OK;
}

// LMS against the published vectors (RFC 8554 Appendix F, NIST ACVP), signatures from
// pyhsslms (an independent implementation), then what a verifier must refuse.
static void test_crypto_lms(void) {
    printf("LMS (RFC 8554 F, NIST ACVP sigVer/sigGen, pyhsslms): %u vectors\n",
           (unsigned)(sizeof(lms_vectors) / sizeof(lms_vectors[0])));
    static uint8_t pub[64], msg[8192], sig[9000], bad[9000];
    for (unsigned i = 0; i < sizeof(lms_vectors) / sizeof(lms_vectors[0]); i++) {
        size_t pn = unhex_n(lms_vectors[i].pub, pub, sizeof(pub));
        size_t mn = unhex_n(lms_vectors[i].msg, msg, sizeof(msg));
        size_t sn = unhex_n(lms_vectors[i].sig, sig, sizeof(sig));
        CK(pn && sn && strlen(lms_vectors[i].msg) / 2 == mn, "%s: vector too big for the test buffers", lms_vectors[i].src);
        mb_lms_ram_t r = {sig, (uint32_t)sn};
        bool ok = mb_lms_pub_len(pub) == pn && mb_lms_verify(msg, mn, pub, mb_lms_read_ram, &r, (uint32_t)sn);
        CK(ok == lms_vectors[i].ok, "%s: expected %s, got %s", lms_vectors[i].src, lms_vectors[i].ok ? "valid" : "invalid",
           ok ? "accepted" : "refused");
        if (!lms_vectors[i].ok || !ok) continue;
        // what must fail: any flipped bit (q, type, C, a chain value, the lms type, the path), a
        // changed message, a wrong length, a reader error, a leaf index past the tree
        uint32_t spots[] = {3, 7, 9, (uint32_t)sn / 2, (uint32_t)sn - 1, (uint32_t)sn - 33};
        for (unsigned k = 0; k < sizeof(spots) / sizeof(spots[0]); k++) {
            memcpy(bad, sig, sn);
            bad[spots[k]] ^= 0x10;
            mb_lms_ram_t b = {bad, (uint32_t)sn};
            CK(!mb_lms_verify(msg, mn, pub, mb_lms_read_ram, &b, (uint32_t)sn), "%s: bit flip at %u accepted",
               lms_vectors[i].src, spots[k]);
        }
        msg[0] ^= 1;
        CK(!mb_lms_verify(msg, mn, pub, mb_lms_read_ram, &r, (uint32_t)sn), "%s: changed message accepted", lms_vectors[i].src);
        msg[0] ^= 1;
        CK(!mb_lms_verify(msg, mn, pub, mb_lms_read_ram, &r, (uint32_t)sn - 1), "%s: short length accepted", lms_vectors[i].src);
        lms_rd_t f = {sig, (uint32_t)sn, (int)sn / 3};
        CK(!mb_lms_verify(msg, mn, pub, failing_read, &f, (uint32_t)sn), "%s: read error accepted", lms_vectors[i].src);
        memcpy(bad, sig, sn);
        unsigned h = pub[3] >= 0x0A ? 5u * (pub[3] - 9u) : 5u * (pub[3] - 4u);
        uint32_t q = 1u << h;
        bad[0] = (uint8_t)(q >> 24); bad[1] = (uint8_t)(q >> 16); bad[2] = (uint8_t)(q >> 8); bad[3] = (uint8_t)q;
        mb_lms_ram_t b = {bad, (uint32_t)sn};
        CK(!mb_lms_verify(msg, mn, pub, mb_lms_read_ram, &b, (uint32_t)sn), "%s: q = 2^h accepted", lms_vectors[i].src);
        // a different key (another I) with the same signature
        pub[8] ^= 1;
        CK(!mb_lms_verify(msg, mn, pub, mb_lms_read_ram, &r, (uint32_t)sn), "%s: other key accepted", lms_vectors[i].src);
        pub[8] ^= 1;
        // what a check costs: SHA-256 blocks (one per chain step), for the parameter sets offered
        if (pn == 56 && (pub[7] == 3 || pub[7] == 4) && (pub[3] == 5 || pub[3] == 6)) {
            uint32_t before = mb_sha256_blocks;
            mb_lms_verify(msg, mn, pub, mb_lms_read_ram, &r, (uint32_t)sn);
            printf("  %-34s H%-2u W%u: %u SHA-256 blocks\n", lms_vectors[i].src, h, pub[7] == 3 ? 4u : 8u,
                   (unsigned)(mb_sha256_blocks - before));
        }
    }
    // types that aren't LMS-with-SHA-256, or an n/m mismatch
    memset(pub, 0, sizeof(pub));
    pub[3] = 0x0F; pub[7] = 3;
    CK(mb_lms_sig_len(pub) == 0, "unknown LMS type has a signature length");
    pub[3] = 5; pub[7] = 7;           // m = 32 with n = 24
    CK(mb_lms_sig_len(pub) == 0, "mixed n/m accepted");
    pub[3] = 6; pub[7] = 3;
    CK(mb_lms_sig_len(pub) == 2508, "H10/W4 signature size");
    pub[8] = 0x11; pub[9] = 0x22; pub[10] = 0x33; pub[11] = 0x44;
    CK(mb_lms_key_id(pub) == 0x44332211u, "key id = the first 4 bytes of I, LE");
}
#endif

#if MB_FEAT_ENC
#include "tests/gen_enc.h"

static bool eqhex(const uint8_t* b, size_t n, const char* want) {
    uint8_t w[128];
    unhex(want, w);
    return strlen(want) == 2 * n && memcmp(b, w, n) == 0;
}

// The encrypted-image primitives against published vectors (each also checked
// against pyca/cryptography when this was written), then envelopes made by
// imgtool and by the generator (tests/gen_enc.py, an independent implementation).
static void test_crypto_enc(void) {
    printf("AES (FIPS-197 C.1, C.3), AES-CTR (SP 800-38A F.5.1, F.5.5)\n");
    uint8_t k[32], in[64], out[64], nonce[16];
    mb_aes_t a;
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", k);
    unhex("00112233445566778899aabbccddeeff", in);
    CK(mb_aes_init(&a, k, 16), "AES-128 key schedule");
    mb_aes_block(&a, in, out);
    CK(eqhex(out, 16, "69c4e0d86a7b0430d8cdb78070b4c55a"), "FIPS-197 C.1");
    CK(mb_aes_init(&a, k, 32), "AES-256 key schedule");
    mb_aes_block(&a, in, out);
    CK(eqhex(out, 16, "8ea2b7ca516745bfeafc49904b496089"), "FIPS-197 C.3");
    CK(!mb_aes_init(&a, k, 24), "AES-192 is not offered");
    static const char* pt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    struct { const char* key; const char* ct; } ctr[] = {
        { "2b7e151628aed2a6abf7158809cf4f3c",
          "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee" },
        { "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
          "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6" },
    };
    unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", nonce);
    for (unsigned i = 0; i < 2; i++) {
        unhex(ctr[i].key, k);
        CK(mb_aes_init(&a, k, strlen(ctr[i].key) / 2), "CTR key %u", i);
        unhex(pt, out);
        mb_aes_ctr(&a, nonce, 0, out, 64);
        CK(eqhex(out, 64, ctr[i].ct), "SP 800-38A CTR vector %u", i);
        // the same keystream from any starting offset, in any piece sizes
        unhex(pt, out);
        static const uint32_t cuts[] = { 0, 1, 15, 16, 17, 31, 33, 47, 64 };
        for (unsigned c = 0; c + 1 < sizeof cuts / sizeof cuts[0]; c++)
            mb_aes_ctr(&a, nonce, cuts[c], out + cuts[c], cuts[c + 1] - cuts[c]);
        CK(eqhex(out, 64, ctr[i].ct), "SP 800-38A CTR vector %u, in odd pieces", i);
    }
    mb_aes_clear(&a);

    printf("HMAC-SHA256 (RFC 4231), HKDF-SHA256 (RFC 5869 case 3)\n");
    unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", k);
    mb_hmac_sha256(k, 20, "Hi There", 8, out);
    CK(eqhex(out, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), "RFC 4231 case 1");
    mb_hmac_sha256((const uint8_t*)"Jefe", 4, "what do ya want for nothing?", 28, out);
    CK(eqhex(out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), "RFC 4231 case 2");
    {                                            // RFC 4231 case 6: a key longer than the block
        uint8_t big[131];
        memset(big, 0xaa, sizeof big);
        mb_hmac_sha256(big, sizeof big, "Test Using Larger Than Block-Size Key - Hash Key First", 54, out);
        CK(eqhex(out, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"), "RFC 4231 case 6");
    }
    mb_hkdf_sha256(k, 22, "", 0, out, 42);
    CK(eqhex(out, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"), "RFC 5869 case 3");

    printf("X25519 (RFC 7748 sections 5.2 and 6.1)\n");
    struct { const char* k; const char* u; const char* r; } xv[] = {
        { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
          "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" },
        { "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
          "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957" },
        { "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
          "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" },
        { "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
          "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" },
    };
    for (unsigned i = 0; i < 4; i++) {
        uint8_t s[32], u[32];
        unhex(xv[i].k, s);
        unhex(xv[i].u, u);
        CK(mb_x25519(out, s, u) && eqhex(out, 32, xv[i].r), "X25519 vector %u", i + 1);
    }
    {
        uint8_t kk[32] = { 9 }, uu[32] = { 9 }, r[32];
        for (int i = 1; i <= 1000; i++) {
            mb_x25519(r, kk, uu);
            memcpy(uu, kk, 32);
            memcpy(kk, r, 32);
            if (i == 1) CK(eqhex(kk, 32, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), "X25519 iterated once");
        }
        CK(eqhex(kk, 32, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), "X25519 iterated 1000 times");
        uint8_t zero_u[32] = { 0 }, one_u[32] = { 1 };
        CK(!mb_x25519(r, kk, zero_u), "X25519: u = 0 (low order) gives no shared secret");
        CK(!mb_x25519(r, kk, one_u), "X25519: u = 1 (low order) gives no shared secret");
    }

    printf("Envelopes (imgtool and tests/gen_enc.py)\n");
    for (unsigned i = 0; i < sizeof enc_vec / sizeof enc_vec[0]; i++) {
        const enc_vec_t* v = &enc_vec[i];
        CK(mb_enc_unwrap(&a, v->env, v->env_len, enc_priv) == MB_OK, "%s: unwraps", v->name);
        static uint8_t buf[ENC_BODY_MAX];
        memcpy(buf, v->body, v->body_len);
        static const uint8_t zn[16];
        mb_aes_ctr(&a, zn, 0, buf, v->body_len);
        mb_sha256_t sh;
        uint8_t d[32];
        mb_sha256_init(&sh);
        mb_sha256_update(&sh, buf, v->body_len);
        mb_sha256_final(&sh, d);
        CK(!memcmp(d, v->plain_sha, 32), "%s: decrypts to the plaintext", v->name);
        CK(mb_enc_unwrap(&a, v->env, v->env_len, enc_other_priv) == MB_E_SIGNATURE, "%s: another device's key is refused", v->name);
        uint8_t env[MB_ENC_ENV_MAX];
        for (size_t at = 4; at < v->env_len; at += 7) {             // any flipped byte: refused
            memcpy(env, v->env, v->env_len);
            env[at] ^= 0x20;
            CK(mb_enc_unwrap(&a, env, v->env_len, enc_priv) != MB_OK, "%s: byte %u flipped is refused", v->name, (unsigned)at);
        }
        memcpy(env, v->env, v->env_len);
        env[0] = 0x32;
        CK(mb_enc_unwrap(&a, env, v->env_len, enc_priv) == MB_E_CORRUPT, "%s: another TLV type is not an envelope", v->name);
        CK(mb_enc_unwrap(&a, v->env, v->env_len - 1, enc_priv) == MB_E_CORRUPT, "%s: short is not an envelope", v->name);
    }
    mb_aes_clear(&a);
}
#endif

void test_crypto(void) {
    printf("SHA-512\n");
    struct { const char* m; const char* h; } s[] = {
        { "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
        { "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
    };
    for (unsigned i = 0; i < 3; i++) {
        mb_sha512_t c;
        uint8_t d[64];
        char h[129];
        mb_sha512_init(&c);
        mb_sha512_update(&c, s[i].m, strlen(s[i].m));
        mb_sha512_final(&c, d);
        tohex(d, 64, h);
        CK(!strcmp(h, s[i].h), "sha512(\"%.10s...\") = %.32s...", s[i].m, h);
    }

    printf("Ed25519 (RFC 8032 vectors)\n");
    struct { const char* pk; const char* m; const char* sig; } v[] = {
        { "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
        { "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
        { "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
          "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
    };
    for (unsigned i = 0; i < 3; i++) {
        uint8_t pk[32], m[8], sig[64];
        unhex(v[i].pk, pk);
        unhex(v[i].sig, sig);
        size_t mlen = strlen(v[i].m) / 2;
        unhex(v[i].m, m);
        CK(mb_ed25519_verify(sig, m, mlen, pk), "vector %u verifies", i + 1);
        // every class of tampering must fail
        uint8_t bad[64];
        memcpy(bad, sig, 64); bad[5] ^= 1;
        CK(!mb_ed25519_verify(bad, m, mlen, pk), "vector %u: R bit flipped", i + 1);
        memcpy(bad, sig, 64); bad[40] ^= 0x10;
        CK(!mb_ed25519_verify(bad, m, mlen, pk), "vector %u: S bit flipped", i + 1);
        uint8_t m2[8];
        memcpy(m2, m, sizeof(m2));
        m2[0] ^= 1;
        CK(!mb_ed25519_verify(sig, m2, mlen ? mlen : 1, pk), "vector %u: message changed", i + 1);
        uint8_t pk2[32];
        memcpy(pk2, pk, 32); pk2[3] ^= 4;
        CK(!mb_ed25519_verify(sig, m, mlen, pk2), "vector %u: key changed", i + 1);
        // S + L is the same point but a second encoding: must be refused
        static const uint8_t L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
        memcpy(bad, sig, 64);
        unsigned carry = 0;
        for (int k = 0; k < 32; k++) { unsigned t = bad[32 + k] + L[k] + carry; bad[32 + k] = (uint8_t)t; carry = t >> 8; }
        CK(!mb_ed25519_verify(bad, m, mlen, pk), "vector %u: S + L (malleable) refused", i + 1);
    }

    // Wycheproof: every "valid" vector verifies, every "invalid" one doesn't.
    // "acceptable" ones (small-order and mixed-order keys, which RFC 8032 leaves
    // open) are counted, not judged: MimiBoot's keys are its own, never an
    // attacker's choice. Signatures that aren't 64 bytes never reach the
    // verifier (the image header has exactly 64), so they count as refused.
    printf("Ed25519 (Wycheproof, %u vectors)\n", (unsigned)(sizeof wp_ed25519 / sizeof wp_ed25519[0]));
    unsigned acc_yes = 0, acc_no = 0;
    for (unsigned i = 0; i < sizeof wp_ed25519 / sizeof wp_ed25519[0]; i++) {
        const wp_vector_t* t = &wp_ed25519[i];
        bool ok = t->sig_len == 64 && mb_ed25519_verify((const uint8_t*)t->sig, t->msg, t->msg_len, (const uint8_t*)t->pub);
        if (t->result == 2) { ok ? acc_yes++ : acc_no++; continue; }
        CK(ok == (t->result == 1), "Wycheproof tcId %d: expected %s, got %s", t->id, t->result ? "valid" : "invalid",
           ok ? "accepted" : "refused");
    }
    printf("  'acceptable' vectors: %u accepted, %u refused\n", acc_yes, acc_no);

#if MB_FEAT_ECDSA
    // ECDSA P-256 (micro-ecc) against Wycheproof's P1363 vectors (raw r || s).
    // The verifier takes a digest: hash the message here, as the image code does.
    printf("ECDSA P-256 (Wycheproof, %u vectors)\n", (unsigned)(sizeof wp_p256 / sizeof wp_p256[0]));
    for (unsigned i = 0; i < sizeof wp_p256 / sizeof wp_p256[0]; i++) {
        const wp_vector_t* t = &wp_p256[i];
        uint8_t d[32];
        mb_sha256_t s;
        mb_sha256_init(&s);
        mb_sha256_update(&s, t->msg, t->msg_len);
        mb_sha256_final(&s, d);
        bool ok = t->sig_len == 64 && mb_ecdsa_p256_verify((const uint8_t*)t->sig, d, (const uint8_t*)t->pub);
        // Known: micro-ecc refuses two *valid* signatures built so that its
        // Shamir double-multiplication passes through the point at infinity
        // (tcId 60) or hits an extreme k / s^-1 (tcId 210). A false reject is
        // safe (nothing forged gets in) and a real signer lands there with
        // probability ~2^-256. Pinned here so a change in either direction shows.
        if (t->id == 60 || t->id == 210) {
            CK(!ok, "Wycheproof P-256 tcId %d: known false reject now accepted (micro-ecc changed?)", t->id);
            continue;
        }
        CK(ok == (t->result == 1), "Wycheproof P-256 tcId %d: expected %s, got %s", t->id, t->result ? "valid" : "invalid",
           ok ? "accepted" : "refused");
    }
#endif
#if MB_FEAT_ENC
    test_crypto_enc();
#endif
#if MB_FEAT_LMS
    test_crypto_lms();
#endif
}
