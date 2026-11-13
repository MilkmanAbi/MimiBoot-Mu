/*
 * MimiBoot crypto known-answer tests: SHA-512 (FIPS 180-4 examples) and
 * Ed25519 (RFC 8032 section 7.1 vectors), plus the negative cases a
 * verifier has to get right. Called from test_mimiboot.c.
 */
#include "core/mimiboot.h"
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
}
