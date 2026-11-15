/*
 * MimiBoot - ECDSA P-256 verification (MB_FEAT_ECDSA)
 *
 * The arithmetic is micro-ecc v1.2 (third_party/micro-ecc, BSD 2-clause),
 * compiled here with a fixed configuration: portable C, secp256r1 only, no
 * compressed points, no random-number source (verification needs none).
 *
 * A signature is the raw pair r || s (32 + 32 bytes, big-endian) over a
 * SHA-256 digest. The public key is the raw point X || Y (64 bytes).
 */
#include "core/mimiboot.h"

#if MB_FEAT_ECDSA

#define uECC_PLATFORM                   uECC_arch_other
#define uECC_WORD_SIZE                  4
#define uECC_OPTIMIZATION_LEVEL         2
#define uECC_SQUARE_FUNC                0
#define uECC_SUPPORTS_secp160r1         0
#define uECC_SUPPORTS_secp192r1         0
#define uECC_SUPPORTS_secp224r1         0
#define uECC_SUPPORTS_secp256r1         1
#define uECC_SUPPORTS_secp256k1         0
#define uECC_SUPPORT_COMPRESSED_POINT   0
#define _UECC_PLATFORM_SPECIFIC_H_      /* skip micro-ecc's OS random sources: verify doesn't use one */

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include "third_party/micro-ecc/uECC.c"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

bool mb_ecdsa_p256_verify(const uint8_t sig[64], const uint8_t digest[32], const uint8_t pub[64]) {
    // r and s must be in [1, n-1]: uECC_verify checks that, and that the key is on the curve
    if (!uECC_valid_public_key(pub, uECC_secp256r1())) return false;
    return uECC_verify(pub, digest, 32, sig, uECC_secp256r1()) == 1;
}

#else
bool mb_ecdsa_p256_verify(const uint8_t sig[64], const uint8_t digest[32], const uint8_t pub[64]) {
    (void)sig; (void)digest; (void)pub;
    return false;
}
#endif
