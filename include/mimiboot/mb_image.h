/*
 * MimiBoot - image format (header version 2)
 *
 * A slot holds one image:
 *
 *   slot + 0          mb_image_hdr_t, then 0xFF to the end of the first sector
 *   slot + 4096       payload, byte for byte as the compiler produced it
 *
 * The header lives in its own sector so the payload stays untouched, and the
 * header is written last: an image without a valid header is "empty", never
 * half-booted.
 *
 * Integrity: hdr_crc covers the header, sha256 the payload. Authenticity
 * (optional): an Ed25519 signature over the first MB_IMG_SIGNED_BYTES of the
 * header, which include the payload hash, so one signature covers both.
 */
#ifndef MIMIBOOT_IMAGE_H
#define MIMIBOOT_IMAGE_H

#include <stdint.h>
#include <stddef.h>

#define MB_IMG_MAGIC        0x474D494Du     /* "MIMG" */
#define MB_IMG_HDR_VERSION  2
#define MB_IMG_HDR_SIZE     256             /* bytes covered by hdr_crc (+4) */
#define MB_IMG_PAYLOAD_OFF  4096            /* payload starts one sector into the slot */

/* How the payload is started */
#define MB_LOAD_CHAIN       1   /* execute in place: the slot is mapped at the flash base */
#define MB_LOAD_RAM         2   /* copy to load_addr, check it there, start it there */

/* CPU architecture the payload is built for */
#define MB_ARCH_ANY         0
#define MB_ARCH_ARM         1   /* RP2350: Cortex-M33 */
#define MB_ARCH_RISCV       2   /* RP2350: Hazard3 */

/* flags */
#define MB_IMG_F_GOLDEN     0x0001  /* built to be the recovery image */
#define MB_IMG_F_SIGNED     0x0002  /* signature[] is valid for key_id */

#define MB_VERSION(maj, min, pat)   (((uint32_t)(maj) << 24) | ((uint32_t)(min) << 16) | (uint32_t)(pat))
#define MB_VERSION_MAJOR(v)         ((v) >> 24)
#define MB_VERSION_MINOR(v)         (((v) >> 16) & 0xFF)
#define MB_VERSION_PATCH(v)         ((v) & 0xFFFF)

typedef struct {
    uint32_t magic;             /* MB_IMG_MAGIC */
    uint16_t hdr_version;       /* MB_IMG_HDR_VERSION */
    uint16_t hdr_size;          /* MB_IMG_HDR_SIZE */
    uint32_t flags;             /* MB_IMG_F_* */
    uint32_t load_type;         /* MB_LOAD_* */
    uint32_t payload_offset;    /* from the slot start; MB_IMG_PAYLOAD_OFF */
    uint32_t payload_size;      /* bytes */
    uint8_t  sha256[32];        /* of the payload */
    uint32_t version;           /* MB_VERSION(): shown in the menu, golden monotonicity */
    uint32_t security_version;  /* anti-rollback: never boot below the recorded floor */
    uint32_t build_time;        /* unix seconds, informational */
    uint32_t load_addr;         /* MB_LOAD_RAM: where the payload goes */
    uint32_t entry;             /* RAM: RP2040 vector address; RP2350 informational (IMAGE_DEF) */
    uint32_t trial_timeout_ms;  /* watchdog during a trial boot (0 = bootloader default) */
    char     name[32];          /* NUL-terminated */
    char     target[16];        /* chip family, e.g. "rp2350" */
    uint8_t  arch;              /* MB_ARCH_* */
    uint8_t  _pad[3];
    uint32_t handoff_addr;      /* RAM address for the boot handoff (0 = none); see mb_handoff.h */
    uint32_t key_id;            /* which trusted key signed it (first 4 bytes of the key, LE) */
    uint8_t  reserved[48];      /* zero */
    uint8_t  signature[64];     /* Ed25519 over bytes [0, MB_IMG_SIGNED_BYTES) */
    uint32_t hdr_crc;           /* CRC-32 of the 252 bytes before it */
} mb_image_hdr_t;

#define MB_IMG_SIGNED_BYTES offsetof(mb_image_hdr_t, signature)

/* The image id is the start of the payload hash: it changes whenever the
 * payload does, so the boot log can tell "the same image" from "a new one". */
static inline uint64_t mb_image_id(const mb_image_hdr_t* h) {
    uint64_t id = 0;
    for (int i = 0; i < 8; i++) id = (id << 8) | h->sha256[i];
    return id;
}

#endif
