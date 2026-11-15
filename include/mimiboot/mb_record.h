/*
 * MimiBoot - boot record (measured boot: what was checked and what ran)
 *
 * An image that wants it reserves a buffer its startup code doesn't clear,
 * as for the handoff, and mbtool finds the symbol `mb_boot_record` and puts
 * its address in the header (record_addr):
 *
 *     #include "mimiboot/mb_record.h"
 *     MB_BOOT_RECORD_BUFFER;
 *
 * Builds with BOOT_RECORD write it right before starting the image, after
 * every check passed. It says which checks passed on this boot, with which
 * key, and gives two hashes and a measurement that binds them:
 *
 *   loader_sha256   SHA-256 of the bootloader's own image in flash (what
 *                   mimiboot.bin holds: code, constants, initial data)
 *   measurement     SHA-256("MimiBoot measure v1\0" || loader_sha256 ||
 *                   the image header's signed bytes), and those bytes hold
 *                   the payload hash, version, security version, flags and
 *                   key id
 *
 * So a server that knows the expected bootloader and image can recompute the
 * measurement and compare. What this is not: attestation. Nothing here is
 * signed by the device, and the image could change the record after it
 * starts. It is a report from the bootloader to the image, for the image to
 * pass on, for example inside its own signed report.
 */
#ifndef MIMIBOOT_RECORD_H
#define MIMIBOOT_RECORD_H

#include <stdint.h>

#define MB_RECORD_MAGIC     0x4352424Du     /* "MBRC" */
#define MB_RECORD_VERSION   1

/* flags: what held on this boot */
#define MB_REC_SIGNED       0x01    /* signature verified against a trusted key */
#define MB_REC_HASHED       0x02    /* payload hashed and matched */
#define MB_REC_TRIAL        0x04    /* a trial boot (the image hasn't confirmed itself yet) */
#define MB_REC_LOADER       0x08    /* loader_sha256 is real (else zero: the port can't measure itself) */
#define MB_REC_RAM          0x10    /* started from RAM */

typedef struct {
    uint32_t magic;             /* MB_RECORD_MAGIC */
    uint16_t version;           /* MB_RECORD_VERSION */
    uint16_t size;              /* sizeof(mb_boot_record_t) */
    uint32_t flags;             /* MB_REC_* */
    uint32_t key_id;            /* the key the signature verified against (0: unsigned) */
    uint32_t image_version;     /* MB_VERSION() */
    uint32_t security_version;  /* the image's */
    uint32_t floor;             /* the rollback floor in force at this boot */
    uint32_t loader_version;    /* MimiBoot's MB_VERSION() */
    uint8_t  image_sha256[32];  /* the payload hash from the header */
    uint8_t  loader_sha256[32];
    uint8_t  measurement[32];
    uint32_t crc;               /* CRC-32 of everything before it */
} mb_boot_record_t;

#define MB_RECORD_DOMAIN    "MimiBoot measure v1"   /* hashed with its NUL */

#define MB_BOOT_RECORD_BUFFER \
    __attribute__((section(".uninitialized_data.mb_boot_record"), used, aligned(8))) volatile mb_boot_record_t mb_boot_record

#endif
