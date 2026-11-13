/*
 * MimiBoot - boot control log (BCL), record version 2
 *
 * All boot state lives in an append-only log spread over two flash sectors.
 * Each record is a complete snapshot with a sequence number and a CRC, so
 * the current state is simply "the newest valid record".
 *
 *   sector:  [sector header][rec][rec]...[0xFF...]     (256-byte units)
 *
 * Writing a record only ever programs blank (0xFF) bytes. A power cut during
 * the write leaves a record with a bad CRC, which readers ignore: the state
 * is entirely the old one or entirely the new one. When a sector is full the
 * log moves to the other one (erase, header with generation+1, current
 * record); until that record lands, the old sector still holds the state.
 *
 * The bootloader writes only when something changes (a new image, a trial
 * attempt, a bad image, a request consumed, a watchdog strike). Apps write
 * through the client library (confirm, requests).
 */
#ifndef MIMIBOOT_BCL_H
#define MIMIBOOT_BCL_H

#include <stdint.h>
#include <stdbool.h>
#include "mimiboot/mb_layout.h"

#define MB_SLOT_A           0
#define MB_SLOT_B           1
#define MB_SLOT_GOLDEN      2
#define MB_SLOT_NONE        0xFF
#define MB_SLOT_AB          0xFE    /* config entries: "the A/B pair, by policy" */

/* per-slot state */
#define MB_ST_EMPTY         0   /* no valid header */
#define MB_ST_NEW           1   /* a valid image the log hasn't booted yet */
#define MB_ST_TRIAL         2   /* A/B: being tried; must be confirmed before tries run out */
#define MB_ST_GOOD          3   /* confirmed (A/B) or verified (golden, aux) */
#define MB_ST_BAD           4   /* never boot again (until the image changes) */

/* why a slot went bad */
#define MB_BAD_NONE         0
#define MB_BAD_HEADER       1
#define MB_BAD_HASH         2
#define MB_BAD_TRIALS       3   /* booted N times without confirming */
#define MB_BAD_ROLLBACK     4   /* security_version below the floor */
#define MB_BAD_TARGET       5   /* another chip, an arch or load type this port can't start */
#define MB_BAD_LAUNCH       6   /* the launcher refused it */
#define MB_BAD_REJECTED     7   /* rejected by the app or the console */
#define MB_BAD_GOLDEN_OLD   8   /* golden replaced by a version that isn't newer */
#define MB_BAD_SIGNATURE    9   /* unsigned when signatures are required, or a bad signature */

/* slot flags */
#define MB_SF_SIG_OK        0x01    /* signature checked for this image_id: don't redo it every boot */
#define MB_SF_HASH_OK       0x02    /* payload hash checked for this image_id (MB_BOOT_VERIFY "once") */

/* one-shot requests (consumed by the bootloader on the next boot) */
#define MB_REQ_NONE         0
#define MB_REQ_MENU         1   /* stop in the boot menu */
#define MB_REQ_BOOT_ONCE    2   /* boot slot request_arg once */
#define MB_REQ_BOOTSEL      3   /* reboot into the ROM USB bootloader */
#define MB_REQ_ENTRY_ONCE   4   /* boot config entry request_arg once (with args[] if set) */
#define MB_REQ_NIGHT        6   /* versioned command in reserved[24], consumed once */
#define MB_REQ_FLASH        5   /* flash mode: console up, no countdown, waiting for mbtool */

/* how the last boot was chosen */
#define MB_KIND_NONE        0
#define MB_KIND_NORMAL      1
#define MB_KIND_TRIAL       2
#define MB_KIND_ONCE        3
#define MB_KIND_FALLBACK    4   /* the preferred choice failed, this one was next */
#define MB_KIND_GOLDEN      5
#define MB_KIND_MENU        6   /* picked by hand */
#define MB_KIND_ENTRY       7   /* a non-default config entry */

/* record flags */
#define MB_LF_HANDOVER      0x02    /* the next boot follows an architecture-switch reboot, not a crash */

typedef struct {
    uint64_t image_id;          /* mb_image_id() of the image this entry describes */
    uint8_t  state;             /* MB_ST_* */
    uint8_t  tries_left;        /* trial boots remaining */
    uint8_t  bad_reason;        /* MB_BAD_* */
    uint8_t  flags;             /* MB_SF_* */
    uint16_t boots;             /* trial starts (saturating) */
    uint16_t _pad;
} mb_slot_rec_t;                /* 16 bytes */

#define MB_BCL_REC_MAGIC    0xB0C8u     /* record version 2 */
#define MB_BCL_REC_SIZE     256
#define MB_ARGS_MAX         96

typedef struct {
    uint16_t magic;             /* MB_BCL_REC_MAGIC */
    uint16_t size;              /* MB_BCL_REC_SIZE */
    uint32_t seq;               /* +1 per record, across sectors */
    mb_slot_rec_t slot[MB_MAX_SLOTS];
    uint32_t min_security;      /* anti-rollback floor: only ever increases */
    uint32_t golden_version;    /* highest golden version accepted (monotonic) */
    uint64_t golden_id;         /* the golden image that version belongs to */
    uint8_t  active;            /* preferred GOOD A/B slot (last confirmed) */
    uint8_t  request;           /* MB_REQ_* */
    uint8_t  request_arg;
    uint8_t  last_slot;         /* what the bootloader started last */
    uint8_t  last_kind;         /* MB_KIND_* */
    uint8_t  last_entry;        /* config entry index of the last boot (0xFF: none) */
    uint8_t  strikes;           /* watchdog resets in a row of last_slot (crash-loop guard) */
    uint8_t  flags;             /* MB_LF_* */
    uint32_t boot_count;        /* boots that wrote the log (informational) */
    char     args[MB_ARGS_MAX]; /* one-shot args for MB_REQ_ENTRY_ONCE, or the last boot's (MB_LF_ARGS) */
    uint8_t  reserved[24];
    uint32_t crc;               /* CRC-32 of the 252 bytes before it */
} mb_bcl_rec_t;

#define MB_BCL_SECT_MAGIC   0x4C43424Du     /* "MBCL" */

typedef struct {
    uint32_t magic;             /* MB_BCL_SECT_MAGIC */
    uint32_t generation;        /* the sector with the higher generation is newer */
    uint32_t rec_size;
    uint8_t  reserved[MB_BCL_REC_SIZE - 16];
    uint32_t crc;
} mb_bcl_sect_t;

#endif
