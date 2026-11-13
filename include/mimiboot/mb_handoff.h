/*
 * MimiBoot - boot handoff (what the bootloader tells the image it starts)
 *
 * An image that wants it reserves a buffer in RAM that its startup code
 * doesn't clear and names it in its header (mbtool finds the symbol
 * `mb_handoff` in the ELF and fills in handoff_addr):
 *
 *     #include "mimiboot/mb_handoff.h"
 *     MB_HANDOFF_BUFFER;              // pico-sdk: in .uninitialized_data
 *
 * Right before starting the image MimiBoot writes this struct there. It is
 * bound to the boot: image_id must be the running image's own, and the
 * client library clears the magic once read, so a struct left over in RAM
 * from an earlier boot is never mistaken for this one. When there is no
 * valid handoff, mb_client_args() falls back to the config + log in flash.
 */
#ifndef MIMIBOOT_HANDOFF_H
#define MIMIBOOT_HANDOFF_H

#include <stdint.h>

#define MB_HANDOFF_MAGIC    0x46464F48u     /* "HOFF" */
#define MB_HANDOFF_VERSION  1

/* reset causes (best effort, port dependent) */
#define MB_RESET_POWER      0x01
#define MB_RESET_WATCHDOG   0x02    /* a watchdog timeout (not a requested reboot) */
#define MB_RESET_SOFT       0x04    /* a requested reboot */

typedef struct {
    uint32_t magic;             /* MB_HANDOFF_MAGIC */
    uint16_t version;           /* MB_HANDOFF_VERSION */
    uint16_t size;              /* sizeof(mb_handoff_t) */
    uint64_t image_id;          /* of the image this was written for */
    uint32_t boot_count;        /* MimiBoot's log counter at this boot */
    uint8_t  slot;              /* which slot (index) */
    uint8_t  kind;              /* MB_KIND_* */
    uint8_t  entry;             /* config entry index (0xFF: none) */
    uint8_t  arch;              /* MB_ARCH_* the image was started on */
    uint32_t reset_cause;       /* MB_RESET_* */
    uint32_t loader_version;    /* MimiBoot version, MB_VERSION() */
    char     slot_name[8];
    char     entry_name[16];
    char     args[96];          /* the command line */
    uint32_t reserved;
    uint32_t crc;               /* CRC-32 of everything before it */
} mb_handoff_t;

#define MB_HANDOFF_BUFFER \
    __attribute__((section(".uninitialized_data.mb_handoff"), used, aligned(8))) volatile mb_handoff_t mb_handoff

#endif
