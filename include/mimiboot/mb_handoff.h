/*
 * MimiBoot - boot handoff (what the bootloader tells the image it starts),
 * and the mailbox (what the running image tells the next boot)
 *
 * An image that wants it reserves a buffer in RAM that its startup code
 * doesn't clear and names it in its header (mbtool finds the symbol
 * `mb_handoff` in the ELF and fills in handoff_addr and handoff_size):
 *
 *     #include "mimiboot/mb_handoff.h"
 *     MB_HANDOFF_BUFFER;              // pico-sdk: in .uninitialized_data
 *
 * Right before starting the image MimiBoot writes the handoff there. It is
 * bound to the boot: image_id must be the running image's own, and the
 * client library clears the magic once read, so a struct left over in RAM
 * from an earlier boot is never mistaken for this one. When there is no
 * valid handoff, mb_client_args() falls back to the config + log in flash.
 *
 * Versions. The image's header says how big its buffer is (handoff_size), and
 * MimiBoot never writes more than that:
 *   v1  160 bytes: slot, entry, args, reset cause, loader version
 *   v2  320 bytes: v1, then capabilities, features, how the previous run ended,
 *       trial state, boot time, a random seed (MB_HANDOFF_V2_SIZE buffers only)
 * A v2 block starts with a complete v1 block (its CRC at 156 covers bytes
 * 0..155), so a v1 reader takes it as one; crc2 at the end covers the rest.
 *
 * The mailbox goes the other way: before it resets, the running image may
 * leave an mb_mailbox_t in the same buffer (a reason, a message, what to boot
 * next). MimiBoot reads it first thing on the next boot, clears it, and acts
 * on it without writing flash. RAM survives a reset, not a power cut: a
 * mailbox that is lost or damaged just means a normal boot (the client library
 * falls back to the boot log in flash for requests that must not be lost).
 */
#ifndef MIMIBOOT_HANDOFF_H
#define MIMIBOOT_HANDOFF_H

#include <stdint.h>
#include "mimiboot/mb_control.h"

#define MB_HANDOFF_MAGIC    0x46464F48u     /* "HOFF" */
#define MB_HANDOFF_VERSION  2               /* what this header describes; v1 blocks still exist */
#define MB_HANDOFF_V1_SIZE  160
#define MB_HANDOFF_V2_SIZE  320

/* reset causes (best effort, port dependent) */
#define MB_RESET_POWER      0x01
#define MB_RESET_WATCHDOG   0x02    /* a watchdog timeout (not a requested reboot) */
#define MB_RESET_SOFT       0x04    /* a requested reboot */

/* How the previous run ended (mb_end_t.reason): what the OS said in the
 * mailbox, or, without one, what the reset hardware says. */
#define MB_END_UNKNOWN      0       /* a reset nobody announced (a soft reset without a note) */
#define MB_END_POWER_ON     1       /* power-on / brown-out: nothing ran before */
#define MB_END_REBOOT       2       /* the OS rebooted on purpose */
#define MB_END_UPDATE       3       /* ... to install or try an update */
#define MB_END_POWEROFF     4       /* the OS shut down; something woke the chip */
#define MB_END_PANIC        5       /* the OS gave up (mb_client_panic) */
#define MB_END_FAULT        6       /* a CPU fault the OS caught (mb_client_fault) */
#define MB_END_WATCHDOG     7       /* the watchdog fired (nothing said otherwise) */
#define MB_END_LOADER       8       /* the bootloader itself reset (from its menu, an architecture switch) */

#define MB_ENDF_NOTED       0x01    /* the OS left this in the mailbox (not guessed from the reset cause) */
#define MB_ENDF_CRASH       0x02    /* counted as a crash (the crash-loop guard's strike) */

typedef struct {
    uint8_t  reason;            /* MB_END_* */
    uint8_t  flags;             /* MB_ENDF_* */
    uint16_t _pad;
    uint32_t pc, lr, info;      /* panic / fault: where, and what (e.g. the fault status register); else 0 */
    char     msg[48];           /* the OS's own words, NUL-terminated ("" when none) */
} mb_end_t;                     /* 64 bytes */

/* what the bootloader was built with (mb_handoff_t.features): the parts an OS may want to know about */
#define MB_HF_SIGNATURES        (1ull << 0)     /* Ed25519 */
#define MB_HF_ECDSA             (1ull << 1)
#define MB_HF_LMS               (1ull << 2)
#define MB_HF_REQUIRE_SIGNATURE (1ull << 3)     /* unsigned images don't boot */
#define MB_HF_ANTI_ROLLBACK     (1ull << 4)
#define MB_HF_AB_TRIAL          (1ull << 5)     /* new A/B images must call mb_client_confirm() */
#define MB_HF_TRIAL_WATCHDOG    (1ull << 6)
#define MB_HF_CRASH_GUARD       (1ull << 7)
#define MB_HF_CONSOLE           (1ull << 8)
#define MB_HF_SHELL             (1ull << 9)
#define MB_HF_RECV              (1ull << 10)    /* console uploads (mbtool install) */
#define MB_HF_SMP               (1ull << 11)
#define MB_HF_CFG_FILE          (1ull << 12)
#define MB_HF_CFG_SIGNED        (1ull << 13)
#define MB_HF_CONSOLE_AUTH      (1ull << 14)
#define MB_HF_ENCRYPTED_IMAGES  (1ull << 15)
#define MB_HF_BOOT_RECORD       (1ull << 16)
#define MB_HF_TWO_STAGE         (1ull << 17)
#define MB_HF_PROTECTED_FLOOR   (1ull << 18)
#define MB_HF_BOOT_LOCK         (1ull << 19)
#define MB_HF_DEBUG_LOCK        (1ull << 20)
#define MB_HF_REVOKE            (1ull << 21)
#define MB_HF_RAM_IMAGES        (1ull << 22)
#define MB_HF_IMG_MCUBOOT       (1ull << 23)
#define MB_HF_IMG_RAW           (1ull << 24)
#define MB_HF_SCRUB_RAM         (1ull << 25)
#define MB_HF_FAULT_HARDENING   (1ull << 26)
#define MB_HF_CONTROL           (1ull << 27)
#define MB_HF_MAILBOX           (1ull << 28)
#define MB_HF_CONSOLE_USB       (1ull << 29)

/* mb_handoff_t.hflags */
#define MB_HO_SEED              0x01    /* seed[] holds bytes from a hardware RNG */
#define MB_HO_TRIAL             0x02    /* this is a trial boot: confirm, or be rolled back */

typedef struct {
    /* ---- v1 (160 bytes) ---- */
    uint32_t magic;             /* MB_HANDOFF_MAGIC */
    uint16_t version;           /* 1 or 2 */
    uint16_t size;              /* MB_HANDOFF_V1_SIZE or MB_HANDOFF_V2_SIZE */
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
    uint32_t reserved;          /* MB_HOFF_HAS_CAPS | topology | caps << 8 (v1 readers) */
    uint32_t crc;               /* CRC-32 of the 156 bytes before it */
    /* ---- v2 (to 320 bytes) ---- */
    uint64_t features;          /* MB_HF_* */
    uint32_t caps;              /* MB_CAP_*: what the running image may ask for */
    uint32_t boot_ms;           /* time spent in the bootloader this boot (0: no clock) */
    uint32_t min_security;      /* the rollback floor in force */
    uint32_t trial_ms;          /* trial boot: the watchdog period armed for it (0: none) */
    uint8_t  active;            /* the preferred GOOD A/B slot */
    uint8_t  tries_left;        /* trial boot: boots left before rollback */
    uint8_t  strikes;           /* crash-loop guard: crashes in a row of this image */
    uint8_t  hflags;            /* MB_HO_* */
    mb_end_t prev;              /* how the previous run ended */
    uint8_t  seed[32];          /* MB_HO_SEED: fresh random bytes for the OS's RNG pool */
    uint8_t  reserved2[32];
    uint32_t crc2;              /* CRC-32 of the 316 bytes before it */
} mb_handoff_t;

/* The other way: what the running image leaves for the next boot (same buffer). */
#define MB_MAILBOX_MAGIC    0x584F424Du     /* "MBOX" */
#define MB_MAILBOX_VERSION  1
typedef struct {
    uint32_t magic;             /* MB_MAILBOX_MAGIC */
    uint16_t version, size;     /* MB_MAILBOX_VERSION, sizeof(mb_mailbox_t) */
    uint64_t image_id;          /* the image that wrote it: anything else is ignored */
    mb_end_t end;               /* why this run is ending */
    mb_control_request_t next;  /* what to boot next (version 0: nothing, a normal boot) */
    uint32_t crc;               /* CRC-32 of everything before it */
} mb_mailbox_t;

#define MB_HANDOFF_BUFFER \
    __attribute__((section(".uninitialized_data.mb_handoff"), used, aligned(8))) volatile mb_handoff_t mb_handoff

#endif
