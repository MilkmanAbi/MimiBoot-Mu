/*
 * MimiBoot client - what a booted image uses to talk to the bootloader
 *
 * State goes through the boot log and config in flash, so it works the same
 * whether the bootloader is running or not (and survives resets). The boot
 * handoff (args, how we were booted) comes in RAM when the image asked for
 * one, with the flash as the fallback.
 *
 *   mb_client_init(port)             once, with the app-side port (flash ops)
 *   mb_client_set_handoff(&mb_handoff)   if the image declares MB_HANDOFF_BUFFER
 *   mb_client_status(&st)            which slot am I, am I on trial?
 *   mb_client_args()                 my command line
 *   mb_client_confirm()              "this image works": GOOD, active, raise the rollback floor
 *   mb_client_request(...)           menu / another slot or entry once / ROM loader, next reset
 *   mb_client_install_*()            write a new image into the other slot (A/B update)
 *   mb_client_recv(...)              ... or receive one over a byte stream (OTA)
 *
 * OS hooks (docs/OS-INTEGRATION.md): the next boot, reboots, crashes, power-off
 *   mb_client_next(action, target, args, how)   what the next boot does, once: the menu,
 *                         an entry or slot (with args), flash mode, the ROM loader
 *   mb_client_reboot(reason, msg)   reset now, telling the next boot why
 *   mb_client_panic(msg) / mb_client_fault(pc, lr, info)   give up: counted as a crash
 *   mb_client_poweroff(msg)          off (where the chip can), noted as a clean shutdown
 *   mb_client_last_end(&end)         how the previous run ended (reason, message, address)
 *   mb_client_slot_info / set_active / rollback / entries / loader_info
 *   client/mb_ctl.h: all of it as shell commands (`mbctl ...`) for the OS's own shell
 *
 * How a request travels (mb_client_transport(), picked for you):
 *   MB_VIA_MAILBOX  RAM, read once by the next boot: no flash write, lost on a power cut.
 *                   When this boot's handoff (v2) says the bootloader reads one.
 *   MB_VIA_FLASH    the boot log (control service): survives a power cut. Asked for
 *                   explicitly (how = MB_VIA_FLASH), or when there is no mailbox.
 *   MB_VIA_LEGACY   the boot log's old one-shot requests (mb_client_request): any
 *                   MimiBoot, no handoff needed; menu, entry, slot, flash mode, ROM only.
 * The older calls stay: mb_client_request() writes the log directly (always works),
 * mb_client_control() / mb_client_reboot_*() go through the control service.
 */
#ifndef MIMIBOOT_CLIENT_H
#define MIMIBOOT_CLIENT_H

#include "core/mimiboot.h"

typedef struct {
    int slot;  /* the slot this image runs from (MB_SLOT_NONE: not booted by MimiBoot) */
    int state; /* its log state: MB_ST_TRIAL means "confirm me" */
    int tries_left;
    int active;    /* the preferred GOOD A/B slot */
    int last_kind; /* how this boot was chosen (MB_KIND_*) */
    int strikes;   /* watchdog resets in a row (crash-loop guard) */
    uint32_t version, security_version, min_security;
    bool handoff; /* a valid handoff was received this boot */
    char name[32];
    char entry[16]; /* config entry we were booted as ("" if unknown) */
} mb_client_status_t;

int mb_client_init(const mb_port_t *port);
void mb_client_set_handoff(volatile mb_handoff_t *h);
const mb_handoff_t *mb_client_handoff(void); /* NULL: none this boot */
const char *mb_client_args(void);            /* never NULL */
int mb_client_status(mb_client_status_t *st);
int mb_client_confirm(void);
int mb_client_reject(int slot);              /* mark another slot BAD (until its image changes) */
int mb_client_vacate(int slot);              /* empty another slot: its header erased, its log record cleared */
int mb_client_request(int request, int arg); /* MB_REQ_MENU / _BOOT_ONCE(slot) / _BOOTSEL / _FLASH */
int mb_client_request_entry(const char *entry, const char *args); /* MB_REQ_ENTRY_ONCE by name */

/* A/B update into `slot` (normally the one we are *not* running from;
 * writing your own slot or golden is refused). The header is written last,
 * after the payload hashed correctly, so a half-written image is never
 * seen as one. The bootloader boots it as a trial on the next reset.
 * Writes are in order (offset = what has been written so far; a chunk sent
 * again is accepted and ignored) and of any size: the library gathers whole
 * flash pages and programs each once, so flash with write-once units (STM32
 * L4/G0/G4 ECC, SAM D21 rows) needs nothing from the caller.
 * install_abort() gives up: the slot is left empty (its header was erased at
 * begin), the library ready for a new begin.
 * An LMS-signed image (MB_IMG_F_LMS) carries its signature in the file's header
 * sector (a TLV at offset 256, mbtool's lms_sig_of): hand it over with
 * install_sig() before begin; it is checked there and written into the slot.
 * Encrypted images (MB_IMG_F_ENCRYPTED) are refused with MB_E_UNSUPP, here
 * and in mb_client_recv(): only the bootloader holds the decryption key, so
 * they go to MimiBoot's console (mbtool install) or its SMP. */
int mb_client_install_sig(const void *sig, size_t len); /* LMS-signed images: the signature, before begin */
int mb_client_install_begin(int slot, const mb_image_hdr_t *hdr);
int mb_client_install_write(uint32_t offset, const void *data, size_t len);
int mb_client_install_end(void);
int mb_client_install_abort(void);

/* OTA: run the mb_recv protocol on a byte stream (a console, a socket...)
 * straight into `slot` through the install functions above. */
int mb_client_recv(int slot, void *io, int (*getc)(void *io, uint32_t ms), void (*puts)(void *io, const char *s),
                   uint16_t max_frame);

uint32_t mb_client_capabilities(void);

/* ---- OS hooks ---------------------------------------------------------------------- */
#define MB_VIA_AUTO     0       /* how: the mailbox when there is one, else the log */
#define MB_VIA_FLASH    1       /* how: the log in flash (survives a power cut); also a result */
#define MB_VIA_MAILBOX  2       /* result: RAM, for the next reset */
#define MB_VIA_LEGACY   3       /* result: the log's old one-shot request */
int mb_client_transport(void);                          /* MB_VIA_MAILBOX / _FLASH / _LEGACY */
/* action MB_CONTROL_*: target = an entry name (ENTRY) or a slot name (SLOT), args = the
 * command line for that boot (NULL: the entry's own). >0: how it went (MB_VIA_*), <0: error.
 * A mailbox request takes effect with the next mb_client_reboot() (or any reset this
 * library does); a log request at the next reset of any kind. */
int mb_client_next(unsigned action, const char *target, const char *args, int how);
int mb_client_next_boot(const mb_control_request_t *q, int how);
/* reset now (doesn't return; MB_E_UNSUPP when the port can't). reason MB_END_*: REBOOT, UPDATE... */
int mb_client_reboot(int reason, const char *msg);
/* give up: noted as a crash (the crash-loop guard counts it; after a few in a row the
 * previous image boots instead). Safe from a fault handler: RAM only, never flash. Without
 * the mailbox, a watchdog reset where the port has one. pc for panic: the caller. */
void mb_client_panic(const char *msg) __attribute__((noreturn));
void mb_client_fault(uint32_t pc, uint32_t lr, uint32_t info) __attribute__((noreturn));
int mb_client_poweroff(const char *msg);                /* MB_E_UNSUPP: this chip/port can't */
int mb_client_last_end(mb_end_t *out);                  /* MB_E_UNSUPP without a v2 handoff */

typedef struct {
    int slot;
    char name[8];               /* "a", "b", "g", ... */
    uint8_t role;               /* MB_ROLE_* */
    uint32_t size;              /* bytes */
    bool present;               /* a valid header */
    bool running;               /* this image */
    bool active;                /* the preferred A/B slot */
    bool below_floor;           /* under the rollback floor: won't boot */
    uint8_t format;             /* MB_FMT_* */
    uint8_t state;              /* MB_ST_* for this image (NEW: not booted yet) */
    uint8_t bad_reason;         /* MB_BAD_* */
    uint8_t tries_left;
    uint32_t version, security_version, flags, payload_size;
    uint64_t image_id;
    char image_name[32];
} mb_client_slot_t;
int mb_client_slot_info(int slot, mb_client_slot_t *out);
/* make another confirmed A/B image the preferred one (GOOD, at or above the floor) */
int mb_client_set_active(int slot);
int mb_client_rollback(void);                           /* set_active(the other A/B slot) */

typedef struct {
    char name[16], title[32];
    uint8_t slot;               /* MB_SLOT_AB for "the A/B pair" */
    bool is_default;
} mb_client_entry_t;
int mb_client_entries(mb_client_entry_t *out, int max); /* how many (the built-in ones without a config) */

typedef struct {
    const char *board, *target;
    int n_slots;
    uint32_t version;           /* MB_VERSION() of the bootloader */
    uint32_t caps;              /* MB_CAP_* */
    uint64_t features;          /* MB_HF_* (v2 handoffs) */
    int handoff_version;        /* 1, 2 */
    uint32_t boot_ms;
} mb_client_loader_t;
int mb_client_loader_info(mb_client_loader_t *out);    /* MB_E_UNSUPP: no handoff (board and layout still filled) */
int mb_client_control(const mb_control_request_t *request, bool reboot_now);
int mb_client_reboot_menu(void);
int mb_client_reboot_config(void);
int mb_client_reboot_profile(const char *entry, mb_topology_t profile, const char *args);
int mb_client_get_config(char *, size_t);
int mb_client_set_config(const char *, size_t, char *, size_t);
int mb_client_set_default(const char *);
int mb_client_other_slot(void); /* the A/B slot we don't run from */

#endif
