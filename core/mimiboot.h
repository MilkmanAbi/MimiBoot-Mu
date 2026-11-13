/*
 * MimiBoot 1.1 "Torii" - core API
 */
#ifndef MIMIBOOT_H
#define MIMIBOOT_H

#include "core/mb_port.h"
#include "mimiboot/mb_bcl.h"

#define MIMIBOOT_VERSION        "2.0.0"
#define MIMIBOOT_NAME           "MimiBoot-Night"
#define MIMIBOOT_VERSION_NUM    MB_VERSION(2, 0, 0)
#define MIMIBOOT_CODENAME       "Night"

/* MB_DEFAULT_TRIES, MB_DEFAULT_TRIAL_MS, MB_STRIKES_MAX: core/mb_features.h (configurable) */
#define MB_FLASH_WAIT_MS        60000   /* flash mode: how long to wait for a host to show up */
#define MB_FLASH_IDLE_MS        300000  /* flash mode: idle this long at the prompt -> boot normally */

/* ---- checksums and crypto ---------------------------------------------------- */
uint32_t mb_crc32(uint32_t crc, const void* data, size_t len);     /* crc = 0 to start */

typedef struct { uint32_t h[8]; uint8_t buf[64]; uint64_t len; uint32_t used; } mb_sha256_t;
void mb_sha256_init(mb_sha256_t* s);
void mb_sha256_update(mb_sha256_t* s, const void* data, size_t len);
void mb_sha256_final(mb_sha256_t* s, uint8_t out[32]);

typedef struct { uint64_t h[8]; uint8_t buf[128]; uint64_t len; uint32_t used; } mb_sha512_t;
void mb_sha512_init(mb_sha512_t* s);
void mb_sha512_update(mb_sha512_t* s, const void* data, size_t len);
void mb_sha512_final(mb_sha512_t* s, uint8_t out[64]);

/* Ed25519 (RFC 8032) verification only: the private key never sees the device */
bool mb_ed25519_verify(const uint8_t sig[64], const void* msg, size_t len, const uint8_t pub[32]);

/* ---- slots ------------------------------------------------------------------ */
const char* mb_slot_name(const mb_port_t* p, int slot);            /* "a" "b" "g" "c" ... */
int  mb_slot_parse(const mb_port_t* p, const char* s);             /* name -> index, -1 */
int  mb_slot_role(const mb_port_t* p, int slot);

/* What a slot holds. Foreign formats are described with a synthesized
 * mb_image_hdr_t (name, version, sha256 = the format's own digest, payload =
 * where the code starts) so policy, log and console treat every format alike;
 * hash_off/hash_len say which bytes of the slot the digest covers. */
#define MB_FMT_NONE     0
#define MB_FMT_NATIVE   1       /* MIMG header sector + payload */
#define MB_FMT_MCUBOOT  2       /* MCUboot header + image + TLVs (Zephyr) */
#define MB_FMT_RAW      3       /* bare vector table, no metadata: no digest */

typedef struct {
    bool header_ok;             /* magic, version, CRC, sizes */
    int  hash_state;            /* 0 not checked, 1 good, -1 bad */
    int  sig_state;             /* 0 not checked, 1 good, -1 bad / missing when required */
    uint8_t fmt;                /* MB_FMT_* */
    uint32_t hash_off, hash_len;/* digest coverage, from the slot start */
    mb_image_hdr_t hdr;
} mb_slot_info_t;

/* foreign formats (core/mb_formats.c); out->hdr is synthesized */
int mb_mcuboot_probe(const mb_port_t* p, int slot, mb_slot_info_t* out);
int mb_raw_probe(const mb_port_t* p, int slot, mb_slot_info_t* out);

int  mb_image_read_header(const mb_port_t* p, int slot, mb_slot_info_t* out);
int  mb_image_verify(const mb_port_t* p, int slot, mb_slot_info_t* info);   /* full SHA-256 of the payload */
int  mb_image_check_sig(const mb_port_t* p, mb_slot_info_t* info);         /* MB_OK, or MB_E_SIGNATURE */
void mb_image_seal(mb_image_hdr_t* h);                                      /* sets hdr_crc */
int  mb_image_check_header(const mb_port_t* p, const mb_image_hdr_t* h, uint32_t room);

/* ---- boot control log -------------------------------------------------------- */
typedef struct {
    const mb_port_t* port;
    mb_bcl_rec_t cur;           /* the current state */
    int sector;                 /* where the next record goes: 0 or 1 (-1: none yet) */
    uint32_t next_off;          /* offset of the next free record in that sector */
    uint32_t generation;
    bool fresh;                 /* no valid log found: cur is the default state */
} mb_bcl_t;

int  mb_bcl_load(mb_bcl_t* b, const mb_port_t* p);
int  mb_bcl_commit(mb_bcl_t* b, const mb_bcl_rec_t* next);   /* append (compacts when full) */
void mb_bcl_default(mb_bcl_rec_t* r);

/* ---- boot config (a small text file, GRUB-ish) ------------------------------------
 *
 *     timeout 5                    # menu countdown, seconds (0: no menu unless asked)
 *     default os                   # entry name or number
 *     entry os
 *         title My OS (Arm)
 *         slot ab                  # the A/B pair, with update/rollback policy
 *         args console=usb quiet
 *     entry hazard3
 *         slot c
 *         arch riscv               # must match the image
 *         args init=/bin/sh
 *     entry recovery
 *         slot g
 *
 * Kept in its own two flash sectors (seq + CRC, written atomically). Anything
 * that doesn't parse is ignored line by line; with nothing usable the
 * built-in config (ab, then golden) applies. Security settings are not
 * config keys: they are compiled in (mb_port_t.keys / require_signature).
 */
#define MB_MAX_ENTRIES      8
#define MB_CFG_MAX          3840            /* text bytes */

typedef struct {
    char name[16];
    char title[32];
    uint8_t slot;               /* slot index or MB_SLOT_AB */
    uint8_t arch;               /* MB_ARCH_ANY = whatever the image says */
    mb_topology_t topology;
    char args[MB_ARGS_MAX];
} mb_entry_t;

typedef struct {
    int n;
    mb_entry_t e[MB_MAX_ENTRIES];
    int def;                    /* default entry index */
    int timeout_s;              /* -1: not set (port default) */
    bool from_flash;            /* false: built-in */
    uint32_t seq;
    int errors;                 /* lines that didn't parse */
} mb_config_t;

void mb_config_builtin(const mb_port_t* p, mb_config_t* c);
int  mb_config_parse(const mb_port_t* p, const char* text, size_t len, mb_config_t* c, char* err, size_t errcap);
int  mb_config_load(const mb_port_t* p, mb_config_t* c);
int  mb_config_read_text(const mb_port_t* p, char* buf, size_t cap, uint32_t* seq);  /* length, or <0 */
int  mb_config_save(const mb_port_t* p, const char* text, size_t len);               /* atomic */
int mb_config_set_default(const mb_port_t*,const char*);
int mb_config_validate_save(const mb_port_t*,const char*,size_t,char*,size_t);
int mb_grub_translate(const char*,size_t,char*,size_t,char*,size_t);
int mb_control_consume(const mb_port_t*,mb_bcl_rec_t*,const mb_config_t*,mb_topology_t*,int*);
struct mb_choice;
void mb_control_requeue(mb_bcl_rec_t*,const mb_config_t*,const struct mb_choice*);
int  mb_config_find(const mb_config_t* c, const char* name);                         /* name or number */

/* ---- policy: pick what to boot -------------------------------------------------- */
typedef struct mb_choice {
    int slot;                   /* slot index or MB_SLOT_NONE */
    int kind;                   /* MB_KIND_* */
    int entry;                  /* config entry index, -1 none */
    bool trial;                 /* arm the watchdog */
    bool want_menu;             /* stop in the console (key, request, nothing bootable) */
    bool want_rom;              /* reboot into the ROM loader */
    mb_topology_t topology;
    bool config_mode;
    int control_error;
    bool flash_mode;            /* stop in the console, ready to receive images (MB_REQ_FLASH) */
    char args[MB_ARGS_MAX];     /* the command line for the image */
} mb_choice_t;

typedef struct {
    mb_choice_t choice;
    mb_bcl_rec_t base;          /* log brought up to date: new/vanished images, requests, bad marks */
    mb_bcl_rec_t boot;          /* base + the bookkeeping for booting choice.slot */
    bool base_dirty, boot_dirty;
} mb_plan_t;

#define MB_F_MENU       0x01    /* stop in the menu (key pressed) */
#define MB_F_NO_TRIAL   0x02    /* only images that need no log write (the log is failing) */

/* Reconcile the log with what is in flash, consume requests, resolve the
 * entry (one-shot, else the default), walk its candidates verifying each
 * (CRC, target, arch, rollback floor, signature, SHA-256) and say what to
 * boot. Writes nothing: the caller commits plan.boot right before launching
 * (or plan.base when stopping in the menu). */
int mb_decide(const mb_port_t* p, const mb_bcl_t* log, const mb_config_t* cfg, mb_slot_info_t info[MB_MAX_SLOTS],
              unsigned flags, mb_plan_t* plan);

/* The same for an entry / a slot picked by hand. args NULL = the entry's own.
 * force = boot even a BAD slot (it must still pass the hash and signature). */
int mb_plan_entry(const mb_port_t* p, const mb_bcl_t* log, const mb_config_t* cfg, mb_slot_info_t info[MB_MAX_SLOTS],
                  int entry, const char* args, mb_plan_t* plan);
int mb_plan_slot(const mb_port_t* p, const mb_bcl_t* log, mb_slot_info_t info[MB_MAX_SLOTS], int slot, bool force,
                 const char* args, mb_plan_t* plan);

/* Commit plan.boot, write the handoff, launch. Returns only if the launch
 * failed (the slot is then marked bad). */
int mb_boot(const mb_port_t* p, mb_bcl_t* log, const mb_config_t* cfg, mb_slot_info_t info[MB_MAX_SLOTS], const mb_plan_t* plan);

/* The whole bootloader. Doesn't return on hardware (the simulator's launch
 * "returns" by longjmp). */
void mb_main(const mb_port_t* p);

/* ---- receiving images (console upload, OTA from a running app) -------------------
 *
 *   dev:  "MB READY <where> <max frame>\n"
 *   host: 'H' + 256-byte image header          dev: "MB OK\n" | "MB ERR <why>\n"
 *   host: 'D' u32 off, u16 len, data, u32 crc   dev: "MB OK <off>\n" | "MB ERR ..." (resend)
 *   host: 'E'                                   dev: "MB DONE\n" | "MB ERR <why>\n"
 *   host: 'X' at any point aborts
 */
typedef struct {
    void* ctx;
    int  (*getc)(void* ctx, uint32_t timeout_ms);           /* -1 timeout */
    void (*puts)(void* ctx, const char* s);
    uint16_t max_frame;                                     /* the receiver's buffer (<= 1024) */
    const char* where;                                      /* shown in READY */
    /* the sink */
    int  (*begin)(void* ctx, const mb_image_hdr_t* hdr);    /* validate, erase */
    int  (*data)(void* ctx, uint32_t off, const void* d, size_t n);
    int  (*end)(void* ctx);                                 /* verify what landed, commit */
} mb_recv_t;

int mb_recv(const mb_recv_t* r, mb_image_hdr_t* hdr_out);

/* the flash-slot sink (ctx = mb_slot_sink_t*) */
typedef struct { const mb_port_t* p; int slot; mb_image_hdr_t hdr; } mb_slot_sink_t;
int mb_sink_slot_begin(void* ctx, const mb_image_hdr_t* hdr);
int mb_sink_slot_data(void* ctx, uint32_t off, const void* d, size_t n);
int mb_sink_slot_end(void* ctx);

/* Start an image that is already in RAM at hdr->load_addr and checked
 * (console `ramboot`): signature + hash re-checked, handoff, launch. */
int mb_boot_ram(const mb_port_t* p, const mb_bcl_t* log, const mb_config_t* cfg, const mb_image_hdr_t* hdr, const char* args);

/* ---- console ---------------------------------------------------------------------- */
/* Boot menu + command line. Returns when the caller should decide again;
 * boots directly when the user picks something. */
void mb_console(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, mb_slot_info_t info[MB_MAX_SLOTS], const mb_plan_t* plan);
void mb_printf(const mb_port_t* p, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

/* The menu mb_main shows when it stops: the text console by default. A port
 * can override it with its own UI by setting mb_menu_override (the watch
 * variant registers a graphical LCD menu: port/rp2350/mb_watch.c +
 * core/mb_gfx.c). Left NULL, mb_menu falls back to the text console. A
 * function pointer, not a weak symbol, so it works on every host too. */
typedef void (*mb_menu_fn)(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg,
                           mb_slot_info_t info[MB_MAX_SLOTS], const mb_plan_t* plan);
extern mb_menu_fn mb_menu_override;
void mb_menu(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, mb_slot_info_t info[MB_MAX_SLOTS], const mb_plan_t* plan);

/* ---- writing images ----------------------------------------------------------------- */
int mb_slot_erase(const mb_port_t* p, int slot, uint32_t bytes);          /* header sector + bytes of payload */
int mb_slot_write(const mb_port_t* p, int slot, uint32_t payload_off, const void* data, size_t len);
int mb_slot_write_header(const mb_port_t* p, int slot, const mb_image_hdr_t* hdr);

/* ---- handoff -------------------------------------------------------------------------- */
void mb_handoff_build(const mb_port_t* p, const mb_bcl_rec_t* log, const mb_config_t* cfg, const mb_image_hdr_t* hdr,
                      const mb_choice_t* c, mb_handoff_t* out);

#endif
