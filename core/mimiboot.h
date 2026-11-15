/*
 * MimiBoot-Mu "Komorebi" - core API
 */
#ifndef MIMIBOOT_H
#define MIMIBOOT_H

#include "core/mb_port.h"
#include "mimiboot/mb_bcl.h"
#include "mimiboot/mb_record.h"

#define MIMIBOOT_VERSION        "3.0.0"
#define MIMIBOOT_NAME           "MimiBoot-Mu"
#define MIMIBOOT_VERSION_NUM    MB_VERSION(3, 0, 0)
#define MIMIBOOT_CODENAME       "Komorebi"

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

/* ECDSA P-256 over a SHA-256 digest (MB_FEAT_ECDSA): sig = r || s, pub = X || Y, big-endian */
bool mb_ecdsa_p256_verify(const uint8_t sig[64], const uint8_t digest[32], const uint8_t pub[64]);

/* ---- LMS signatures (MB_FEAT_LMS, core/mb_lms.c) -------------------------------
 * Single-level LMS (RFC 8554 / SP 800-208), SHA-256 or SHA-256/192. An image
 * signed with LMS has MB_IMG_F_SIGNED | MB_IMG_F_LMS, key_id = the first 4 bytes
 * of the key's I (LE), and its signature in the header sector's TLV list
 * (MB_TLV_LMS_SIG) over the same bytes Ed25519 signs. The signature is read
 * through `rd` (offset, length), in order. */
#define MB_TLV_LMS_SIG      0x4C
#ifndef MB_LMS_SIG_MAX
#define MB_LMS_SIG_MAX      2988        /* the largest that fits the header sector: H25 / W4, SHA-256 */
#endif
typedef int (*mb_lms_read_t)(void* ctx, uint32_t off, void* buf, size_t n);
typedef struct { const uint8_t* sig; uint32_t len; } mb_lms_ram_t;  /* ctx for mb_lms_read_ram */
int    mb_lms_read_ram(void* ctx, uint32_t off, void* buf, size_t n);
size_t mb_lms_sig_len(const uint8_t* pub);     /* the signature size this key makes; 0: unsupported key */
size_t mb_lms_pub_len(const uint8_t* pub);     /* 56 or 48; 0: unsupported */
uint32_t mb_lms_key_id(const uint8_t* pub);
bool   mb_lms_verify(const void* msg, size_t msg_len, const uint8_t* pub, mb_lms_read_t rd, void* ctx, uint32_t sig_len);
/* An upload's LMS signature (recv 'S' frame, SMP header sector, mb_client_install_sig),
 * held from before the slot is erased until it is written into the header sector. */
typedef struct { uint16_t len; uint8_t buf[MB_FEAT_LMS ? MB_LMS_SIG_MAX : 1]; } mb_upload_sig_t;
extern mb_upload_sig_t mb_upload_sig;

/* ---- encrypted images (MB_FEAT_ENC, core/mb_enc.c) ----------------------------
 * MCUboot's scheme, so imgtool and MimiBoot agree: the payload is AES-CTR
 * (128 or 256) under a random key, counter block = 12 zero bytes + the
 * big-endian block number from the payload start. The key travels in an
 * ECIES-X25519 envelope (MCUboot TLV 0x33): ephemeral public key (32) ||
 * HMAC-SHA256 tag (32) || the key, AES-CTR-encrypted with a zero counter (16/32),
 * keys from HKDF-SHA256(no salt, info "MCUBoot_ECIES_v1"). Hash and signature
 * always cover the plaintext. */
#define MB_ENC_TLV_X25519   0x33
#define MB_ENC_ENV_MAX      (4 + 32 + 32 + 32)  /* TLV head (type, 0, length LE) + the largest envelope */

typedef struct { uint32_t sk[MB_FEAT_ENC ? 120 : 1]; uint32_t rounds; } mb_aes_t;
extern mb_aes_t mb_upload_key;      /* the image being received (recv or SMP, one at a time), when it came encrypted */
bool mb_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);    /* false: all-zero result */
void mb_hmac_sha256(const uint8_t* key, size_t key_len, const void* msg, size_t len, uint8_t out[32]);
void mb_hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const void* info, size_t info_len, uint8_t* okm, size_t okm_len);
bool mb_aes_init(mb_aes_t* a, const uint8_t* key, size_t len);                         /* 16 or 32 bytes */
void mb_aes_block(const mb_aes_t* a, const uint8_t in[16], uint8_t out[16]);
/* XOR the keystream for byte offset `off` (counter = nonce's last 32 bits, big-endian, + off/16) into buf */
void mb_aes_ctr(const mb_aes_t* a, const uint8_t nonce[16], uint32_t off, uint8_t* buf, size_t n);
void mb_aes_clear(mb_aes_t* a);
/* env = the TLV (head included), n its size. On MB_OK `a` holds the image key.
 * MB_E_CORRUPT: not an envelope; MB_E_SIGNATURE: not made for this device's key. */
int  mb_enc_unwrap(mb_aes_t* a, const uint8_t* env, size_t n, const uint8_t priv[32]);

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

/* Proof tokens (MB_FEAT_FAULT_HARDENING): written only on the code path where
 * a check really passed, and checked again right before an image starts. They
 * are multi-bit values, not booleans, so a skipped instruction or a flipped bit
 * doesn't produce one. */
#define MB_PROOF_SIG        0x6C1E5A93u     /* signature verified against a trusted key */
#define MB_PROOF_UNSIGNED   0x1B7C30E6u     /* no signature, and this build allows that */
#define MB_PROOF_HASH       0x3B97C42Du     /* payload SHA-256 matched (or a raw image: nothing to hash) */

/* 0 when the n bytes are equal; no early exit (time doesn't depend on where they differ) */
uint32_t mb_ct_diff(const void* a, const void* b, size_t n);

typedef struct {
    bool header_ok;             /* magic, version, CRC, sizes */
    int  hash_state;            /* 0 not checked, 1 good, -1 bad */
    int  sig_state;             /* 0 not checked, 1 good, -1 bad / missing when required */
    uint32_t proof_sig, proof_hash;   /* MB_PROOF_* when the check passed this boot, else 0 */
    uint8_t fmt;                /* MB_FMT_* */
    uint32_t hash_off, hash_len;/* digest coverage, from the slot start */
    mb_image_hdr_t hdr;
#if MB_FEAT_LMS
    /* where an LMS signature is: an upload's, in RAM (sig_ram), or the slot's own
     * header-sector TLV list at flash offset tlv_flash (0: none). (Only in LMS
     * builds: the bootloader keeps one of these per slot, and RAM is tight.) */
    const uint8_t* sig_ram;
    uint32_t sig_ram_len;
    uint32_t tlv_flash;
#endif
} mb_slot_info_t;

/* Header-sector TLV list (file offset 256..): type u8, 0, length u16 LE, data; 0xFF ends it.
 * Find `type` in a list in RAM: MB_OK with the data at area[*at], *len bytes, MB_E_BADARG if absent,
 * MB_E_CORRUPT if the list is malformed, holds a type twice, holds a type other than the
 * key envelope and the LMS signature, or has anything but 0xFF after its end. */
#define MB_TLV_AREA         (MB_IMG_PAYLOAD_OFF - MB_IMG_HDR_SIZE)
int mb_tlv_find(const uint8_t* area, size_t n, uint8_t type, size_t* at, size_t* len);

/* foreign formats (core/mb_formats.c); out->hdr is synthesized */
int mb_mcuboot_probe(const mb_port_t* p, int slot, mb_slot_info_t* out);
/* MCUboot direct-xip confirmation: the slot's image trailer has a valid magic
 * and image_ok set (Zephyr's boot_write_img_confirmed(), imgtool --confirm) */
bool mb_mcuboot_confirmed(const mb_port_t* p, int slot);
int mb_raw_probe(const mb_port_t* p, int slot, mb_slot_info_t* out);

int  mb_image_read_header(const mb_port_t* p, int slot, mb_slot_info_t* out);
int  mb_image_verify(const mb_port_t* p, int slot, mb_slot_info_t* info);   /* full SHA-256 of the payload */
int  mb_image_check_sig(const mb_port_t* p, mb_slot_info_t* info);         /* MB_OK, or MB_E_SIGNATURE */
void mb_image_seal(mb_image_hdr_t* h);                                      /* sets hdr_crc */
int  mb_image_check_header(const mb_port_t* p, const mb_image_hdr_t* h, uint32_t room);

/* ---- protected rollback floors (core/mb_floor.c) -------------------------------- */
int mb_floor_get(const mb_port_t* p, uint32_t out[MB_FLOOR_COUNT]);     /* zeros (+MB_E_UNSUPP) without a store */
int mb_floor_raise(const mb_port_t* p, int which, uint32_t value);      /* never lowers; MB_E_NOSPACE when full */
int mb_store_count(const mb_port_t* p, int tag, uint32_t value);        /* entries with this tag and value */
int mb_store_append(const mb_port_t* p, int tag, uint32_t value);       /* one more entry (MB_STORE_S1_ATTEMPT) */

/* ---- two-stage builds (core/mb_stage0.c) ----------------------------------------
 * Stage 0 picks the stage 1 to run; stage 1 confirms itself once it works. */
#define MB_STAGE1_TRIES 3       /* boots of an unconfirmed stage 1 before it is passed over */
typedef struct {
    int slot;                   /* the stage-1 slot to start, or -1: none usable */
    bool trial;                 /* not confirmed yet: arm the watchdog, an attempt was recorded */
    mb_slot_info_t info;        /* its header and check results */
} mb_stage0_choice_t;
int  mb_stage0_choose(const mb_port_t* p, mb_stage0_choice_t* out);
int  mb_stage1_confirm(const mb_port_t* p);                             /* stage 1: "I work" (idempotent) */
int  mb_stage1_accepts(const mb_port_t* p, int slot, const mb_image_hdr_t* h);   /* slot role vs MB_IMG_F_STAGE1 */
int  mb_stage1_check_sig(const mb_port_t* p, mb_slot_info_t* info);     /* against the stage-1 keys only */
int  mb_stage1_vectors_ok(const mb_port_t* p, int slot, const mb_image_hdr_t* h);  /* reset vector inside, as linked */

/* ---- key revocation (REVOKE_KEYS) ----------------------------------------------------
 * A signing key (Ed25519 or P-256, image or stage-1 keys) named by its key_id can
 * be revoked with a statement from one of the port's revoke_keys:
 *   Ed25519 over "MimiBoot revoke v1\0" || target[16] || key_id (LE)
 * It is recorded in the protected store and every signature check skips that
 * key from then on. Refused if no unrevoked key would be left in its keyring. */
bool mb_key_revoked(const mb_port_t* p, uint32_t key_id);
int  mb_key_revoke(const mb_port_t* p, uint32_t key_id, const uint8_t sig[64]);

/* The slot whose image is being checked right now (MB_SLOT_NONE otherwise):
 * a port's fault handler records it so the next boot can mark it bad. */
extern volatile uint8_t mb_checking_slot;

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
    uint32_t version;           /* MB_FEAT_CFG_SIGNED: the signed version (rollback floor) */
    int errors;                 /* lines that didn't parse */
} mb_config_t;

void mb_config_builtin(const mb_port_t* p, mb_config_t* c);
int  mb_config_parse(const mb_port_t* p, const char* text, size_t len, mb_config_t* c, char* err, size_t errcap);
int  mb_config_load(const mb_port_t* p, mb_config_t* c);
int  mb_config_read_text(const mb_port_t* p, char* buf, size_t cap, uint32_t* seq);  /* length, or <0 */
int  mb_config_save(const mb_port_t* p, const char* text, size_t len);               /* atomic; MB_E_REFUSED with CFG_SIGNED */
/* MB_FEAT_CFG_SIGNED: Ed25519 (a key from p->keys) over
 *   "MimiBoot config v1\0" || target[16] || version (u32 LE) || len (u32 LE) || SHA-256(text)
 * Refused unless the signature checks and version isn't below the config floor. */
int  mb_config_save_signed(const mb_port_t* p, const char* text, size_t len, uint32_t version, const uint8_t sig[64]);
int  mb_config_erase(const mb_port_t* p);                                            /* back to the built-in config */
int mb_config_set_default(const mb_port_t*,const char*);
int mb_config_validate_save(const mb_port_t*,const char*,size_t,char*,size_t);
int mb_grub_translate(const char*,size_t,char*,size_t,char*,size_t);
int mb_control_consume(const mb_port_t*,mb_bcl_rec_t*,const mb_config_t*,mb_topology_t*,int*);
/* Check a control request and store it into a log record in RAM (consumed like one from flash) */
int mb_control_put(const mb_port_t* p, mb_bcl_rec_t* r, const mb_config_t* c, const mb_control_request_t* q);
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
#define MB_F_AGAIN      0x04    /* not the first decision this power-up: the reset was counted already */

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
 *   host: 'H' + 256-byte image header          dev: "MB OK\n" | "MB KEY\n" | "MB ERR <why>\n"
 *   (MB KEY: the header says MB_IMG_F_ENCRYPTED)
 *   host: 'K' u16 len, envelope, u32 crc        dev: "MB OK\n" | "MB SIG\n" | "MB ERR <why>\n"
 *   (MB SIG: the header says MB_IMG_F_LMS; it comes after MB KEY when both apply)
 *   host: 'S' u16 len, LMS signature, u32 crc   dev: "MB OK\n" | "MB ERR <why>\n"
 *   host: 'D' u32 off, u16 len, data, u32 crc   dev: "MB OK <off>\n" | "MB ERR ..." (resend)
 *   (an encrypted image's data frames carry ciphertext; the sink gets plaintext)
 *   host: 'E'                                   dev: "MB DONE\n" | "MB ERR <why>\n"
 *   host: 'X' at any point aborts
 */
typedef struct {
    void* ctx;
    int  (*getc)(void* ctx, uint32_t timeout_ms);           /* -1 timeout */
    void (*puts)(void* ctx, const char* s);
    uint16_t max_frame;                                     /* the receiver's buffer (<= 1024) */
    const char* where;                                      /* shown in READY */
    const uint8_t* enc_key;                                 /* X25519 key for encrypted images (NULL: refused) */
    /* the sink */
    int  (*begin)(void* ctx, const mb_image_hdr_t* hdr);    /* validate, erase */
    int  (*data)(void* ctx, uint32_t off, const void* d, size_t n);
    int  (*end)(void* ctx);                                 /* verify what landed, commit */
} mb_recv_t;

int mb_recv(const mb_recv_t* r, mb_image_hdr_t* hdr_out);

/* the flash-slot sink (ctx = mb_slot_sink_t*) */
typedef struct { const mb_port_t* p; int slot; mb_image_hdr_t hdr; } mb_slot_sink_t;
int mb_sink_slot_check(void* ctx, const mb_image_hdr_t* hdr);     /* begin without the erase */
int mb_sink_slot_begin(void* ctx, const mb_image_hdr_t* hdr);
int mb_sink_slot_data(void* ctx, uint32_t off, const void* d, size_t n);
int mb_sink_slot_end(void* ctx);
int mb_sink_slot_tlvs(void* ctx);           /* after an erase of your own: the LMS signature into the header sector */

/* Start an image that is already in RAM at hdr->load_addr and checked
 * (console `ramboot`): signature + hash re-checked, handoff, launch. */
int mb_boot_ram(const mb_port_t* p, const mb_bcl_t* log, const mb_config_t* cfg, const mb_image_hdr_t* hdr, const char* args);

/* ---- mcumgr / SMP over the console (core/mb_smp.c, MB_FEAT_SMP) -----------------------
 * The console calls this for each line that starts with an SMP marker (0x06 0x09
 * first, 0x04 0x14 continuation), with the two marker bytes already read. It reads
 * the rest of the line; when a packet is complete it runs it and replies. */
void mb_smp_frame(const mb_port_t* p, mb_bcl_t* log, bool locked, bool first);

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
int mb_slot_write_lms(const mb_port_t* p, int slot, const uint8_t* sig, size_t len);   /* into the erased header sector */

/* ---- handoff and mailbox (mb_handoff_size(): core/mb_port.h) --------------------------- */
/* core/mb_mailbox.c: read (and clear) the mailbox the last image left, once per power-up,
 * before the boot decision. mb_last_end then says how the previous run ended (the next
 * handoff carries it); mb_mailbox_next holds its request until the decision takes it
 * (version 0: none). mb_mailbox_crashed(): it ended in a panic or a fault (a strike). */
extern mb_end_t mb_last_end;
extern mb_control_request_t mb_mailbox_next;
void mb_mailbox_take(const mb_port_t* p, const mb_bcl_rec_t* log);
bool mb_mailbox_crashed(void);
uint64_t mb_handoff_features(const mb_port_t* p);
void mb_handoff_build(const mb_port_t* p, const mb_bcl_rec_t* log, const mb_config_t* cfg, const mb_image_hdr_t* hdr,
                      const mb_choice_t* c, mb_handoff_t* out);

#endif
