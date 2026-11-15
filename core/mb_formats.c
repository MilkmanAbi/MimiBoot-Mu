/*
 * MimiBoot-Mu - foreign image formats
 *
 * MCUboot (what Zephyr builds with CONFIG_BOOTLOADER_MCUBOOT=y and what
 * `imgtool sign` / `west sign` produce):
 *
 *   slot + 0              image_header (32 bytes, magic 0x96f3b83d), padded to ih_hdr_size
 *   slot + hdr_size       the image (Zephyr: the vector table is here, so the
 *                         app is linked at slot + hdr_size, usually +0x200)
 *   + img_size            protected TLVs (info 0x6908) when ih_protect_tlv_size != 0
 *   then                  TLVs (info 0x6907): SHA256, KEYHASH, ED25519, ...
 *
 * The SHA-256 TLV covers header + image + protected TLVs. The ED25519 TLV is
 * a signature over that 32-byte digest. Encrypted images, "pure" signatures
 * and non-bootable images are refused (not supported here).
 *
 * Raw: a bare Cortex-M vector table at the slot start (FreeRTOS or bare-metal
 * firmware linked for the slot address). There is no metadata, so there is
 * nothing to verify: the image id is CRC-32 of its first bytes so the boot
 * log can still tell images apart. Wrap with mbtool or imgtool for integrity.
 */
#include "core/mimiboot.h"
#include <string.h>

__attribute__((unused)) static void copy_target(mb_image_hdr_t* x, const mb_port_t* p) {
    for (size_t i = 0; i < sizeof x->target && p->target[i]; i++) x->target[i] = p->target[i];
}

#if MB_FEAT_IMG_MCUBOOT

#define MCUBOOT_MAGIC           0x96f3b83du
#define MCUBOOT_TLV_INFO        0x6907u
#define MCUBOOT_TLV_PROT_INFO   0x6908u
#define MCUBOOT_F_ENCRYPTED     (0x04u | 0x08u)     /* AES128 | AES256 */
#define MCUBOOT_F_NON_BOOTABLE  0x10u
#define MCUBOOT_F_RAM_LOAD      0x20u
#define TLV_KEYHASH             0x01u
#define TLV_SHA256              0x10u
#define TLV_ED25519             0x24u
#define TLV_SIG_PURE            0x25u
#define TLV_SEC_CNT             0x50u
#define TLV_ENC_FIRST           0x30u               /* 0x30..0x35: encryption keys */
#define TLV_ENC_LAST            0x35u
#define MCUBOOT_TLV_MAX         4096u               /* sanity bound on the TLV areas */

static uint16_t le16(const uint8_t* b) { return (uint16_t)(b[0] | b[1] << 8); }
static uint32_t le32(const uint8_t* b) { return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24; }

#define TLV_ECDSA_SIG           0x22u               /* ECDSA P-256 over the image digest, DER */

typedef struct { bool sha, sig, ecdsa, pure, enc; uint8_t sha256[32], sig64[64]; uint32_t sec_cnt; bool have_sec; } tlvs_t;

// DER  SEQUENCE { INTEGER r, INTEGER s }  ->  r || s, 32 bytes each (what imgtool writes)
static bool der_to_raw(const uint8_t* d, uint32_t n, uint8_t out[64]) {
    if (n < 8 || d[0] != 0x30 || d[1] != n - 2) return false;
    uint32_t at = 2;
    for (int part = 0; part < 2; part++) {
        if (at + 2 > n || d[at] != 0x02) return false;
        uint32_t len = d[at + 1];
        at += 2;
        if (len == 0 || len > 33 || at + len > n) return false;
        const uint8_t* v = d + at;
        if (len == 33) {                    // a leading zero keeps a high bit from reading as negative
            if (v[0] != 0) return false;
            v++;
            len--;
        }
        memset(out + 32 * part, 0, 32 - len);
        memcpy(out + 32 * part + 32 - len, v, len);
        at += d[at - 1];
    }
    return at == n;
}

// Walk one TLV area: [off] = {u16 magic, u16 total incl. this info}, then {u16 type, u16 len, data}...
static int walk(const mb_port_t* p, uint32_t base, uint32_t room, uint32_t off, uint16_t magic, uint32_t* total, tlvs_t* t) {
    uint8_t b[4];
    if (off + 4 > room || p->flash_read(base + off, b, 4) != MB_OK) return MB_E_CORRUPT;
    if (le16(b) != magic) return MB_E_CORRUPT;
    uint32_t tot = le16(b + 2);
    if (tot < 4 || tot > MCUBOOT_TLV_MAX || off + tot > room) return MB_E_CORRUPT;
    *total = tot;
    for (uint32_t at = off + 4; at < off + tot;) {
        if (at + 4 > off + tot || p->flash_read(base + at, b, 4) != MB_OK) return MB_E_CORRUPT;
        uint16_t type = le16(b), len = le16(b + 2);
        at += 4;
        if (at + len > off + tot) return MB_E_CORRUPT;
        if (type == TLV_SHA256 && len == 32) { if (p->flash_read(base + at, t->sha256, 32)) return MB_E_IO; t->sha = true; }
        else if (type == TLV_ED25519 && len == 64) { if (p->flash_read(base + at, t->sig64, 64)) return MB_E_IO; t->sig = true; }
        else if (type == TLV_ECDSA_SIG && len >= 8 && len <= 72 && !t->sig) {
            uint8_t der[72];
            if (p->flash_read(base + at, der, len)) return MB_E_IO;
            if (der_to_raw(der, len, t->sig64)) t->sig = t->ecdsa = true;
        }
        else if (type == TLV_SIG_PURE) t->pure = true;
        else if (type >= TLV_ENC_FIRST && type <= TLV_ENC_LAST) t->enc = true;
        else if (type == TLV_SEC_CNT && len == 4) {
            uint8_t v[4];
            if (p->flash_read(base + at, v, 4)) return MB_E_IO;
            t->sec_cnt = le32(v);
            t->have_sec = true;
        }
        at += len;
    }
    return MB_OK;
}

int mb_mcuboot_probe(const mb_port_t* p, int slot, mb_slot_info_t* out) {
    memset(out, 0, sizeof(*out));
    if (slot < 0 || slot >= p->layout->n_slots) return MB_E_BADARG;
    const mb_slot_def_t* r = &p->layout->slot[slot];
    uint8_t h[32];
    if (p->flash_read(r->offset, h, sizeof h) != MB_OK) return MB_E_IO;
    if (le32(h) != MCUBOOT_MAGIC) return MB_E_CORRUPT;
    uint32_t load = le32(h + 4), hdr_size = le16(h + 8), prot = le16(h + 10), img = le32(h + 12), flags = le32(h + 16);
    if (hdr_size < 32 || img == 0 || hdr_size > r->size || img > r->size - hdr_size) return MB_E_CORRUPT;
    if (flags & (MCUBOOT_F_ENCRYPTED | MCUBOOT_F_NON_BOOTABLE)) return MB_E_UNSUPP;
    uint32_t tlv_off = hdr_size + img;
    tlvs_t t;
    memset(&t, 0, sizeof t);
    uint32_t ptot = 0, utot = 0;
    if (prot) {
        if (walk(p, r->offset, r->size, tlv_off, MCUBOOT_TLV_PROT_INFO, &ptot, &t) != MB_OK || ptot != prot) return MB_E_CORRUPT;
    }
    if (walk(p, r->offset, r->size, tlv_off + prot, MCUBOOT_TLV_INFO, &utot, &t) != MB_OK) return MB_E_CORRUPT;
    if (t.enc || t.pure || !t.sha) return MB_E_UNSUPP;   // need a SHA-256 digest; no encryption, no pure signatures

    mb_image_hdr_t* x = &out->hdr;
    x->magic = MB_IMG_MAGIC;                // synthesized: never written back, never CRC-checked
    x->hdr_version = MB_IMG_HDR_VERSION;
    x->hdr_size = MB_IMG_HDR_SIZE;
    x->load_type = (flags & MCUBOOT_F_RAM_LOAD) ? MB_LOAD_RAM : MB_LOAD_CHAIN;
    x->load_addr = (flags & MCUBOOT_F_RAM_LOAD) ? load : 0;
    x->payload_offset = hdr_size;           // the code (vector table) starts here
    x->payload_size = img;
    memcpy(x->sha256, t.sha256, 32);
    x->version = MB_VERSION(h[20], h[21], le16(h + 22));
    x->security_version = t.have_sec ? t.sec_cnt : 0;
    memcpy(x->name, "mcuboot", 8);
    copy_target(x, p);
    x->arch = MB_ARCH_ANY;
    if (t.sig) {
        x->flags |= MB_IMG_F_SIGNED | (t.ecdsa ? MB_IMG_F_ECDSA : 0);
        memcpy(x->signature, t.sig64, 64);
    }
    out->header_ok = true;
    out->fmt = MB_FMT_MCUBOOT;
    out->hash_off = 0;
    out->hash_len = hdr_size + img + prot;
    return MB_OK;
}

/* The image trailer at the end of the slot (MCUboot bootutil_misc.h):
 *   magic     the last 16 bytes: with BOOT_MAX_ALIGN 8 a fixed 16-byte value,
 *             otherwise {u16 align, 14 fixed bytes}
 *   image_ok  at ALIGN_DOWN(slot_size - 16 - align, align): 0x01 = confirmed
 * In direct-xip mode (what MimiBoot's in-place A/B slots are) a Zephyr app
 * confirms itself by setting image_ok in its own slot. */
bool mb_mcuboot_confirmed(const mb_port_t* p, int slot) {
    static const uint8_t magic8[16] = { 0x77, 0xc2, 0x95, 0xf3, 0x60, 0xd2, 0xef, 0x7f,
                                        0x35, 0x52, 0x50, 0x0f, 0x2c, 0xb6, 0x79, 0x80 };
    static const uint8_t magic14[14] = { 0x2d, 0xe1, 0x5d, 0x29, 0x41, 0x0b, 0x8d, 0x77, 0x67, 0x9c, 0x11, 0x0f, 0x1f, 0x8a };
    if (slot < 0 || slot >= p->layout->n_slots) return false;
    const mb_slot_def_t* r = &p->layout->slot[slot];
    uint8_t m[16], ok;
    if (r->size < 64 || p->flash_read(r->offset + r->size - 16, m, 16) != MB_OK) return false;
    uint32_t align;
    if (!memcmp(m, magic8, 16)) align = 8;
    else if (!memcmp(m + 2, magic14, 14)) align = le16(m);
    else return false;
    if (align < 1 || align > 512 || (align & (align - 1))) return false;    // a power of two, or not a trailer
    uint32_t ok_off = (r->size - 16 - align) / align * align;
    return p->flash_read(r->offset + ok_off, &ok, 1) == MB_OK && ok == 0x01;
}

#else
int mb_mcuboot_probe(const mb_port_t* p, int slot, mb_slot_info_t* out) { (void)p; (void)slot; (void)out; return MB_E_UNSUPP; }
bool mb_mcuboot_confirmed(const mb_port_t* p, int slot) { (void)p; (void)slot; return false; }
#endif

#if MB_FEAT_IMG_RAW
int mb_raw_probe(const mb_port_t* p, int slot, mb_slot_info_t* out) {
    memset(out, 0, sizeof(*out));
    if (slot < 0 || slot >= p->layout->n_slots) return MB_E_BADARG;
    const mb_slot_def_t* r = &p->layout->slot[slot];
    uint32_t v[2];
    if (r->size < 1024 || p->flash_read(r->offset, v, sizeof v) != MB_OK) return MB_E_IO;
    // initial SP: word aligned, not blank; reset vector: a Thumb address, not blank
    if (v[0] == 0xFFFFFFFFu || v[0] == 0 || (v[0] & 3) || v[1] == 0xFFFFFFFFu || !(v[1] & 1)) return MB_E_CORRUPT;
    uint8_t buf[256];
    uint32_t c1 = 0, c4 = 0;
    for (uint32_t done = 0; done < 4096 && done < r->size; done += sizeof buf) {
        if (p->flash_read(r->offset + done, buf, sizeof buf) != MB_OK) return MB_E_IO;
        if (done < 1024) c1 = mb_crc32(c1, buf, sizeof buf);
        c4 = mb_crc32(c4, buf, sizeof buf);
    }
    mb_image_hdr_t* x = &out->hdr;
    x->magic = MB_IMG_MAGIC;
    x->hdr_version = MB_IMG_HDR_VERSION;
    x->hdr_size = MB_IMG_HDR_SIZE;
    x->load_type = MB_LOAD_CHAIN;
    x->payload_offset = 0;
    x->payload_size = r->size;              // unknown: the whole slot
    for (int i = 0; i < 4; i++) {           // image id = the first 8 bytes of "sha256"
        x->sha256[i] = (uint8_t)(c4 >> (24 - 8 * i));
        x->sha256[4 + i] = (uint8_t)(c1 >> (24 - 8 * i));
    }
    memcpy(x->name, "raw", 4);
    copy_target(x, p);
    x->arch = MB_ARCH_ARM;
    out->header_ok = true;
    out->fmt = MB_FMT_RAW;
    return MB_OK;
}
#else
int mb_raw_probe(const mb_port_t* p, int slot, mb_slot_info_t* out) { (void)p; (void)slot; (void)out; return MB_E_UNSUPP; }
#endif
