/*
 * MimiBoot - mcumgr / SMP over the serial console (MB_FEAT_SMP)
 *
 * The Simple Management Protocol that Zephyr's tools speak (mcumgr, smpmgr,
 * AuTerm, smpclient), in the subset MCUboot's serial recovery offers, so
 * those tools can update a board MimiBoot boots:
 *
 *   OS group (0):    echo, console echo control, reset, MCUmgr parameters,
 *                    bootloader info
 *   image group (1): state read (list), state write (test / confirm),
 *                    upload, erase
 *
 * On the wire (Zephyr's serial transport): each line is 0x06 0x09 (first) or
 * 0x04 0x14 (continuation), base64 text, '\n'. The base64 of the whole packet
 * is [length, big-endian][SMP header + CBOR][CRC-16/XMODEM, big-endian]; the
 * length counts the message and the CRC. The console hands every line that
 * starts with a marker to mb_smp_frame(); text and SMP share the UART.
 *
 * Uploads take MimiBoot images (mbtool pack) and Zephyr/MCUboot images
 * (imgtool sign) alike, and keep the rule `recv` keeps: the first page (the
 * header) is held in RAM and written last, after the whole image has been
 * hashed and checked, so an upload that stops halfway leaves an empty slot.
 * The slot is erased (as far as the image reaches) when the first chunk
 * arrives, as MCUboot does by default; pages are written whole, once each
 * (ECC flash can't take a second write). Which slot:
 *
 *   "image" 0 or absent  the A/B slot an update goes to (not the active one)
 *   "image" N >= 1       slot N-1 (a, b, g, ...), as in MCUboot's direct upload
 *
 * Never golden (mcumgr has no "force"), never the stage 1 that is running.
 * With CONSOLE_AUTH and the console locked, everything that writes is refused
 * (access denied); reading, echo, parameters and reset still work.
 *
 * Errors: a general error is {"rc": n}; an image-group error is the SMP v2
 * {"err": {"group": 1, "rc": n}} when the request was v2, else {"rc": n}.
 */
#include "core/mimiboot.h"
#include <string.h>

#if MB_FEAT_SMP

#ifndef MB_SMP_BUF
#define MB_SMP_BUF 1024         /* largest request (header + CBOR) + length + CRC: told to clients as buf_size */
#endif
#define RSP_MAX 768             /* largest response: header + CBOR (the image list) */
#define PAGE 256                /* the program unit the core writes in (mb_slot_write's page) */

/* mcumgr error codes (Zephyr's mgmt_defines.h) */
enum { E_OK = 0, E_UNKNOWN = 1, E_NOMEM = 2, E_INVAL = 3, E_NOENT = 5, E_BADSTATE = 6, E_MSGSIZE = 7,
       E_NOTSUP = 8, E_CORRUPT = 9, E_BUSY = 10, E_ACCESS = 11 };
/* image group (img_mgmt.h) */
enum { IE_FLASH_READ = 11, IE_FLASH_WRITE = 12, IE_FLASH_ERASE = 13, IE_INVALID_SLOT = 14, IE_INVALID_OFFSET = 20,
       IE_INVALID_LENGTH = 21, IE_BAD_HEADER = 22, IE_BAD_MAGIC = 23, IE_INVALID_HASH = 24, IE_TOO_LARGE = 30 };

#define OP_READ 0
#define OP_WRITE 2
#define GROUP_OS 0
#define GROUP_IMAGE 1

static uint16_t crc16(uint16_t crc, const uint8_t* d, size_t n) {
    while (n--) {
        crc ^= (uint16_t)(*d++ << 8);
        for (int i = 0; i < 8; i++) crc = crc & 0x8000 ? (uint16_t)(crc << 1 ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

/* ---- a response: header + CBOR, built in place ------------------------------------- */
static uint8_t rsp[RSP_MAX];
static uint32_t rsp_n;
static bool rsp_over;

static void put_byte(uint8_t b) { if (rsp_n < sizeof(rsp)) rsp[rsp_n++] = b; else rsp_over = true; }
static void put_head(unsigned major, uint32_t v) {
    uint8_t m = (uint8_t)(major << 5);
    if (v < 24) put_byte((uint8_t)(m | v));
    else if (v < 0x100) { put_byte(m | 24); put_byte((uint8_t)v); }
    else if (v < 0x10000) { put_byte(m | 25); put_byte((uint8_t)(v >> 8)); put_byte((uint8_t)v); }
    else { put_byte(m | 26); for (int s = 24; s >= 0; s -= 8) put_byte((uint8_t)(v >> s)); }
}
static void put_bytes(unsigned major, const void* d, size_t n) {
    put_head(major, (uint32_t)n);
    for (const uint8_t* b = d; n--;) put_byte(*b++);
}
static void put_str(const char* s) { put_bytes(3, s, strlen(s)); }
static void put_uint(uint32_t v) { put_head(0, v); }
static void put_bool(bool b) { put_byte(b ? 0xF5 : 0xF4); }
static void put_map(uint32_t n) { put_head(5, n); }

/* ---- a request: a flat CBOR map -------------------------------------------------- */
typedef struct {
    const uint8_t *p, *end;
    bool bad;
} rd_t;

// One item's head: major type and argument (indef: an indefinite-length string/array/map)
static uint64_t get_head(rd_t* r, unsigned* major, bool* indef) {
    *indef = false;
    if (r->p >= r->end) { r->bad = true; return 0; }
    uint8_t b = *r->p++;
    *major = b >> 5;
    unsigned ai = b & 31;
    if (ai < 24) return ai;
    if (ai == 31) { *indef = true; return 0; }
    if (ai > 27) { r->bad = true; return 0; }
    unsigned n = 1u << (ai - 24);
    if ((size_t)(r->end - r->p) < n) { r->bad = true; return 0; }
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) v = v << 8 | *r->p++;
    return v;
}

static bool is_break(rd_t* r) {
    if (r->p < r->end && *r->p == 0xFF) { r->p++; return true; }
    return false;
}

// Skip one item (any type), for keys we don't know
static void skip(rd_t* r, int depth) {
    unsigned major;
    bool indef;
    uint64_t v = get_head(r, &major, &indef);
    if (r->bad || depth > 8) { r->bad = true; return; }
    uint64_t left = (uint64_t)(r->end - r->p);
    switch (major) {
    case 0: case 1: case 7: return;                     // ints, simple values, floats: all in the head
    case 2: case 3:
        if (indef) {                                    // chunked string
            while (!r->bad && !is_break(r)) skip(r, depth + 1);
            return;
        }
        if (v > left) { r->bad = true; return; }
        r->p += v;
        return;
    case 4: case 5: {
        if (!indef && v > left) { r->bad = true; return; }     // every item takes a byte at least
        uint64_t items = major == 5 ? 2 * v : v;
        for (uint64_t i = 0; indef ? !is_break(r) : i < items; i++) {
            skip(r, depth + 1);
            if (r->bad) return;
        }
        return;
    }
    case 6: skip(r, depth + 1); return;                 // tag: the tagged item
    }
}

typedef struct {
    bool has_off, has_len, has_image, has_data, has_sha, has_confirm, has_hash, has_d, has_slot;
    uint32_t off, len, image, slot;
    bool confirm;
    const uint8_t *data, *sha, *hash;
    uint32_t data_n, sha_n, hash_n;
    const char* d;
    uint32_t d_n;
} req_t;

static bool key_is(const uint8_t* k, uint32_t n, const char* s) { return strlen(s) == n && !memcmp(k, s, n); }

static bool get_uint(rd_t* r, uint32_t* out) {
    unsigned major;
    bool indef;
    uint64_t v = get_head(r, &major, &indef);
    if (r->bad || major != 0 || indef || v > 0xFFFFFFFFu) return false;
    *out = (uint32_t)v;
    return true;
}
static bool get_str(rd_t* r, unsigned want, const uint8_t** out, uint32_t* n) {
    unsigned major;
    bool indef;
    uint64_t v = get_head(r, &major, &indef);      // chunked strings aren't taken: no client sends them
    if (r->bad || major != want || indef || v > (uint64_t)(r->end - r->p)) return false;
    *out = r->p;
    *n = (uint32_t)v;
    r->p += v;
    return true;
}

static bool parse_req(const uint8_t* b, uint32_t n, req_t* q) {
    memset(q, 0, sizeof(*q));
    rd_t r = { b, b + n, false };
    if (n == 0) return true;                            // an empty body: no fields
    unsigned major;
    bool indef;
    uint64_t pairs = get_head(&r, &major, &indef);
    if (r.bad || major != 5 || (!indef && pairs > n)) return false;
    for (uint64_t i = 0; indef ? !is_break(&r) : i < pairs; i++) {
        const uint8_t* k;
        uint32_t kn;
        if (!get_str(&r, 3, &k, &kn)) return false;
        bool ok = true;
        if (key_is(k, kn, "off")) ok = q->has_off = get_uint(&r, &q->off);
        else if (key_is(k, kn, "len")) ok = q->has_len = get_uint(&r, &q->len);
        else if (key_is(k, kn, "image")) ok = q->has_image = get_uint(&r, &q->image);
        else if (key_is(k, kn, "slot")) ok = q->has_slot = get_uint(&r, &q->slot);
        else if (key_is(k, kn, "data")) ok = q->has_data = get_str(&r, 2, &q->data, &q->data_n);
        else if (key_is(k, kn, "sha")) ok = q->has_sha = get_str(&r, 2, &q->sha, &q->sha_n);
        else if (key_is(k, kn, "hash")) ok = q->has_hash = get_str(&r, 2, &q->hash, &q->hash_n);
        else if (key_is(k, kn, "d")) ok = q->has_d = get_str(&r, 3, (const uint8_t**)&q->d, &q->d_n);
        else if (key_is(k, kn, "confirm")) {
            if (r.p >= r.end || (*r.p != 0xF4 && *r.p != 0xF5)) return false;
            q->confirm = *r.p++ == 0xF5;
            q->has_confirm = true;
        } else skip(&r, 0);
        if (!ok || r.bad) return false;
    }
    return !r.bad;
}

/* ---- the reply: [length][header + CBOR][CRC] in base64 lines ------------------------ */
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct {
    const mb_port_t* p;
    char line[124];             /* a multiple of 4: every line decodes on its own */
    int n;
    bool first;
    uint8_t tri[3];
    int tn;
} tx_t;

static void tx_flush(tx_t* t) {
    if (!t->n) return;
    t->p->write(t->first ? "\x06\x09" : "\x04\x14", 2);
    t->p->write(t->line, (size_t)t->n);
    t->p->write("\n", 1);
    t->first = false;
    t->n = 0;
}
static void tx_quad(tx_t* t, int have) {
    uint32_t v = (uint32_t)t->tri[0] << 16 | (uint32_t)t->tri[1] << 8 | t->tri[2];
    for (int i = 0; i < 4; i++)
        t->line[t->n++] = i <= have ? b64[(v >> (18 - 6 * i)) & 63] : '=';
    if (t->n == (int)sizeof(t->line)) tx_flush(t);
}
static void tx_byte(tx_t* t, uint8_t b) {
    t->tri[t->tn++] = b;
    if (t->tn == 3) { tx_quad(t, 3); t->tn = 0; }
}

static void send_reply(const mb_port_t* p, const uint8_t req[8]) {
    uint32_t body = rsp_n - 8;
    rsp[0] = (uint8_t)((req[0] & ~7u) | ((req[0] & 7u) + 1u));    // read -> read rsp, write -> write rsp; version kept
    rsp[1] = 0;
    rsp[2] = (uint8_t)(body >> 8);
    rsp[3] = (uint8_t)body;
    memcpy(rsp + 4, req + 4, 4);                                      // group, sequence, command
    uint16_t crc = crc16(0, rsp, rsp_n);
    uint32_t total = rsp_n + 2;
    tx_t t = { .p = p, .first = true };
    tx_byte(&t, (uint8_t)(total >> 8));
    tx_byte(&t, (uint8_t)total);
    for (uint32_t i = 0; i < rsp_n; i++) tx_byte(&t, rsp[i]);
    tx_byte(&t, (uint8_t)(crc >> 8));
    tx_byte(&t, (uint8_t)crc);
    if (t.tn) {
        for (int i = t.tn; i < 3; i++) t.tri[i] = 0;
        tx_quad(&t, t.tn);
    }
    tx_flush(&t);
}

// An error. mgmt: the general code; img: the image-group code (0: none)
static void put_error(unsigned version, int mgmt, int img) {
    rsp_n = 8;
    rsp_over = false;
    if (version >= 1 && img) {
        put_map(1);
        put_str("err");
        put_map(2);
        put_str("group");
        put_uint(GROUP_IMAGE);
        put_str("rc");
        put_uint((uint32_t)img);
    } else {
        put_map(1);
        put_str("rc");
        put_uint((uint32_t)mgmt);
    }
}

/* ---- image group -------------------------------------------------------------------- */
static void version_str(uint32_t v, char* out) {
    unsigned parts[3] = { MB_VERSION_MAJOR(v), MB_VERSION_MINOR(v), MB_VERSION_PATCH(v) };
    char* o = out;
    for (int i = 0; i < 3; i++) {
        char tmp[6];
        int n = 0;
        unsigned x = parts[i];
        do { tmp[n++] = (char)('0' + x % 10); x /= 10; } while (x);
        while (n) *o++ = tmp[--n];
        if (i < 2) *o++ = '.';
    }
    *o = 0;
}

static void image_list(const mb_port_t* p, const mb_bcl_t* log) {
    static mb_slot_info_t in;
    int n = 0;
    for (int i = 0; i < p->layout->n_slots; i++)
        if (mb_image_read_header(p, i, &in) == MB_OK) n++;
    put_map(2);
    put_str("images");
    put_head(4, (uint32_t)n);
    for (int i = 0; i < p->layout->n_slots; i++) {
        if (mb_image_read_header(p, i, &in) != MB_OK) continue;
        const mb_slot_rec_t* s = &log->cur.slot[i];
        bool known = s->image_id == mb_image_id(&in.hdr);
        bool stage1 = mb_slot_role(p, i) == MB_ROLE_STAGE1;
        char ver[20];
        version_str(in.hdr.version, ver);
        put_map(6);
        put_str("slot");
        put_uint((uint32_t)i);
        put_str("version");
        put_str(ver);
        put_str("hash");
        put_bytes(2, in.hdr.sha256, 32);
        put_str("bootable");
        put_bool(!stage1 && !(in.hdr.flags & MB_IMG_F_STAGE1) && (!known || s->state != MB_ST_BAD));
        put_str("pending");
        put_bool(!stage1 && (!known || s->state == MB_ST_NEW || s->state == MB_ST_TRIAL));
        put_str("confirmed");
        put_bool(!stage1 && known && s->state == MB_ST_GOOD);
    }
    put_str("splitStatus");
    put_uint(0);
}

// The A/B slot an update goes to: the one that isn't active
static int update_slot(const mb_port_t* p, const mb_bcl_t* log) {
    int ab[2] = { -1, -1 }, n = 0;
    for (int i = 0; i < p->layout->n_slots && n < 2; i++)
        if (mb_slot_role(p, i) == MB_ROLE_AB) ab[n++] = i;
    if (n < 2) return ab[0];
    return log->cur.active == ab[0] ? ab[1] : ab[0];
}

static bool slot_ok_for_writes(const mb_port_t* p, int slot) {
    if (slot < 0 || slot >= p->layout->n_slots) return false;
    if (mb_slot_role(p, slot) == MB_ROLE_GOLDEN) return false;            // no "force" in mcumgr
    if (p->stage1_slot && p->stage1_slot() == slot) return false;         // the bootloader running now
    return true;
}

/* the header sector's TLV list an upload may carry (from byte 256): a key envelope, an LMS signature */
#define SMP_TLV_MAX (MB_ENC_ENV_MAX + (MB_FEAT_LMS ? 4 + MB_LMS_SIG_MAX : 0))

/* the upload in progress */
static struct {
    bool on, mimg, enc, lms, has_sha, head_done;
    int slot;
    uint32_t len, off;          /* total, next expected */
    uint8_t head[PAGE];         /* the first page, written last */
    uint8_t page[PAGE];         /* the page being filled */
    uint32_t page_at;           /* its offset in the image */
    uint8_t sha[32];
    mb_sha256_t fsha;           /* of the file as it arrives (flash holds plaintext when it came encrypted) */
    uint8_t tlv[SMP_TLV_MAX];   /* the header sector's TLVs (from byte 256), when the header says there are some */
    mb_slot_sink_t sink;
} up;
static const uint8_t zero_nonce[16];

// Program one whole page of the image at image offset `at` (>= PAGE)
static int write_page(const mb_port_t* p, uint32_t at) {
    if (up.mimg) {
        if (at < MB_IMG_PAYLOAD_OFF) return MB_OK;      // the rest of the header sector: blank
        if (up.enc) {                                   // only the image's bytes: the tail stays 0xFF
            uint32_t n = up.len - at < PAGE ? up.len - at : PAGE;
            mb_aes_ctr(&mb_upload_key, zero_nonce, at - MB_IMG_PAYLOAD_OFF, up.page, n);
        }
        return mb_sink_slot_data(&up.sink, at - MB_IMG_PAYLOAD_OFF, up.page, PAGE);
    }
    return p->flash_program(p->layout->slot[up.slot].offset + at, up.page, PAGE);
}

// The first page is complete: what kind of image, checks, erase. 0 or an image-group error.
static int begin(const mb_port_t* p) {
    const mb_slot_def_t* d = &p->layout->slot[up.slot];
    uint32_t magic;
    memcpy(&magic, up.head, 4);
    if (up.len > d->size) return IE_TOO_LARGE;
    if (magic == MB_IMG_MAGIC) {
        mb_image_hdr_t h;
        memcpy(&h, up.head, sizeof(h));
        if (h.payload_offset != MB_IMG_PAYLOAD_OFF || up.len != MB_IMG_PAYLOAD_OFF + h.payload_size) return IE_INVALID_LENGTH;
        up.mimg = true;
        up.enc = (h.flags & MB_IMG_F_ENCRYPTED) != 0;
        up.lms = MB_FEAT_LMS && (h.flags & MB_IMG_F_LMS) != 0;
        if (up.enc && (!MB_FEAT_ENC || !p->enc_key)) return IE_BAD_HEADER;   // no key here to open it
        if (up.lms && !MB_FEAT_LMS) return IE_BAD_HEADER;
        up.sink.p = p;
        up.sink.slot = up.slot;
        up.sink.hdr = h;
        memset(up.tlv, 0xFF, sizeof(up.tlv));
        // header, target, stage-1 rules, signature: the erase waits for the end of the
        // header sector (payload_start), where an envelope or an LMS signature arrives;
        // an LMS signature is checked there too, everything else right away
        if (up.lms) return 0;
        return mb_sink_slot_check(&up.sink, &h) == MB_OK ? 0 : IE_BAD_HEADER;
    }
#if MB_FEAT_IMG_MCUBOOT
    if (magic == 0x96f3b83du) {
        if (mb_slot_role(p, up.slot) == MB_ROLE_STAGE1) return IE_BAD_HEADER;
        uint32_t flags;
        memcpy(&flags, up.head + 16, 4);
        if (flags & 0x0Cu) return IE_BAD_HEADER;       // imgtool --encrypt: ciphertext can't run from a slot
        up.mimg = false;
        return mb_slot_erase(p, up.slot, up.len > MB_IMG_PAYLOAD_OFF ? up.len - MB_IMG_PAYLOAD_OFF : 0) == MB_OK
                   ? 0 : IE_FLASH_ERASE;
    }
#endif
    return IE_BAD_MAGIC;
}

// Everything is in flash but the first page: check it all, then write that page.
static int finish(const mb_port_t* p) {
    const mb_slot_def_t* d = &p->layout->slot[up.slot];
    if (up.has_sha) {                                   // the whole file, as the client hashed it
        uint8_t got[32];
        mb_sha256_final(&up.fsha, got);
        if (mb_ct_diff(got, up.sha, 32)) return IE_INVALID_HASH;
    }
    if (up.mimg) {
        int rc = mb_sink_slot_end(&up.sink);            // payload hash, stage-1 vectors, then the header
        return rc == MB_OK ? 0 : rc == MB_E_IO ? IE_FLASH_WRITE : IE_INVALID_HASH;
    }
    // MCUboot: the header goes in, then the image must check out as a whole (hash, signature)
    if (p->flash_program(d->offset, up.head, PAGE) != MB_OK) return IE_FLASH_WRITE;
    static mb_slot_info_t in;
    bool ok = mb_image_read_header(p, up.slot, &in) == MB_OK && in.fmt == MB_FMT_MCUBOOT &&
              mb_image_check_sig(p, &in) == MB_OK && mb_image_verify(p, up.slot, &in) == MB_OK;
    if (!ok) {
        p->flash_erase(d->offset, p->layout->sector_size);     // back to empty
        return IE_INVALID_HASH;
    }
    return 0;
}

// A MimiBoot image's header sector is all in: open an encrypted image's envelope,
// check an LMS signature (a wrong one is refused before anything is erased), erase,
// put the LMS signature into the slot's header sector.
static int payload_start(const mb_port_t* p) {
    size_t at, n;
    if (up.enc) {
        if (mb_tlv_find(up.tlv, sizeof(up.tlv), MB_ENC_TLV_X25519, &at, &n) != MB_OK) return IE_BAD_HEADER;
        if (mb_enc_unwrap(&mb_upload_key, up.tlv + at - 4, n + 4, p->enc_key) != MB_OK) return IE_BAD_HEADER;
    }
    if (up.lms) {
        if (mb_tlv_find(up.tlv, sizeof(up.tlv), MB_TLV_LMS_SIG, &at, &n) != MB_OK || n > sizeof(mb_upload_sig.buf))
            return IE_BAD_HEADER;
        memcpy(mb_upload_sig.buf, up.tlv + at, n);
        mb_upload_sig.len = (uint16_t)n;
        if (mb_sink_slot_check(&up.sink, &up.sink.hdr) != MB_OK) return IE_BAD_HEADER;
    }
    if (mb_slot_erase(p, up.slot, up.sink.hdr.payload_size) != MB_OK) return IE_FLASH_ERASE;
    return mb_sink_slot_tlvs(&up.sink) == MB_OK ? 0 : IE_FLASH_WRITE;
}

// Feed image bytes at image offset `at`
static int feed(const mb_port_t* p, uint32_t at, const uint8_t* data, uint32_t n) {
    while (n) {
        if (at < PAGE) {                                // the first page: held back
            uint32_t k = PAGE - at < n ? PAGE - at : n;
            memcpy(up.head + at, data, k);
            at += k; data += k; n -= k;
            if ((at == PAGE || at == up.len) && !up.head_done) {
                if (up.len < PAGE) return IE_INVALID_LENGTH;
                int rc = begin(p);
                if (rc) return rc;
                up.head_done = true;
                up.page_at = PAGE;
                memset(up.page, 0xFF, PAGE);
            }
            continue;
        }
        if (up.mimg && at < MB_IMG_PAYLOAD_OFF) {       // header sector: TLVs (when announced), then blank
            for (; n && at < MB_IMG_PAYLOAD_OFF; at++, data++, n--) {
                if ((up.enc || up.lms) && at - PAGE < sizeof(up.tlv)) up.tlv[at - PAGE] = *data;
                else if (*data != 0xFF) return IE_BAD_HEADER;
            }
            if (at == MB_IMG_PAYLOAD_OFF) {
                int rc = payload_start(p);
                if (rc) return rc;
                up.page_at = MB_IMG_PAYLOAD_OFF;
            }
            continue;
        }
        uint32_t in_page = at - up.page_at;
        uint32_t k = PAGE - in_page < n ? PAGE - in_page : n;
        memcpy(up.page + in_page, data, k);
        at += k; data += k; n -= k;
        if (at - up.page_at == PAGE) {
            if (write_page(p, up.page_at) != MB_OK) return IE_FLASH_WRITE;
            up.page_at += PAGE;
            memset(up.page, 0xFF, PAGE);
        }
    }
    return 0;
}

static int image_upload(const mb_port_t* p, const mb_bcl_t* log, const req_t* q, int* mgmt) {
    *mgmt = E_INVAL;
    if (!q->has_off || !q->has_data) return IE_INVALID_OFFSET;
    if (q->off == 0) {                                  // (re)start
        if (!q->has_len) return IE_INVALID_LENGTH;
        memset(&up, 0, sizeof(up));
        up.slot = q->has_image && q->image ? (int)q->image - 1 : update_slot(p, log);
        if (!slot_ok_for_writes(p, up.slot)) { *mgmt = E_ACCESS; return IE_INVALID_SLOT; }
        up.len = q->len;
        if (q->has_sha && q->sha_n == 32) { memcpy(up.sha, q->sha, 32); up.has_sha = true; }
        mb_sha256_init(&up.fsha);
        mb_aes_clear(&mb_upload_key);
        up.on = true;
    } else if (!up.on) {
        return IE_INVALID_OFFSET;
    } else if (q->off != up.off) {
        rsp_n = 8;                                      // out of step: tell the client where we are
        put_map(1);
        put_str("off");
        put_uint(up.off);
        return 0;
    }
    if (q->data_n > up.len - up.off) { up.on = false; return IE_INVALID_LENGTH; }
    int rc = feed(p, up.off, q->data, q->data_n);
    if (rc) { up.on = false; mb_aes_clear(&mb_upload_key); *mgmt = E_CORRUPT; return rc; }
    mb_sha256_update(&up.fsha, q->data, q->data_n);
    up.off += q->data_n;
    bool done = up.off == up.len;
    if (done) {
        if (up.page_at < up.len && (rc = write_page(p, up.page_at)) != MB_OK) { up.on = false; return IE_FLASH_WRITE; }
        up.on = false;
        mb_aes_clear(&mb_upload_key);
        if ((rc = finish(p)) != 0) { *mgmt = E_CORRUPT; return rc; }
    }
    rsp_n = 8;
    put_map(done && up.has_sha ? 2 : 1);
    put_str("off");
    put_uint(up.off);
    if (done && up.has_sha) {
        put_str("match");
        put_bool(true);
    }
    return 0;
}

// test (confirm false): boot it next as a trial; confirm: it is good
static int image_state(const mb_port_t* p, mb_bcl_t* log, const req_t* q, int* mgmt) {
    *mgmt = E_INVAL;
    if (!q->has_hash) return q->has_confirm && q->confirm ? 0 : IE_INVALID_HASH;   // "confirm what runs": nothing does
    if (q->hash_n != 32) return IE_INVALID_HASH;
    static mb_slot_info_t in;
    for (int i = 0; i < p->layout->n_slots; i++) {
        if (mb_slot_role(p, i) == MB_ROLE_STAGE1 || mb_image_read_header(p, i, &in) != MB_OK ||
            memcmp(in.hdr.sha256, q->hash, 32))
            continue;
        mb_bcl_rec_t r = log->cur;
        mb_slot_rec_t* s = &r.slot[i];
        s->image_id = mb_image_id(&in.hdr);
        s->bad_reason = MB_BAD_NONE;
        if (q->confirm) {
            s->state = MB_ST_GOOD;
            s->tries_left = 0;
            if (mb_slot_role(p, i) == MB_ROLE_AB) {
                r.active = (uint8_t)i;
                if (in.hdr.security_version > r.min_security) r.min_security = in.hdr.security_version;
            }
        } else {
            s->state = MB_ST_NEW;
            s->tries_left = MB_DEFAULT_TRIES;
        }
        if (mb_bcl_commit(log, &r) != MB_OK) { *mgmt = E_UNKNOWN; return IE_FLASH_WRITE; }
        return 0;
    }
    *mgmt = E_NOENT;
    return IE_INVALID_HASH;
}

static int image_erase(const mb_port_t* p, const mb_bcl_t* log, const req_t* q, int* mgmt) {
    *mgmt = E_INVAL;
    int slot = q->has_slot ? (int)q->slot : update_slot(p, log);
    bool active_good = slot == log->cur.active && log->cur.slot[slot].state == MB_ST_GOOD;
    if (!slot_ok_for_writes(p, slot) || active_good) { *mgmt = E_ACCESS; return IE_INVALID_SLOT; }
    if (mb_slot_erase(p, slot, p->layout->slot[slot].size - MB_IMG_PAYLOAD_OFF) != MB_OK) { *mgmt = E_UNKNOWN; return IE_FLASH_ERASE; }
    if (up.on && up.slot == slot) up.on = false;
    rsp_n = 8;
    put_map(0);
    return 0;
}

/* ---- dispatch ------------------------------------------------------------------- */
static bool reset_after;

static void handle(const mb_port_t* p, mb_bcl_t* log, bool locked, const uint8_t* m, uint32_t n) {
    if (n < 8) return;
    unsigned op = m[0] & 7u, version = (m[0] >> 3) & 3u;
    uint32_t len = (uint32_t)m[2] << 8 | m[3];
    unsigned group = (unsigned)m[4] << 8 | m[5], id = m[7];
    if ((op != OP_READ && op != OP_WRITE) || len != n - 8) return;   // not a request (as MCUboot: no reply)
    static req_t q;
    rsp_n = 8;
    rsp_over = false;
    int mgmt = E_OK, img = 0;
    if (!parse_req(m + 8, len, &q)) {
        mgmt = E_INVAL;
    } else if (group == GROUP_OS) {
        switch (id) {
        case 0:                                         // echo
            if (!q.has_d) { mgmt = E_INVAL; break; }
            put_map(1);
            put_str("r");
            put_bytes(3, q.d, q.d_n);
            break;
        case 1:                                         // console echo control: nothing to do
            put_map(0);
            break;
        case 5:                                         // reset (after the reply is out)
            put_map(0);
            reset_after = true;
            break;
        case 6:                                         // MCUmgr parameters
            put_map(2);
            put_str("buf_size");
            put_uint(MB_SMP_BUF);
            put_str("buf_count");
            put_uint(1);
            break;
        case 8:                                         // bootloader info
            put_map(1);
            put_str("bootloader");
            put_str("MimiBoot");
            break;
        default:
            mgmt = E_NOTSUP;
        }
    } else if (group == GROUP_IMAGE) {
        bool writes = op == OP_WRITE;
        if (writes && locked) {
            mgmt = E_ACCESS;
        } else if (id == 0 && !writes) {
            image_list(p, log);
        } else if (id == 0) {
            img = image_state(p, log, &q, &mgmt);
            if (!img) { rsp_n = 8; image_list(p, log); }
        } else if (id == 1 && writes) {
            img = image_upload(p, log, &q, &mgmt);
        } else if (id == 5 && writes) {
            img = image_erase(p, log, &q, &mgmt);
        } else {
            mgmt = E_NOTSUP;
        }
        if (!img && mgmt != E_ACCESS && mgmt != E_NOTSUP) mgmt = E_OK;
    } else {
        mgmt = E_NOTSUP;
    }
    if (rsp_over) put_error(version, E_MSGSIZE, 0);
    else if (img || mgmt != E_OK) put_error(version, mgmt == E_OK ? E_UNKNOWN : mgmt, img);
    send_reply(p, m);
    if (reset_after) {
        reset_after = false;
        if (p->time_ms) {                               // let the reply leave the UART
            uint32_t t0 = p->time_ms();
            while (p->time_ms() - t0 < 50) {}
        }
        if (p->reboot) p->reboot();
    }
}

/* ---- frames in ------------------------------------------------------------------ */
static uint8_t pkt[MB_SMP_BUF + 4];
static uint32_t pkt_n;
static bool pkt_open;

static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;
    return -1;
}

void mb_smp_frame(const mb_port_t* p, mb_bcl_t* log, bool locked, bool first) {
    if (first) { pkt_n = 0; pkt_open = true; }
    bool bad = !pkt_open;                               // a continuation with no start: read past it
    uint32_t acc = 0;
    int bits = 0;
    for (int guard = 0; guard < 4096; guard++) {
        int c = p->getc ? p->getc(200) : -1;
        if (c < 0) { pkt_open = false; return; }        // the line stopped: drop the packet
        if (c == '\n') break;
        if (c == '\r') continue;
        int v = b64_val(c);
        if (v == -2) { bits = 0; continue; }            // padding: the group ends here
        if (v < 0) { bad = true; continue; }
        acc = (acc << 6 | (uint32_t)v) & 0xFFFFFFu;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (pkt_n < sizeof(pkt)) pkt[pkt_n++] = (uint8_t)(acc >> bits);
            else bad = true;
        }
    }
    if (bad) { pkt_open = false; return; }
    if (pkt_n < 2) return;
    uint32_t want = ((uint32_t)pkt[0] << 8 | pkt[1]) + 2;    // the length counts the message and the CRC
    if (want > sizeof(pkt) || want < 2 + 8 + 2) { pkt_open = false; return; }
    if (pkt_n < want) return;                           // more lines to come
    pkt_open = false;
    if (pkt_n != want || crc16(0, pkt + 2, want - 2) != 0) return;     // damaged: the client retries
    handle(p, log, locked, pkt + 2, want - 4);
}

#endif /* MB_FEAT_SMP */
