/*
 * MimiBoot - receiving an image over a byte stream (see mimiboot.h)
 *
 * One implementation for the bootloader's console (`recv`, `ramboot`) and
 * for a running app taking an OTA update (an OS command like `boot recv`): only the
 * byte I/O and the sink differ. Frames carry a CRC and are resent on error;
 * the sink checks the whole payload hash before anything becomes bootable.
 */
#include "core/mimiboot.h"
#include <stdio.h>
#include <string.h>

#if !MB_FEAT_RECV
int mb_recv(const mb_recv_t* r, mb_image_hdr_t* hdr_out) { (void)r; (void)hdr_out; return MB_E_UNSUPP; }
int mb_sink_slot_begin(void* ctx, const mb_image_hdr_t* hdr) { (void)ctx; (void)hdr; return MB_E_UNSUPP; }
int mb_sink_slot_check(void* ctx, const mb_image_hdr_t* hdr) { (void)ctx; (void)hdr; return MB_E_UNSUPP; }
int mb_sink_slot_data(void* ctx, uint32_t off, const void* d, size_t n) { (void)ctx; (void)off; (void)d; (void)n; return MB_E_UNSUPP; }
int mb_sink_slot_end(void* ctx) { (void)ctx; return MB_E_UNSUPP; }
int mb_sink_slot_tlvs(void* ctx) { (void)ctx; return MB_E_UNSUPP; }
#else

static int rd(const mb_recv_t* r, void* dst, size_t n, uint32_t ms) {
    uint8_t* d = dst;
    for (size_t i = 0; i < n; i++) {
        int c = r->getc(r->ctx, ms);
        if (c < 0) return MB_E_TIMEOUT;
        d[i] = (uint8_t)c;
    }
    return MB_OK;
}

static uint32_t le32(const uint8_t* b) { return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24; }

static void say(const mb_recv_t* r, const char* fmt, unsigned long v, const char* s) {
    char line[80];
    snprintf(line, sizeof(line), fmt, v, s);
    r->puts(r->ctx, line);
}

static const uint8_t zero_nonce[16];
static uint8_t data[1024];

// An encrypted image: ask for the envelope ('K' u16 len, envelope, u32 crc) and open it
static int read_key(const mb_recv_t* r) {
    if (!MB_FEAT_ENC || !r->enc_key) {
        r->puts(r->ctx, "MB ERR encrypted image: no decryption key in this build\n");
        return MB_E_UNSUPP;
    }
    r->puts(r->ctx, "MB KEY\n");
    uint8_t h[2], t[4];
    if (r->getc(r->ctx, 5000) != 'K' || rd(r, h, 2, 2000) != MB_OK) return MB_E_TIMEOUT;
    uint32_t len = (uint32_t)h[0] | (uint32_t)h[1] << 8;
    if (len > MB_ENC_ENV_MAX) return MB_E_CORRUPT;
    if (rd(r, data, len, 2000) != MB_OK || rd(r, t, 4, 2000) != MB_OK) return MB_E_TIMEOUT;
    if (mb_crc32(0, data, len) != le32(t)) return MB_E_CORRUPT;
    int rc = mb_enc_unwrap(&mb_upload_key, data, len, r->enc_key);
    if (rc == MB_E_SIGNATURE) r->puts(r->ctx, "MB ERR key: not encrypted for this device\n");
    return rc;
}

// An LMS-signed image: ask for the signature ('S' u16 len, signature, u32 crc).
// It is checked (with the header) before anything is erased, and kept for the slot.
static int read_sig(const mb_recv_t* r) {
    mb_upload_sig.len = 0;
    if (!MB_FEAT_LMS) {
        r->puts(r->ctx, "MB ERR LMS-signed image: this build has no LMS\n");
        return MB_E_UNSUPP;
    }
    r->puts(r->ctx, "MB SIG\n");
    uint8_t h[2], t[4];
    if (r->getc(r->ctx, 5000) != 'S' || rd(r, h, 2, 2000) != MB_OK) return MB_E_TIMEOUT;
    uint32_t len = (uint32_t)h[0] | (uint32_t)h[1] << 8;
    if (len > sizeof(mb_upload_sig.buf)) return MB_E_CORRUPT;
    if (rd(r, mb_upload_sig.buf, len, 2000) != MB_OK || rd(r, t, 4, 2000) != MB_OK) return MB_E_TIMEOUT;
    if (mb_crc32(0, mb_upload_sig.buf, len) != le32(t)) return MB_E_CORRUPT;
    mb_upload_sig.len = (uint16_t)len;
    return MB_OK;
}

int mb_recv(const mb_recv_t* r, mb_image_hdr_t* hdr_out) {
    uint16_t max = r->max_frame && r->max_frame <= sizeof(data) ? r->max_frame : (uint16_t)sizeof(data);
    say(r, "MB READY %lu %s\n", max, r->where ? r->where : "-");
    mb_image_hdr_t hdr;
    int c = r->getc(r->ctx, 30000);
    if (c != 'H' || rd(r, &hdr, sizeof(hdr), 2000) != MB_OK) { r->puts(r->ctx, "MB ERR no header\n"); return MB_E_TIMEOUT; }
    if (hdr.magic != MB_IMG_MAGIC || mb_crc32(0, &hdr, offsetof(mb_image_hdr_t, hdr_crc)) != hdr.hdr_crc) {
        r->puts(r->ctx, "MB ERR bad header\n");
        return MB_E_CORRUPT;
    }
    bool enc = MB_FEAT_ENC && (hdr.flags & MB_IMG_F_ENCRYPTED);
    // the envelope is checked before anything is erased (a build without the feature refuses here)
    int rc = (hdr.flags & MB_IMG_F_ENCRYPTED) ? read_key(r) : MB_OK;
    if (rc == MB_OK && (hdr.flags & MB_IMG_F_LMS)) rc = read_sig(r);
    if (rc == MB_OK) rc = r->begin(r->ctx, &hdr);
    if (rc != MB_OK) {
        char line[48];
        snprintf(line, sizeof(line), "MB ERR refused (%d)\n", rc);
        r->puts(r->ctx, line);
        mb_aes_clear(&mb_upload_key);
        return rc;
    }
    r->puts(r->ctx, "MB OK\n");
    for (;;) {
        c = r->getc(r->ctx, 5000);
        if (c == 'X' || c < 0) { r->puts(r->ctx, "MB ERR aborted (nothing installed)\n"); rc = MB_E_TIMEOUT; goto out; }
        if (c == 'E') break;
        if (c != 'D') { r->puts(r->ctx, "MB ERR frame\n"); continue; }
        uint8_t h[6], t[4];
        if (rd(r, h, 6, 2000) != MB_OK) { r->puts(r->ctx, "MB ERR timeout\n"); rc = MB_E_TIMEOUT; goto out; }
        uint32_t off = le32(h);
        uint32_t len = (uint32_t)h[4] | (uint32_t)h[5] << 8;
        if (len > max || off > hdr.payload_size || len > hdr.payload_size - off) { r->puts(r->ctx, "MB ERR range\n"); rc = MB_E_BADARG; goto out; }
        if (rd(r, data, len, 2000) != MB_OK || rd(r, t, 4, 2000) != MB_OK) { r->puts(r->ctx, "MB ERR timeout\n"); rc = MB_E_TIMEOUT; goto out; }
        if (mb_crc32(0, data, len) != le32(t)) { say(r, "MB ERR crc %lu%s\n", off, ""); continue; }
        if (enc) mb_aes_ctr(&mb_upload_key, zero_nonce, off, data, len);     // by offset, so a resent frame decrypts the same
        if ((rc = r->data(r->ctx, off, data, len)) != MB_OK) { r->puts(r->ctx, "MB ERR write\n"); goto out; }
        say(r, "MB OK %lu%s\n", off, "");
    }
    mb_aes_clear(&mb_upload_key);
    memset(data, 0, sizeof(data));
    if ((rc = r->end(r->ctx)) != MB_OK) {
        r->puts(r->ctx, rc == MB_E_SIGNATURE ? "MB ERR signature (nothing installed)\n"
                        : rc == MB_E_REFUSED ? "MB ERR refused: not linked for this slot (nothing installed)\n"
                                             : "MB ERR hash (nothing installed)\n");
        return rc;
    }
    if (hdr_out) *hdr_out = hdr;
    r->puts(r->ctx, "MB DONE\n");
    return MB_OK;
out:
    mb_aes_clear(&mb_upload_key);
    memset(data, 0, sizeof(data));
    return rc;
}

// ---------------------------------------------------------------------------
// Sink: a flash slot. The slot is empty from begin() until end() has hashed
// what actually landed in flash and written the header.
// ---------------------------------------------------------------------------

int mb_sink_slot_begin(void* ctx, const mb_image_hdr_t* hdr) {
    mb_slot_sink_t* s = ctx;
    int rc = mb_sink_slot_check(ctx, hdr);
    if (rc == MB_OK) rc = mb_slot_erase(s->p, s->slot, hdr->payload_size);
    return rc == MB_OK ? mb_sink_slot_tlvs(ctx) : rc;
}

// After the erase: an LMS signature goes into the header sector (the header itself comes last)
int mb_sink_slot_tlvs(void* ctx) {
    mb_slot_sink_t* s = ctx;
    if (!MB_FEAT_LMS || !(s->hdr.flags & MB_IMG_F_LMS)) return MB_OK;
    return mb_slot_write_lms(s->p, s->slot, mb_upload_sig.buf, mb_upload_sig.len);
}

int mb_sink_slot_check(void* ctx, const mb_image_hdr_t* hdr) {
    mb_slot_sink_t* s = ctx;
    const mb_slot_def_t* d = &s->p->layout->slot[s->slot];
    if (mb_image_check_header(s->p, hdr, d->size) != MB_OK) return MB_E_CORRUPT;
    if (strncmp(hdr->target, s->p->target, sizeof(hdr->target))) return MB_E_UNSUPP;
    // a stage 1 only into the stage-1 copy that isn't running, linked for it; nothing else there
    int rc = mb_stage1_accepts(s->p, s->slot, hdr);
    if (rc != MB_OK) return rc;
    if (s->p->stage1_slot && s->p->stage1_slot() == s->slot) return MB_E_REFUSED;
    // refuse early what could never boot: unsigned / badly signed when required
    mb_slot_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.hdr = *hdr;
    tmp.header_ok = true;
    if (MB_FEAT_LMS && (hdr->flags & MB_IMG_F_LMS)) {     // the signature that came with it (nothing is erased yet)
#if MB_FEAT_LMS
        tmp.sig_ram = mb_upload_sig.buf;
        tmp.sig_ram_len = mb_upload_sig.len;
#endif
    }
    bool s1 = mb_slot_role(s->p, s->slot) == MB_ROLE_STAGE1;
    if ((s1 ? mb_stage1_check_sig(s->p, &tmp) : mb_image_check_sig(s->p, &tmp)) != MB_OK) return MB_E_SIGNATURE;
    s->hdr = *hdr;
    return MB_OK;
}

int mb_sink_slot_data(void* ctx, uint32_t off, const void* d, size_t n) {
    mb_slot_sink_t* s = ctx;
    return mb_slot_write(s->p, s->slot, off, d, n);
}

int mb_sink_slot_end(void* ctx) {
    mb_slot_sink_t* s = ctx;
    mb_slot_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.hdr = s->hdr;
    tmp.header_ok = true;
    if (mb_image_verify(s->p, s->slot, &tmp) != MB_OK) return MB_E_CORRUPT;
    bool s1 = mb_slot_role(s->p, s->slot) == MB_ROLE_STAGE1;
    if (s1 && mb_stage1_vectors_ok(s->p, s->slot, &s->hdr) != MB_OK)
        return MB_E_REFUSED;    // a stage 1 built for the other copy: left without a header (empty)
    if (MB_FEAT_LMS && (s->hdr.flags & MB_IMG_F_LMS)) {   // the copy in flash is what boots: check that one
        tmp.sig_state = 0;
#if MB_FEAT_LMS
        tmp.tlv_flash = s->p->layout->slot[s->slot].offset + MB_IMG_HDR_SIZE;
#endif
        if ((s1 ? mb_stage1_check_sig(s->p, &tmp) : mb_image_check_sig(s->p, &tmp)) != MB_OK) return MB_E_SIGNATURE;
    }
    return mb_slot_write_header(s->p, s->slot, &s->hdr);
}

#endif /* MB_FEAT_RECV */
