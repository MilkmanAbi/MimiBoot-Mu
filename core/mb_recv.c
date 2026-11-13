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
int mb_sink_slot_data(void* ctx, uint32_t off, const void* d, size_t n) { (void)ctx; (void)off; (void)d; (void)n; return MB_E_UNSUPP; }
int mb_sink_slot_end(void* ctx) { (void)ctx; return MB_E_UNSUPP; }
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

int mb_recv(const mb_recv_t* r, mb_image_hdr_t* hdr_out) {
    static uint8_t data[1024];
    uint16_t max = r->max_frame && r->max_frame <= sizeof(data) ? r->max_frame : (uint16_t)sizeof(data);
    say(r, "MB READY %lu %s\n", max, r->where ? r->where : "-");
    mb_image_hdr_t hdr;
    int c = r->getc(r->ctx, 30000);
    if (c != 'H' || rd(r, &hdr, sizeof(hdr), 2000) != MB_OK) { r->puts(r->ctx, "MB ERR no header\n"); return MB_E_TIMEOUT; }
    if (hdr.magic != MB_IMG_MAGIC || mb_crc32(0, &hdr, offsetof(mb_image_hdr_t, hdr_crc)) != hdr.hdr_crc) {
        r->puts(r->ctx, "MB ERR bad header\n");
        return MB_E_CORRUPT;
    }
    int rc = r->begin(r->ctx, &hdr);
    if (rc != MB_OK) {
        char line[48];
        snprintf(line, sizeof(line), "MB ERR refused (%d)\n", rc);
        r->puts(r->ctx, line);
        return rc;
    }
    r->puts(r->ctx, "MB OK\n");
    for (;;) {
        c = r->getc(r->ctx, 5000);
        if (c == 'X' || c < 0) { r->puts(r->ctx, "MB ERR aborted (nothing installed)\n"); return MB_E_TIMEOUT; }
        if (c == 'E') break;
        if (c != 'D') { r->puts(r->ctx, "MB ERR frame\n"); continue; }
        uint8_t h[6], t[4];
        if (rd(r, h, 6, 2000) != MB_OK) { r->puts(r->ctx, "MB ERR timeout\n"); return MB_E_TIMEOUT; }
        uint32_t off = le32(h);
        uint32_t len = (uint32_t)h[4] | (uint32_t)h[5] << 8;
        if (len > max || off > hdr.payload_size || len > hdr.payload_size - off) { r->puts(r->ctx, "MB ERR range\n"); return MB_E_BADARG; }
        if (rd(r, data, len, 2000) != MB_OK || rd(r, t, 4, 2000) != MB_OK) { r->puts(r->ctx, "MB ERR timeout\n"); return MB_E_TIMEOUT; }
        if (mb_crc32(0, data, len) != le32(t)) { say(r, "MB ERR crc %lu%s\n", off, ""); continue; }
        if ((rc = r->data(r->ctx, off, data, len)) != MB_OK) { r->puts(r->ctx, "MB ERR write\n"); return rc; }
        say(r, "MB OK %lu%s\n", off, "");
    }
    if ((rc = r->end(r->ctx)) != MB_OK) {
        r->puts(r->ctx, rc == MB_E_SIGNATURE ? "MB ERR signature (nothing installed)\n" : "MB ERR hash (nothing installed)\n");
        return rc;
    }
    if (hdr_out) *hdr_out = hdr;
    r->puts(r->ctx, "MB DONE\n");
    return MB_OK;
}

// ---------------------------------------------------------------------------
// Sink: a flash slot. The slot is empty from begin() until end() has hashed
// what actually landed in flash and written the header.
// ---------------------------------------------------------------------------

int mb_sink_slot_begin(void* ctx, const mb_image_hdr_t* hdr) {
    mb_slot_sink_t* s = ctx;
    const mb_slot_def_t* d = &s->p->layout->slot[s->slot];
    if (mb_image_check_header(s->p, hdr, d->size) != MB_OK) return MB_E_CORRUPT;
    if (strncmp(hdr->target, s->p->target, sizeof(hdr->target))) return MB_E_UNSUPP;
    // refuse early what could never boot: unsigned / badly signed when required
    mb_slot_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.hdr = *hdr;
    tmp.header_ok = true;
    if (mb_image_check_sig(s->p, &tmp) != MB_OK) return MB_E_SIGNATURE;
    s->hdr = *hdr;
    return mb_slot_erase(s->p, s->slot, hdr->payload_size);
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
    return mb_slot_write_header(s->p, s->slot, &s->hdr);
}

#endif /* MB_FEAT_RECV */
