/*
 * MimiBoot - boot control log (see include/mimiboot/mb_bcl.h)
 */
#include "core/mimiboot.h"
#include <string.h>

#define REC MB_BCL_REC_SIZE

static bool blank(const void* p, size_t n) {
    const uint8_t* b = p;
    while (n--) if (*b++ != 0xFF) return false;
    return true;
}

static bool rec_ok(const mb_bcl_rec_t* r) {
    return r->magic == MB_BCL_REC_MAGIC && r->size == REC && mb_crc32(0, r, offsetof(mb_bcl_rec_t, crc)) == r->crc;
}

static bool sect_ok(const mb_bcl_sect_t* s) {
    return s->magic == MB_BCL_SECT_MAGIC && s->rec_size == REC && mb_crc32(0, s, offsetof(mb_bcl_sect_t, crc)) == s->crc;
}

void mb_bcl_default(mb_bcl_rec_t* r) {
    memset(r, 0, sizeof(*r));
    r->magic = MB_BCL_REC_MAGIC;
    r->size = REC;
    r->active = MB_SLOT_NONE;
    r->last_slot = MB_SLOT_NONE;
    r->last_entry = 0xFF;
}

typedef struct {
    bool valid;                 /* header ok and at least one good record */
    uint32_t generation;
    mb_bcl_rec_t newest;
    uint32_t next_off;          /* first never-written record position (or size: full) */
} scan_t;

static void scan_sector(const mb_port_t* p, int i, scan_t* out) {
    const mb_region_t* r = &p->layout->log[i];
    memset(out, 0, sizeof(*out));
    mb_bcl_sect_t sh;
    if (p->flash_read(r->offset, &sh, sizeof(sh)) != MB_OK || !sect_ok(&sh)) return;
    out->generation = sh.generation;
    out->next_off = r->size;
    for (uint32_t off = REC; off + REC <= r->size; off += REC) {
        mb_bcl_rec_t rec;
        if (p->flash_read(r->offset + off, &rec, sizeof(rec)) != MB_OK) return;
        if (blank(&rec, sizeof(rec))) { out->next_off = off; break; }
        // a torn record (bad CRC) is skipped, and its space stays used
        if (rec_ok(&rec) && (!out->valid || (int32_t)(rec.seq - out->newest.seq) > 0)) {
            out->newest = rec;
            out->valid = true;
        }
    }
}

int mb_bcl_load(mb_bcl_t* b, const mb_port_t* p) {
    memset(b, 0, sizeof(*b));
    b->port = p;
    scan_t s[2];
    scan_sector(p, 0, &s[0]);
    scan_sector(p, 1, &s[1]);
    int pick = -1;
    if (s[0].valid && s[1].valid) pick = (int32_t)(s[1].generation - s[0].generation) > 0 ? 1 : 0;
    else if (s[0].valid) pick = 0;
    else if (s[1].valid) pick = 1;
    if (pick < 0) {
        mb_bcl_default(&b->cur);
        b->fresh = true;
        b->sector = -1;                 // first commit initialises a sector
        return MB_OK;
    }
    b->cur = s[pick].newest;
    b->sector = pick;
    b->generation = s[pick].generation;
    b->next_off = s[pick].next_off;
    return MB_OK;
}

static int write_rec(const mb_port_t* p, uint32_t off, const void* rec) {
    // records are a fraction of a page: program the whole page, 0xFF elsewhere
    uint32_t page = p->layout->page_size;
    uint8_t buf[256];
    if (page > sizeof(buf) || page % REC) return MB_E_UNSUPP;
    uint32_t base = off - off % page;
    memset(buf, 0xFF, page);
    memcpy(buf + (off - base), rec, REC);
    return p->flash_program(base, buf, page);
}

int mb_bcl_commit(mb_bcl_t* b, const mb_bcl_rec_t* next) {
    const mb_port_t* p = b->port;
    mb_bcl_rec_t rec = *next;
    rec.magic = MB_BCL_REC_MAGIC;
    rec.size = REC;
    rec.seq = b->fresh ? 1 : b->cur.seq + 1;
    rec.crc = mb_crc32(0, &rec, offsetof(mb_bcl_rec_t, crc));

    bool room = b->sector >= 0 && b->next_off + REC <= p->layout->log[b->sector].size;
    if (room) {
        int rc = write_rec(p, p->layout->log[b->sector].offset + b->next_off, &rec);
        b->next_off += REC;             // used even if the write failed half way
        if (rc != MB_OK) return rc;
    } else {
        // move to the other sector: erase, header, record. Until the record
        // is down the old sector (untouched) still holds the valid state.
        int to = b->sector < 0 ? 0 : 1 - b->sector;
        const mb_region_t* r = &p->layout->log[to];
        int rc = p->flash_erase(r->offset, r->size);
        if (rc != MB_OK) return rc;
        mb_bcl_sect_t sh;
        memset(&sh, 0, sizeof(sh));
        sh.magic = MB_BCL_SECT_MAGIC;
        sh.generation = b->generation + 1;
        sh.rec_size = REC;
        sh.crc = mb_crc32(0, &sh, offsetof(mb_bcl_sect_t, crc));
        if ((rc = write_rec(p, r->offset, &sh)) != MB_OK) return rc;
        if ((rc = write_rec(p, r->offset + REC, &rec)) != MB_OK) return rc;
        b->sector = to;
        b->generation = sh.generation;
        b->next_off = 2 * REC;
    }
    b->cur = rec;
    b->fresh = false;
    return MB_OK;
}
