/*
 * MimiBoot - protected rollback floors (and the rest of the protected store)
 *
 * The boot log holds the anti-rollback floor (min_security) and the newest
 * golden version, but the log is ordinary flash the running app writes, so an
 * app that has been taken over could write a record with a lower floor. A
 * port that can protect part of its own flash from the app (nRF: BPROT/ACL
 * locks the bootloader region until reset) keeps a second copy there: an
 * append-only list of entries,
 *
 *     [tag][value][~value][~tag]   (16 bytes; padded to the chip's program unit)
 *
 * tag "MBF0" is the security floor, "MBF1" the golden version, "MBF2" the
 * signed config version, "MBF3" the stage-1 floor. A value is the highest one
 * found for its tag. Two-stage builds also count entries here (tags 14 and
 * 15: which stage 1 worked, and boots of one that hasn't yet), and revoked
 * keys are tag 13. Writing adds one entry into blank flash: a power cut leaves
 * either the old entries or the old entries plus a complete new one (a torn
 * entry fails its check and is skipped, never reused).
 *
 * One unit: when it is full the floors stay where they are (the log copy
 * still works) and nothing more is counted.
 *
 * Two units (port gives `unit` and `erase`): a full unit is compacted into the
 * other one. What still matters is copied into the blank unit (the highest
 * value of each floor, every revoked key, and the stage-1 records of the two
 * copies installed now, attempts capped at MB_STAGE1_TRIES), then the unit's
 * first entry is written last: tag MB_STORE_GEN, value = generation + 1. That
 * entry is the commit; only then is the old unit erased. The unit in force is
 * the one whose first entry is the higher generation; with none, unit 0 from
 * its start (a fresh store, or one that never filled). A power cut anywhere
 * leaves the old unit or the complete new one in force. Nothing is dropped
 * that a decision could depend on: if the revoked keys alone wouldn't fit, the
 * compaction is refused instead.
 *
 * The effective floor is max(log, store): the store can only make the log
 * stricter.
 */
#include "core/mimiboot.h"
#include <string.h>

#define FLOOR_TAG(w) (0x3046424Du + ((uint32_t)(w) << 24)) /* "MBF0", "MBF1" */

// Compaction is compiled only where a store can have two units: board builds
// say so (MB_FLOOR_UNIT from the configurator), host tests and fuzzing have it
#if defined(MB_FLOOR_UNIT)
#define COMPACT (MB_FLOOR_UNIT != 0)
#elif defined(MB_FLASH_BASE)
#define COMPACT 0
#else
#define COMPACT 1
#endif

typedef struct {
    uint32_t tag, value, inv, ntag;
} entry_t;

static bool blank(const entry_t *e) {
    return e->tag == 0xFFFFFFFFu && e->value == 0xFFFFFFFFu && e->inv == 0xFFFFFFFFu && e->ntag == 0xFFFFFFFFu;
}
static bool valid(const entry_t *e) { return e->inv == ~e->value && e->ntag == ~e->tag; }

static bool store_ok(const mb_floor_store_t *s) { return s && s->read && s->entry >= sizeof(entry_t) && s->entry <= 256; }
static bool two_units(const mb_floor_store_t *s) {
    return COMPACT && s->erase && s->unit && s->unit % s->entry == 0 && s->size >= 2 * s->unit;
}

// The unit in force: [*base + *first, *base + *end) holds its entries (offsets in the store)
static int active(const mb_floor_store_t *s, uint32_t *base, uint32_t *first, uint32_t *end, uint32_t *gen) {
    *base = *first = *gen = 0;
    *end = s->size;
    if (!two_units(s))
        return MB_OK;
    *end = s->unit;
    bool have = false;
    for (uint32_t u = 0; u < 2; u++) {
        entry_t e;
        if (s->read(s->off + u * s->unit, &e, sizeof e) != MB_OK)
            return MB_E_IO;
        if (valid(&e) && e.tag == FLOOR_TAG(MB_STORE_GEN) && (!have || e.value > *gen)) {
            have = true;
            *gen = e.value;
            *base = u * s->unit;
            *first = s->entry;
        }
    }
    return MB_OK;
}

// Walk the unit in force: highest value per floor, and the first blank entry
// (store offset), or the unit's end when full
static int scan(const mb_floor_store_t *s, uint32_t out[MB_FLOOR_COUNT], uint32_t *free_at, uint32_t *unit_end) {
    for (int i = 0; i < MB_FLOOR_COUNT; i++)
        out[i] = 0;
    uint32_t base, off, end, gen;
    int rc = active(s, &base, &off, &end, &gen);
    if (rc != MB_OK)
        return rc;
    for (; off + s->entry <= end; off += s->entry) {
        entry_t e;
        if (s->read(s->off + base + off, &e, sizeof e) != MB_OK)
            return MB_E_IO;
        if (blank(&e))
            break;
        if (!valid(&e))
            continue; // torn by a power cut: skip it, never reuse it
        for (int w = 0; w < MB_FLOOR_COUNT; w++)
            if (e.tag == FLOOR_TAG(w) && e.value > out[w])
                out[w] = e.value;
    }
    if (free_at)
        *free_at = base + off;
    if (unit_end)
        *unit_end = base + end;
    return MB_OK;
}

int mb_floor_get(const mb_port_t *p, uint32_t out[MB_FLOOR_COUNT]) {
    for (int i = 0; i < MB_FLOOR_COUNT; i++)
        out[i] = 0;
    if (!store_ok(p->floor))
        return MB_E_UNSUPP;
    return scan(p->floor, out, NULL, NULL);
}

// How many valid entries with this tag and value (two-stage: stage-1 boot attempts)
int mb_store_count(const mb_port_t *p, int tag, uint32_t value) {
    const mb_floor_store_t *s = p->floor;
    if (!store_ok(s))
        return 0;
    uint32_t base, off, end, gen;
    if (active(s, &base, &off, &end, &gen) != MB_OK)
        return 0;
    int n = 0;
    for (; off + s->entry <= end; off += s->entry) {
        entry_t e;
        if (s->read(s->off + base + off, &e, sizeof e) != MB_OK || blank(&e))
            break;
        if (valid(&e) && e.tag == FLOOR_TAG(tag) && e.value == value)
            n++;
    }
    return n;
}

static int put(const mb_floor_store_t *s, uint32_t at, int tag, uint32_t value) {
    uint8_t buf[256];
    memset(buf, 0xFF, s->entry);
    entry_t e = {FLOOR_TAG(tag), value, ~value, ~FLOOR_TAG(tag)};
    memcpy(buf, &e, sizeof e);
    return s->program(s->off + at, buf, s->entry);
}

#if COMPACT
// The stage-1 copies installed now (their records are the ones stage 0 looks up)
static int live_stage1(const mb_port_t *p, uint32_t ids[2]) {
    int n = 0;
    for (int i = 0; i < p->layout->n_slots && n < 2; i++) {
        mb_image_hdr_t h;
        if (mb_slot_role(p, i) != MB_ROLE_STAGE1 || p->flash_read(p->layout->slot[i].offset, &h, sizeof h) != MB_OK ||
            mb_image_check_header(p, &h, p->layout->slot[i].size) != MB_OK)
            continue;
        ids[n++] = (uint32_t)mb_image_id(&h);
    }
    return n;
}

#define KEEP_MAX 40 /* entries carried over besides the floors */

// Copy what still matters into the other unit, commit it, erase the old one
static int compact(const mb_port_t *p) {
    const mb_floor_store_t *s = p->floor;
    if (!two_units(s) || !s->program)
        return MB_E_NOSPACE;
    uint32_t base, off, end, gen;
    int rc = active(s, &base, &off, &end, &gen);
    if (rc != MB_OK)
        return rc;
    uint32_t fl[MB_FLOOR_COUNT];
    if ((rc = scan(s, fl, NULL, NULL)) != MB_OK)
        return rc;
    uint32_t ids[2];
    int nid = p->layout && p->flash_read ? live_stage1(p, ids) : 0;
    struct {
        uint8_t tag;
        uint32_t value;
    } keep[KEEP_MAX];
    int nk = 0;
    for (; off + s->entry <= end; off += s->entry) {
        entry_t e;
        if (s->read(s->off + base + off, &e, sizeof e) != MB_OK)
            return MB_E_IO;
        if (blank(&e))
            break;
        if (!valid(&e) || (e.tag & 0x00FFFFFFu) != (FLOOR_TAG(0) & 0x00FFFFFFu))
            continue; // torn, or not one of ours
        int tag = (int)((e.tag - FLOOR_TAG(0)) >> 24);
        if (tag < MB_FLOOR_COUNT || tag == MB_STORE_GEN || tag > 15)
            continue; // floors: their maximum is written below
        int same = 0;
        for (int k = 0; k < nk; k++)
            same += keep[k].tag == tag && keep[k].value == e.value;
        if (tag == MB_STORE_S1_GOOD || tag == MB_STORE_S1_ATTEMPT) {
            bool live = false;
            for (int i = 0; i < nid; i++)
                live |= ids[i] == e.value;
            if (!live || same >= (tag == MB_STORE_S1_ATTEMPT ? MB_STAGE1_TRIES : 1))
                continue; // a copy that isn't installed any more, or counted enough
        } else if (same) {
            continue; // revoked keys (and anything newer): each once
        }
        if (nk == KEEP_MAX)
            return MB_E_NOSPACE; // never drop something a decision could depend on
        keep[nk].tag = (uint8_t)tag;
        keep[nk].value = e.value;
        nk++;
    }
    int floors = 0;
    for (int w = 0; w < MB_FLOOR_COUNT; w++)
        floors += fl[w] != 0;
    if ((uint32_t)(1 + floors + nk + MB_STORE_RESERVE) * s->entry > s->unit)
        return MB_E_NOSPACE; // compacting wouldn't free enough to be worth it
    uint32_t to = base == 0 ? s->unit : 0;
    if ((rc = s->erase(s->off + to, s->unit)) != MB_OK)
        return rc;
    uint32_t at = to + s->entry; // the first entry (the commit) comes last
    for (int w = 0; w < MB_FLOOR_COUNT; w++)
        if (fl[w] && (rc = put(s, at, w, fl[w]), at += s->entry, rc != MB_OK))
            return rc;
    for (int k = 0; k < nk; k++)
        if ((rc = put(s, at, keep[k].tag, keep[k].value), at += s->entry, rc != MB_OK))
            return rc;
    if ((rc = put(s, to, MB_STORE_GEN, gen + 1)) != MB_OK)
        return rc;
    uint32_t nb, nf, ne, ng;
    if (active(s, &nb, &nf, &ne, &ng) != MB_OK || nb != to || ng != gen + 1)
        return MB_E_IO; // the commit doesn't read back: the old unit stays in force
    s->erase(s->off + base, s->unit); // a failure here only leaves a stale, lower generation
    return MB_OK;
}
#else
static int compact(const mb_port_t *p) {
    (void)p;
    return MB_E_NOSPACE;
}
#endif

// Room for one more entry (`keep` bytes held back), compacting once if needed
static int room(const mb_port_t *p, uint32_t keep, uint32_t cur[MB_FLOOR_COUNT], uint32_t *at) {
    const mb_floor_store_t *s = p->floor;
    for (int pass = 0; pass < 2; pass++) {
        uint32_t end;
        int rc = scan(s, cur, at, &end);
        if (rc != MB_OK)
            return rc;
        if (*at <= end && end - *at >= s->entry + keep)
            return MB_OK;
        if (pass == 0 && (rc = compact(p)) != MB_OK)
            return rc;
    }
    return MB_E_NOSPACE;
}

// Write one more counted entry (MB_STORE_S1_*, MB_STORE_KEY_REVOKED). Attempts
// stop short of the last MB_STORE_RESERVE entries, so counting boots can never
// use up the room a floor raise needs. Read back like a floor: it counts only
// if it reads as written.
int mb_store_append(const mb_port_t *p, int tag, uint32_t value) {
    const mb_floor_store_t *s = p->floor;
    if (!s || !s->read || !s->program || tag < MB_FLOOR_COUNT || tag == MB_STORE_GEN || tag > 15)
        return MB_E_UNSUPP;
    if (!store_ok(s))
        return MB_E_BADARG;
    uint32_t cur[MB_FLOOR_COUNT], at;
    int rc = room(p, tag == MB_STORE_S1_ATTEMPT ? MB_STORE_RESERVE * s->entry : 0, cur, &at);
    if (rc != MB_OK)
        return rc;
    int before = mb_store_count(p, tag, value);
    if ((rc = put(s, at, tag, value)) != MB_OK)
        return rc;
    return mb_store_count(p, tag, value) > before ? MB_OK : MB_E_IO;
}

int mb_floor_raise(const mb_port_t *p, int which, uint32_t value) {
    const mb_floor_store_t *s = p->floor;
    if (!s || !s->read || !s->program || which < 0 || which >= MB_FLOOR_COUNT)
        return MB_E_UNSUPP;
    if (!store_ok(s))
        return MB_E_BADARG;
    uint32_t cur[MB_FLOOR_COUNT], at;
    int rc = scan(s, cur, NULL, NULL);
    if (rc != MB_OK)
        return rc;
    if (value <= cur[which])
        return MB_OK; // already there: nothing written
    if ((rc = room(p, 0, cur, &at)) != MB_OK)
        return rc;
    if ((rc = put(s, at, which, value)) != MB_OK)
        return rc;
    uint32_t now[MB_FLOOR_COUNT];
    rc = scan(s, now, NULL, NULL); // read back: the write counts only if it reads as written
    if (rc != MB_OK)
        return rc;
    return now[which] >= value ? MB_OK : MB_E_IO;
}
