/*
 * MimiBoot - two-stage builds: stage 0 picks a stage 1, stage 1 confirms itself
 *
 * Flash, in a two-stage build:
 *
 *   boot region   stage 0 (small, never updated) + the store (its last erase unit)
 *   s1a, s1b      two copies of stage 1 (the full bootloader), each a signed
 *                 image linked for its own slot (MB_IMG_F_STAGE1)
 *   log, cfg, A/B, golden ... as in a one-stage build
 *
 * Stage 1 is updated like an app: upload the new one into the copy that isn't
 * running, reboot. Stage 0 then tries it, and keeps the old copy as the way
 * back:
 *
 *   - a copy is usable when its header is good, it is a stage 1 for this
 *     target linked for that slot, it is at or above the stage-1 rollback
 *     floor, it is signed by a stage-1 key (when signatures are required) and
 *     its hash matches. Every boot, both copies.
 *   - a copy that has started an image (stage 1 got as far as launching an
 *     app) is "good": an entry in the store says so (MB_STORE_S1_GOOD).
 *   - a usable copy that isn't good yet is on trial: every boot of it is
 *     counted first (MB_STORE_S1_ATTEMPT). After MB_STAGE1_TRIES boots
 *     without it confirming, it is passed over.
 *
 * The order: not failed, then the higher version, then good. So an update is
 * tried, and wins once it works; one that never works falls back to the old.
 *
 * Never bricked by its own bookkeeping:
 *   - with only one usable copy, it boots whatever its record (nothing to
 *     fall back to, so nothing is counted, and the store doesn't fill up
 *     while a board sits at the menu with no app);
 *   - if every usable copy has failed, the best of them boots anyway;
 *   - if an attempt can't be recorded (store full, write failed), a trial
 *     doesn't start: a good copy runs instead, so a hanging update can't loop
 *     uncounted.
 *
 * There is no watchdog in stage 0: on most of these chips a watchdog can't be
 * stopped or slowed once started, so it would follow stage 1 into the app. A
 * stage 1 that faults resets itself (the fault handler); one that hangs is
 * counted by power cycles.
 */
#include "core/mimiboot.h"
#include <string.h>

static uint32_t id32(const mb_image_hdr_t *h) { return (uint32_t)mb_image_id(h); }

// Everything that makes `slot` a stage 1 stage 0 may start (its own floor, keys)
static bool usable(const mb_port_t *p, int slot, uint32_t floor, mb_slot_info_t *in) {
    if (mb_image_read_header(p, slot, in) != MB_OK || in->fmt != MB_FMT_NATIVE)
        return false;
    if (mb_stage1_accepts(p, slot, &in->hdr) != MB_OK || mb_stage1_vectors_ok(p, slot, &in->hdr) != MB_OK)
        return false;
    if (in->hdr.security_version < floor)
        return false;
    if (p->can_start && !p->can_start(&in->hdr))
        return false;
    mb_checking_slot = (uint8_t)slot; // a fault from here on is this copy's flash
    bool ok = mb_stage1_check_sig(p, in) == MB_OK && mb_image_verify(p, slot, in) == MB_OK;
    mb_checking_slot = MB_SLOT_NONE;
    return ok;
}

typedef struct {
    int slot;
    bool good, failed;
    int tries;
} cand_t;

// a before b?
static bool better(const cand_t *a, const mb_slot_info_t *ia, const cand_t *b, const mb_slot_info_t *ib) {
    if (a->failed != b->failed)
        return !a->failed;
    if (ia->hdr.version != ib->hdr.version)
        return ia->hdr.version > ib->hdr.version;
    if (a->good != b->good)
        return a->good;
    return a->tries < b->tries;
}

int mb_stage0_choose(const mb_port_t *p, mb_stage0_choice_t *out) {
    static mb_slot_info_t info[2];
    cand_t c[2];
    int n = 0;
    memset(out, 0, sizeof(*out));
    out->slot = -1;
    uint32_t fl[MB_FLOOR_COUNT];
    mb_floor_get(p, fl);
    // the CPU faulted while checking a copy last time: leave that one out this boot
    int faulted = p->fault_slot ? p->fault_slot() : -1;
    for (int i = 0; i < p->layout->n_slots && n < 2; i++) {
        if (mb_slot_role(p, i) != MB_ROLE_STAGE1 || i == faulted)
            continue;
        if (!usable(p, i, fl[MB_FLOOR_STAGE1], &info[n]))
            continue;
        uint32_t id = id32(&info[n].hdr);
        c[n].slot = i;
        c[n].good = mb_store_count(p, MB_STORE_S1_GOOD, id) > 0;
        c[n].tries = mb_store_count(p, MB_STORE_S1_ATTEMPT, id);
        c[n].failed = !c[n].good && c[n].tries >= MB_STAGE1_TRIES;
        n++;
    }
    if (n == 0)
        return MB_E_CORRUPT;
    int best = n == 2 && better(&c[1], &info[1], &c[0], &info[0]) ? 1 : 0;
    int other = 1 - best;
    if (!c[best].good && !c[best].failed && n == 2) {
        // on trial with somewhere to fall back to: count this boot before it runs
        if (mb_store_append(p, MB_STORE_S1_ATTEMPT, id32(&info[best].hdr)) == MB_OK)
            out->trial = true;
        else if (c[other].good)
            best = other; // can't count it: run the copy known to work
    }
    out->slot = c[best].slot;
    out->info = info[best];
    return MB_OK;
}

// Stage 1, about to start an image: it works. Record that (once) and raise
// the stage-1 floor to its security version, like a confirmed app's.
int mb_stage1_confirm(const mb_port_t *p) {
    if (!p->stage1_slot || !p->floor)
        return MB_E_UNSUPP;
    int s = p->stage1_slot();
    mb_image_hdr_t h;
    if (s < 0 || s >= p->layout->n_slots || p->flash_read(p->layout->slot[s].offset, &h, sizeof(h)) != MB_OK ||
        mb_image_check_header(p, &h, p->layout->slot[s].size) != MB_OK)
        return MB_E_CORRUPT;
    int rc = MB_OK;
    if (mb_store_count(p, MB_STORE_S1_GOOD, id32(&h)) == 0)
        rc = mb_store_append(p, MB_STORE_S1_GOOD, id32(&h));
    uint32_t fl[MB_FLOOR_COUNT];
    mb_floor_get(p, fl);
    if (h.security_version > fl[MB_FLOOR_STAGE1]) {
        int r2 = mb_floor_raise(p, MB_FLOOR_STAGE1, h.security_version);
        if (rc == MB_OK)
            rc = r2;
    }
    return rc;
}
