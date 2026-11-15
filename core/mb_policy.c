/*
 * MimiBoot - boot policy
 *
 * What gets booted is a config *entry*: the one-shot request if there is
 * one, else the config's default. An entry names a slot, or "ab":
 *
 *   ab      1. an update: NEW (just installed) before TRIAL (tries left), higher version first
 *           2. the active GOOD A/B slot (last confirmed), then the other GOOD one
 *           3. golden
 *   <slot>  1. that slot
 *           2. fallback: the GOOD A/B slots, then golden
 *
 * (So a pending A/B update is tried when an "ab" entry boots, not while the
 * default is some aux image.)
 *
 * Every candidate must pass: built for this target, startable by this port
 * (arch, load type), the entry's arch if it names one, security_version >=
 * the floor (A/B only), the signature (checked once per image, then cached
 * in the log), and a full SHA-256 of the payload (every boot). Failing ones
 * are marked BAD with the reason and the next candidate is tried.
 *
 * Trial attempts are spent *before* launching: a crash, a hang (watchdog), a
 * power cut or an architecture-switch reboot all cost an attempt.
 *
 * Crash-loop guard: consecutive watchdog resets of a GOOD image count as
 * strikes; at MB_STRIKES_MAX it is passed over (as long as something else
 * is bootable) until a reset that isn't a watchdog timeout, or a confirm.
 */
#include "core/mimiboot.h"
#include <stdio.h>
#include <string.h>

// The protected floors (port flash the app can't write), read once per decision.
// The effective floor is the higher of these and the log's copy.
static uint32_t hw_floor[MB_FLOOR_COUNT];

static void load_floors(const mb_port_t *p) { mb_floor_get(p, hw_floor); }

static uint32_t security_floor(const mb_bcl_rec_t *r) {
    return r->min_security > hw_floor[MB_FLOOR_SECURITY] ? r->min_security : hw_floor[MB_FLOOR_SECURITY];
}

// A golden image that is older than one already accepted must not take over.
// The log remembers which image set its golden_version (the same image may
// come back after a log wipe); the protected copy only knows the version, so
// it refuses anything strictly older.
static bool golden_too_old(const mb_bcl_rec_t *r, uint64_t id, uint32_t version) {
    if (r->golden_id && id != r->golden_id && version <= r->golden_version)
        return true;
    return version < hw_floor[MB_FLOOR_GOLDEN];
}

static bool startable(const mb_port_t *p, const mb_image_hdr_t *h) {
    if (strncmp(h->target, p->target, sizeof(h->target)) != 0)
        return false;
#if !MB_FEAT_RAM_IMAGES
    if (h->load_type == MB_LOAD_RAM)
        return false; // this build can't stage RAM images
#endif
    if (p->can_start)
        return p->can_start(h);
    return h->load_type == MB_LOAD_CHAIN && (h->arch == MB_ARCH_ANY || h->arch == p->arch);
}

static void mark_bad(mb_bcl_rec_t *r, int slot, int reason) {
    r->slot[slot].state = MB_ST_BAD;
    r->slot[slot].bad_reason = (uint8_t)reason;
    r->slot[slot].tries_left = 0;
}

// Bring the log in line with the slots' headers
static void reconcile(const mb_port_t *p, mb_bcl_rec_t *r, mb_slot_info_t info[MB_MAX_SLOTS]) {
    for (int i = 0; i < MB_MAX_SLOTS; i++) {
        if (i >= p->layout->n_slots) {
            memset(&info[i], 0, sizeof(info[i]));
            continue;
        }
        mb_image_read_header(p, i, &info[i]);
        mb_slot_rec_t *s = &r->slot[i];
        if (mb_slot_role(p, i) == MB_ROLE_STAGE1) {
            // the bootloader's own copies: stage 0 keeps their books, the log never does
            if (s->state != MB_ST_EMPTY || s->image_id)
                memset(s, 0, sizeof(*s));
            continue;
        }
        if (!info[i].header_ok) {
            if (s->state != MB_ST_EMPTY || s->image_id)
                memset(s, 0, sizeof(*s));
            continue;
        }
        uint64_t id = mb_image_id(&info[i].hdr);
        if (id == s->image_id && s->state != MB_ST_EMPTY)
            continue; // known image
        memset(s, 0, sizeof(*s));
        s->image_id = id;
        if (!startable(p, &info[i].hdr)) {
            mark_bad(r, i, MB_BAD_TARGET);
            continue;
        }
        if (mb_slot_role(p, i) == MB_ROLE_GOLDEN && golden_too_old(r, id, info[i].hdr.version)) {
            mark_bad(r, i, MB_BAD_GOLDEN_OLD); // monotonic golden: only a strictly newer one may replace it
            continue;
        }
        s->state = MB_ST_NEW;
        s->tries_left = MB_DEFAULT_TRIES;
    }
    // Zephyr apps confirm themselves in MCUboot's trailer, not through the
    // MimiBoot client: honour that like a client confirm (it can only be
    // written by the same app that could call mb_client_confirm())
    for (int i = 0; i < p->layout->n_slots && i < MB_MAX_SLOTS; i++) {
        mb_slot_rec_t *s = &r->slot[i];
        if (info[i].fmt != MB_FMT_MCUBOOT || mb_slot_role(p, i) != MB_ROLE_AB ||
            (s->state != MB_ST_NEW && s->state != MB_ST_TRIAL) || !mb_mcuboot_confirmed(p, i))
            continue;
        s->state = MB_ST_GOOD;
        s->tries_left = 0;
        r->active = (uint8_t)i;
        if (info[i].hdr.security_version > r->min_security)
            r->min_security = info[i].hdr.security_version;
    }
}

static bool verify(const mb_port_t *p, mb_bcl_rec_t *r, mb_slot_info_t info[MB_MAX_SLOTS], int slot);

// Can `slot` be booted? Marks it bad in r if it never can.
static bool admit(const mb_port_t *p, mb_bcl_rec_t *r, mb_slot_info_t info[MB_MAX_SLOTS], int slot, uint8_t want_arch) {
    if (slot < 0 || slot >= p->layout->n_slots || mb_slot_role(p, slot) == MB_ROLE_STAGE1)
        return false; // a stage-1 copy is never booted as an image
    mb_slot_rec_t *s = &r->slot[slot];
    if (s->state == MB_ST_EMPTY || s->state == MB_ST_BAD)
        return false;
    if (info[slot].hdr.flags & MB_IMG_F_STAGE1) {
        mark_bad(r, slot, MB_BAD_TARGET); // a bootloader stage 1 put in an app slot
        return false;
    }
    if (s->state == MB_ST_TRIAL && s->tries_left == 0) {
        mark_bad(r, slot, MB_BAD_TRIALS);
        return false;
    }
    if (want_arch != MB_ARCH_ANY && info[slot].hdr.arch != want_arch)
        return false; // config mismatch, not the image's fault
#if MB_FEAT_ANTI_ROLLBACK
    if (mb_slot_role(p, slot) == MB_ROLE_AB && info[slot].hdr.security_version < security_floor(r)) {
        mark_bad(r, slot, MB_BAD_ROLLBACK);
        return false;
    }
#endif
    mb_checking_slot = (uint8_t)slot; // a fault from here on is this image's flash
    bool ok = verify(p, r, info, slot);
    mb_checking_slot = MB_SLOT_NONE;
    return ok;
}

// Signature, then the payload hash (per MB_BOOT_VERIFY)
static bool verify(const mb_port_t *p, mb_bcl_rec_t *r, mb_slot_info_t info[MB_MAX_SLOTS], int slot) {
    mb_slot_rec_t *s = &r->slot[slot];
    // The "signature checked" flag lives in the log, which a running image can
    // write. When signatures are *required* it is therefore never trusted:
    // every boot verifies. (Optional mode uses it only to save time.)
    if (p->require_signature || !(s->flags & MB_SF_SIG_OK)) {
        if (mb_image_check_sig(p, &info[slot]) != MB_OK) {
            mark_bad(r, slot, MB_BAD_SIGNATURE);
            return false;
        }
        if (info[slot].hdr.flags & MB_IMG_F_SIGNED)
            s->flags |= MB_SF_SIG_OK; // the hash still runs every boot
    } else {
        info[slot].proof_sig = MB_PROOF_UNSIGNED; // optional signatures, checked on an earlier boot: not now
    }
#if MB_BOOT_VERIFY == MB_BOOT_VERIFY_NEVER
    (void)0;    // header checks only: installs were hashed as they arrived
#else
#if MB_BOOT_VERIFY == MB_BOOT_VERIFY_ONCE
    if (!(s->flags & MB_SF_HASH_OK)) {  // the first boot of this image hashes it, later ones trust that
#endif
        if (mb_image_verify(p, slot, &info[slot]) != MB_OK) {
            mark_bad(r, slot, MB_BAD_HASH);
            return false;
        }
#if MB_BOOT_VERIFY == MB_BOOT_VERIFY_ONCE
        s->flags |= MB_SF_HASH_OK;
    }
#endif
#endif
    return true;
}

// The record to write when booting `slot`
static void book(const mb_port_t *p, mb_bcl_rec_t *r, const mb_slot_info_t info[MB_MAX_SLOTS], int slot, int kind,
                 int entry, mb_choice_t *c) {
    mb_slot_rec_t *s = &r->slot[slot];
    c->slot = slot;
    c->kind = kind;
    c->entry = entry;
    c->trial = false;
    switch (mb_slot_role(p, slot)) {
    case MB_ROLE_GOLDEN:
        if (s->state == MB_ST_NEW) { // golden needs no confirmation, only a good hash
            s->state = MB_ST_GOOD;
            r->golden_id = s->image_id;
            r->golden_version = info[slot].hdr.version;
        }
        break;
    case MB_ROLE_AUX:
        if (s->state == MB_ST_NEW)
            s->state = MB_ST_GOOD;
        break;
    case MB_ROLE_STAGE1:
        break; // unreachable: admit() never lets one through
    default:
#if !MB_FEAT_AB_TRIAL
        // Updates are trusted once their checks pass: no trial, no confirm.
        // Same bookkeeping as a confirm (preferred slot, security floor).
        if (s->state == MB_ST_NEW || s->state == MB_ST_TRIAL) {
            s->state = MB_ST_GOOD;
            s->tries_left = 0;
            r->active = (uint8_t)slot;
            if (info[slot].hdr.security_version > r->min_security)
                r->min_security = info[slot].hdr.security_version;
        }
        if (c->kind == MB_KIND_TRIAL)
            c->kind = MB_KIND_NORMAL;
        break;
#endif
        if (s->state == MB_ST_NEW || s->state == MB_ST_TRIAL) {
            s->state = MB_ST_TRIAL;
            s->tries_left--; // spent now, before it runs
            if (s->boots < 0xFFFF)
                s->boots++;
            c->trial = true;
            if (kind == MB_KIND_NORMAL)
                c->kind = MB_KIND_TRIAL;
        }
    }
    if (r->last_slot != slot)
        r->strikes = 0; // strikes belong to the image that collected them
    r->last_slot = (uint8_t)slot;
    r->last_kind = (uint8_t)c->kind;
    r->last_entry = (uint8_t)(entry < 0 ? 0xFF : entry);
}

static bool differs(const mb_bcl_rec_t *a, const mb_bcl_rec_t *b) {
    return memcmp(a, b, offsetof(mb_bcl_rec_t, seq)) ||
           memcmp(&a->slot, &b->slot, offsetof(mb_bcl_rec_t, crc) - offsetof(mb_bcl_rec_t, slot));
}

typedef struct {
    int slot[2 * MB_MAX_SLOTS + 2];
    int kind[2 * MB_MAX_SLOTS + 2];
    int n;
} cands_t;

static void push(cands_t *c, int slot, int kind) {
    for (int i = 0; i < c->n; i++)
        if (c->slot[i] == slot)
            return;
    if (c->n < (int)(sizeof(c->slot) / sizeof(c->slot[0]))) {
        c->slot[c->n] = slot;
        c->kind[c->n++] = kind;
    }
}

static void push_goods(cands_t *c, const mb_bcl_rec_t *r, int kind) {
    int first = r->active == MB_SLOT_B ? MB_SLOT_B : MB_SLOT_A;
    if (r->slot[first].state == MB_ST_GOOD)
        push(c, first, kind);
    if (r->slot[1 - first].state == MB_ST_GOOD)
        push(c, 1 - first, kind);
}

static void push_updates(cands_t *c, const mb_bcl_rec_t *r, const mb_slot_info_t *info, unsigned flags) {
    if (flags & MB_F_NO_TRIAL)
        return;
    int upd[2], nu = 0;
    for (int slot = MB_SLOT_A; slot <= MB_SLOT_B; slot++) {
        int st = r->slot[slot].state;
        if (st == MB_ST_TRIAL || st == MB_ST_NEW)
            upd[nu++] = slot;
    }
    if (nu == 2) { // NEW before TRIAL (the latest install wins), then the newer version
        int ra = r->slot[upd[0]].state == MB_ST_NEW ? 0 : 1, rb = r->slot[upd[1]].state == MB_ST_NEW ? 0 : 1;
        if (rb < ra || (rb == ra && info[upd[1]].hdr.version > info[upd[0]].hdr.version)) {
            int t = upd[0];
            upd[0] = upd[1];
            upd[1] = t;
        }
    }
    for (int k = 0; k < nu; k++)
        push(c, upd[k], MB_KIND_TRIAL);
}

static void candidates(const mb_bcl_rec_t *r, const mb_slot_info_t *info, const mb_entry_t *e, int first_kind,
                       unsigned flags, cands_t *c) {
    c->n = 0;
    if (!e || e->slot == MB_SLOT_AB) {
        push_updates(c, r, info, flags);
        push_goods(c, r, first_kind);
    } else {
        int st = r->slot[e->slot].state;
        if (!((flags & MB_F_NO_TRIAL) && (st == MB_ST_NEW || st == MB_ST_TRIAL) && e->slot <= MB_SLOT_B))
            push(c, e->slot, first_kind);
        push_goods(c, r, MB_KIND_FALLBACK);
    }
    push(c, MB_SLOT_GOLDEN, MB_KIND_GOLDEN);
}

static void set_args(mb_choice_t *ch, const char *args) {
    snprintf(ch->args, sizeof(ch->args), "%s", args ? args : "");
}

// Walk the candidates; on success fill plan (base = r before booking)
static bool pick(const mb_port_t *p, const mb_bcl_t *log, mb_bcl_rec_t *r, mb_slot_info_t info[MB_MAX_SLOTS],
                 const cands_t *c, const mb_entry_t *e, int entry, const char *args, int suspect, mb_plan_t *plan) {
    for (int pass = 0; pass < 2; pass++) {
        bool skipped = false;
        for (int k = 0; k < c->n; k++) {
            int slot = c->slot[k];
            if (pass == 0 && slot == suspect) {
                skipped = true;
                continue;
            }
            uint8_t want = e && e->slot == slot ? e->arch : MB_ARCH_ANY;
            if (!admit(p, r, info, slot, want)) {
                skipped = skipped || r->slot[slot].state != MB_ST_EMPTY;
                continue;
            }
            mb_topology_t profile = plan->choice.topology;
            bool own_profile = e && (e->slot == slot || (e->slot == MB_SLOT_AB && slot <= MB_SLOT_B));
            if (!profile.core0 && !profile.core1 && own_profile)
                profile = e->topology;
            mb_topology_t resolved;
            if (mb_topology_resolve(p, profile, info[slot].hdr.arch, &resolved) != MB_OK)
                continue;
            plan->choice.topology = resolved;
            plan->base = *r;
            int kind = c->kind[k];
            if (skipped && (kind == MB_KIND_NORMAL || kind == MB_KIND_ENTRY))
                kind = MB_KIND_FALLBACK;
            // the entry's args belong to the entry's own slot (or the A/B pair it names)
            bool own = e && (e->slot == slot || (e->slot == MB_SLOT_AB && slot <= MB_SLOT_B));
            book(p, r, info, slot, kind, own ? entry : -1, &plan->choice);
            set_args(&plan->choice, own ? args : "");
            plan->boot = *r;
            plan->base_dirty = differs(&plan->base, &log->cur);
            plan->boot_dirty = differs(&plan->boot, &log->cur);
            return true;
        }
        if (suspect == MB_SLOT_NONE)
            break; // no second pass needed
    }
    return false;
}

int mb_decide(const mb_port_t *p, const mb_bcl_t *log, const mb_config_t *cfg, mb_slot_info_t info[MB_MAX_SLOTS],
              unsigned flags, mb_plan_t *plan) {
    memset(plan, 0, sizeof(*plan));
    plan->choice.slot = MB_SLOT_NONE;
    plan->choice.entry = -1;
    mb_bcl_rec_t r = log->cur;
    load_floors(p);
    reconcile(p, &r, info);

    // crash-loop guard (an architecture handover reboot is not a crash: the
    // reset hardware may report it as one, so it is flagged in the log)
    int suspect = MB_SLOT_NONE;
    if (r.flags & MB_LF_HANDOVER) {
        r.flags &= (uint8_t)~MB_LF_HANDOVER;
    }
#if MB_FEAT_CRASH_GUARD
    else if (!(flags & MB_F_AGAIN)) {
        // a crash: a watchdog reset, or the OS saying it panicked / faulted (in the mailbox)
        uint32_t cause = p->reset_cause ? p->reset_cause() : 0;
        bool crash = (cause & MB_RESET_WATCHDOG) || mb_mailbox_crashed();
        if (crash && r.last_slot < p->layout->n_slots && r.slot[r.last_slot].state == MB_ST_GOOD) {
            if (r.strikes < 0xFF)
                r.strikes++;
            if (r.strikes >= MB_STRIKES_MAX)
                suspect = r.last_slot;
        } else if (!crash && r.strikes) {
            r.strikes = 0;
        }
    }
#endif

    // which entry
    int entry = cfg->def, once_slot = -1;
    int first_kind = MB_KIND_NORMAL;
    const char *args = NULL;
    char once_args[MB_ARGS_MAX];
    int action = -1;
    int control = 0;
    // A request from the RAM mailbox goes into this copy of the log record (never into
    // flash) and is consumed below exactly like one an app wrote to the log. One that
    // is already in the log (written to flash, so it survives a power cut) comes first.
#if MB_FEAT_OS_HOOKS
    if (mb_mailbox_next.version) {
        if (r.request == MB_REQ_NONE)
            control = mb_control_put(p, &r, cfg, &mb_mailbox_next);
        mb_mailbox_next.version = 0;
    }
#endif
    if (control == 0)
        control = mb_control_consume(p, &r, cfg, &plan->choice.topology, &action);
    if (control < 0) {
        r.request = MB_REQ_NONE;
        r.request_arg = 0;
        memset(r.args, 0, sizeof r.args);
        plan->base = plan->boot = r;
        plan->base_dirty = plan->boot_dirty = true;
        plan->choice.want_menu = plan->choice.config_mode = true;
        plan->choice.control_error = control;
        return control;
    }
    if (control > 0) {
        switch (action) {
        case MB_CONTROL_MENU:
            r.request = MB_REQ_MENU;
            break;
        case MB_CONTROL_CONFIG:
            r.request = MB_REQ_MENU;
            plan->choice.config_mode = true;
            break;
        case MB_CONTROL_ROM:
            r.request = MB_REQ_BOOTSEL;
            break;
        case MB_CONTROL_FLASH:
            r.request = MB_REQ_FLASH;
            break;
        case MB_CONTROL_ENTRY:
            r.request = MB_REQ_ENTRY_ONCE;
            break;
        case MB_CONTROL_SLOT:
            r.request = MB_REQ_BOOT_ONCE;
            break;
        default:
            r.request = MB_REQ_NONE;
            break;
        }
    }
    switch (r.request) {
    case MB_REQ_MENU:
        plan->choice.want_menu = true;
        break;
    case MB_REQ_BOOTSEL:
        plan->choice.want_rom = true;
        break;
    case MB_REQ_FLASH:
        plan->choice.want_menu = plan->choice.flash_mode = true;
        break;
    case MB_REQ_BOOT_ONCE:
        if (r.request_arg < p->layout->n_slots)
            once_slot = r.request_arg;
        break;
    case MB_REQ_ENTRY_ONCE:
        if (r.request_arg < cfg->n) {
            entry = r.request_arg;
            first_kind = MB_KIND_ENTRY;
            if (r.args[0]) {
                snprintf(once_args, sizeof(once_args), "%.*s", MB_ARGS_MAX - 1, r.args);
                args = once_args;
            }
        }
        break;
    }
    if ((once_slot >= 0 || (control > 0 && action == MB_CONTROL_RESTART)) && r.args[0]) {
        snprintf(once_args, sizeof once_args, "%.*s", MB_ARGS_MAX - 1, r.args);
        args = once_args;
    }
    r.request = MB_REQ_NONE;
    r.request_arg = 0;
    memset(r.args, 0, sizeof(r.args));
    if (flags & MB_F_MENU)
        plan->choice.want_menu = true;

    const mb_entry_t *e = entry >= 0 && entry < cfg->n ? &cfg->e[entry] : NULL;
    if (!args && e)
        args = e->args;
    cands_t c;
    if (once_slot >= 0) {
        mb_entry_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.slot = (uint8_t)once_slot;
        tmp.topology = plan->choice.topology;
        candidates(&r, info, &tmp, MB_KIND_ONCE, flags, &c);
        if (pick(p, log, &r, info, &c, &tmp, -1, args ? args : "", suspect, plan))
            return MB_OK;
    } else {
        candidates(&r, info, e, first_kind, flags, &c);
        if (pick(p, log, &r, info, &c, e, entry, args, suspect, plan))
            return MB_OK;
    }
    // nothing bootable
    plan->base = plan->boot = r;
    plan->base_dirty = plan->boot_dirty = differs(&r, &log->cur);
    plan->choice.want_menu = true;
    return MB_E_CORRUPT;
}

int mb_plan_entry(const mb_port_t *p, const mb_bcl_t *log, const mb_config_t *cfg, mb_slot_info_t info[MB_MAX_SLOTS],
                  int entry, const char *args, mb_plan_t *plan) {
    memset(plan, 0, sizeof(*plan));
    plan->choice.slot = MB_SLOT_NONE;
    plan->choice.entry = -1;
    if (entry < 0 || entry >= cfg->n)
        return MB_E_BADARG;
    mb_bcl_rec_t r = log->cur;
    load_floors(p);
    reconcile(p, &r, info);
    r.request = MB_REQ_NONE;
    const mb_entry_t *e = &cfg->e[entry];
    cands_t c;
    candidates(&r, info, e, MB_KIND_MENU, 0, &c);
    // picked by hand: only the entry's own choices (no silent fallback to something else)
    c.n = e->slot == MB_SLOT_AB ? c.n - 1 : 1;
    if (c.n < 1)
        c.n = 1;
    if (pick(p, log, &r, info, &c, e, entry, args ? args : e->args, MB_SLOT_NONE, plan)) {
        plan->choice.kind = MB_KIND_MENU;
        plan->boot.last_kind = MB_KIND_MENU;
        plan->boot_dirty = differs(&plan->boot, &log->cur);
        return MB_OK;
    }
    plan->base = r;
    plan->base_dirty = differs(&r, &log->cur);
    return MB_E_REFUSED;
}

int mb_plan_slot(const mb_port_t *p, const mb_bcl_t *log, mb_slot_info_t info[MB_MAX_SLOTS], int slot, bool force,
                 const char *args, mb_plan_t *plan) {
    memset(plan, 0, sizeof(*plan));
    plan->choice.slot = MB_SLOT_NONE;
    plan->choice.entry = -1;
    if (slot < 0 || slot >= p->layout->n_slots)
        return MB_E_BADARG;
    mb_bcl_rec_t r = log->cur;
    load_floors(p);
    reconcile(p, &r, info);
    r.request = MB_REQ_NONE;
    bool ok = admit(p, &r, info, slot, MB_ARCH_ANY);
    plan->base = r;
    plan->base_dirty = differs(&r, &log->cur);
    if (!ok) {
        // forced: a header, a startable image, a good signature and hash; its
        // state stays as it is. Never past the rollback floors, though: forcing
        // an old signed image is exactly the attack the floors exist for.
        if (!force || !info[slot].header_ok || !startable(p, &info[slot].hdr))
            return MB_E_REFUSED;
        const mb_image_hdr_t *fh = &info[slot].hdr;
        if (mb_slot_role(p, slot) == MB_ROLE_STAGE1 || (fh->flags & MB_IMG_F_STAGE1))
            return MB_E_REFUSED; // not even forced: stage 1 is started by stage 0 only
        if (MB_FEAT_ANTI_ROLLBACK && mb_slot_role(p, slot) == MB_ROLE_AB && fh->security_version < security_floor(&log->cur))
            return MB_E_REFUSED;
        if (mb_slot_role(p, slot) == MB_ROLE_GOLDEN && golden_too_old(&log->cur, mb_image_id(fh), fh->version))
            return MB_E_REFUSED;
        if (mb_image_check_sig(p, &info[slot]) != MB_OK || mb_image_verify(p, slot, &info[slot]) != MB_OK)
            return MB_E_REFUSED;
        r = log->cur;
        r.last_slot = (uint8_t)slot;
        r.last_kind = MB_KIND_MENU;
        r.last_entry = 0xFF;
        plan->choice.slot = slot;
        plan->choice.kind = MB_KIND_MENU;
    } else {
        book(p, &r, info, slot, MB_KIND_MENU, -1, &plan->choice);
    }
    if (mb_topology_resolve(p, (mb_topology_t){0}, info[slot].hdr.arch, &plan->choice.topology))
        return MB_E_UNSUPP;
    set_args(&plan->choice, args);
    plan->boot = r;
    plan->boot_dirty = differs(&r, &log->cur);
    return MB_OK;
}

// ---------------------------------------------------------------------------
// Handoff and launch
// ---------------------------------------------------------------------------

// What the bootloader was built with, for the OS (mb_handoff_t.features)
uint64_t mb_handoff_features(const mb_port_t *p) {
    return (MB_FEAT_SIGNATURES ? MB_HF_SIGNATURES : 0) | (MB_FEAT_ECDSA ? MB_HF_ECDSA : 0) | (MB_FEAT_LMS ? MB_HF_LMS : 0) |
           (p->require_signature ? MB_HF_REQUIRE_SIGNATURE : 0) | (MB_FEAT_ANTI_ROLLBACK ? MB_HF_ANTI_ROLLBACK : 0) |
           (MB_FEAT_AB_TRIAL ? MB_HF_AB_TRIAL : 0) | (MB_FEAT_TRIAL_WATCHDOG ? MB_HF_TRIAL_WATCHDOG : 0) |
           (MB_FEAT_CRASH_GUARD ? MB_HF_CRASH_GUARD : 0) | (MB_FEAT_CONSOLE ? MB_HF_CONSOLE : 0) |
           (MB_FEAT_SHELL ? MB_HF_SHELL : 0) | (MB_FEAT_RECV ? MB_HF_RECV : 0) | (MB_FEAT_SMP ? MB_HF_SMP : 0) |
           (MB_FEAT_CFG_FILE ? MB_HF_CFG_FILE : 0) | (MB_FEAT_CFG_SIGNED ? MB_HF_CFG_SIGNED : 0) |
           (MB_FEAT_CONSOLE_AUTH ? MB_HF_CONSOLE_AUTH : 0) | (MB_FEAT_ENC ? MB_HF_ENCRYPTED_IMAGES : 0) |
           (MB_FEAT_BOOT_RECORD ? MB_HF_BOOT_RECORD : 0) | (MB_FEAT_TWO_STAGE ? MB_HF_TWO_STAGE : 0) |
           (MB_FEAT_PROTECTED_FLOOR ? MB_HF_PROTECTED_FLOOR : 0) | (MB_FEAT_BOOT_LOCK ? MB_HF_BOOT_LOCK : 0) |
           (MB_FEAT_DEBUG_LOCK ? MB_HF_DEBUG_LOCK : 0) | (MB_FEAT_REVOKE ? MB_HF_REVOKE : 0) |
           (MB_FEAT_RAM_IMAGES ? MB_HF_RAM_IMAGES : 0) | (MB_FEAT_IMG_MCUBOOT ? MB_HF_IMG_MCUBOOT : 0) |
           (MB_FEAT_IMG_RAW ? MB_HF_IMG_RAW : 0) | (MB_FEAT_SCRUB_RAM ? MB_HF_SCRUB_RAM : 0) |
           (MB_FEAT_FAULT_HARDENING ? MB_HF_FAULT_HARDENING : 0) | (MB_FEAT_CONTROL ? MB_HF_CONTROL : 0) |
           (MB_FEAT_OS_HOOKS && p->retains_ram ? MB_HF_MAILBOX : 0) | (MB_CONSOLE_USB ? MB_HF_CONSOLE_USB : 0);
}

static uint32_t boot_caps(const mb_port_t *p) {
    return (mb_control_caps(p) & ~MB_CAP_MAILBOX) | (MB_FEAT_OS_HOOKS && p->retains_ram ? MB_CAP_MAILBOX : 0);
}

// How much of the handoff this build writes: v2 needs OS_HOOKS and an image buffer that big
static uint32_t handoff_size(const mb_image_hdr_t *hdr) {
    return MB_FEAT_OS_HOOKS ? mb_handoff_size(hdr) : MB_HANDOFF_V1_SIZE;
}

// The handoff for the image about to start: v1 (160 bytes), or v2 (320) when the
// build has OS_HOOKS and the image's buffer is that big. h must have room for v2.
void mb_handoff_build(const mb_port_t *p, const mb_bcl_rec_t *log, const mb_config_t *cfg, const mb_image_hdr_t *hdr,
                      const mb_choice_t *c, mb_handoff_t *h) {
    memset(h, 0, sizeof(*h));
    bool v2 = handoff_size(hdr) == MB_HANDOFF_V2_SIZE;
    h->magic = MB_HANDOFF_MAGIC;
    h->version = v2 ? 2 : 1;
    h->size = (uint16_t)handoff_size(hdr);
    h->image_id = mb_image_id(hdr);
    h->boot_count = log->boot_count;
    h->slot = (uint8_t)c->slot;
    h->kind = (uint8_t)c->kind;
    h->entry = (uint8_t)(c->entry < 0 ? 0xFF : c->entry);
    h->arch = hdr->arch;
    h->reset_cause = p->reset_cause ? p->reset_cause() : 0;
    h->loader_version = MIMIBOOT_VERSION_NUM;
    h->reserved =
        MB_HOFF_HAS_CAPS | c->topology.core0 | ((uint32_t)c->topology.core1 << 2) | ((boot_caps(p) & 0xffffu) << 8);
    snprintf(h->slot_name, sizeof(h->slot_name), "%s", c->slot == 0xFF ? "ram" : mb_slot_name(p, c->slot));
    if (cfg && c->entry >= 0 && c->entry < cfg->n)
        snprintf(h->entry_name, sizeof(h->entry_name), "%s", cfg->e[c->entry].name);
    snprintf(h->args, sizeof(h->args), "%s", c->args);
    h->crc = mb_crc32(0, h, offsetof(mb_handoff_t, crc));
#if MB_FEAT_OS_HOOKS
    if (!v2)
        return;
    h->features = mb_handoff_features(p);
    h->caps = boot_caps(p);
    h->boot_ms = p->time_ms ? p->time_ms() : 0;
    h->min_security = security_floor(log);
    h->active = log->active;
    h->strikes = log->strikes;
    if (c->slot < p->layout->n_slots)
        h->tries_left = log->slot[c->slot].tries_left;
    if (c->trial) {
        h->hflags |= MB_HO_TRIAL;
        if (MB_FEAT_TRIAL_WATCHDOG && p->watchdog_arm)
            h->trial_ms = hdr->trial_timeout_ms ? hdr->trial_timeout_ms : MB_DEFAULT_TRIAL_MS;
    }
    h->prev = mb_last_end;
    if (p->random && p->random(h->seed, sizeof(h->seed)) == MB_OK)
        h->hflags |= MB_HO_SEED;
    h->crc2 = mb_crc32(0, h, offsetof(mb_handoff_t, crc2));
#else
    (void)v2;
#endif
}

static void write_handoff(const mb_port_t *p, const mb_bcl_rec_t *log, const mb_config_t *cfg,
                          const mb_image_hdr_t *hdr, const mb_choice_t *c) {
    if (!MB_FEAT_HANDOFF || !hdr->handoff_addr || !p->ram_ptr)
        return;
    uint32_t size = handoff_size(hdr); // never more than the image's buffer holds
    mb_handoff_t *dst = p->ram_ptr(hdr->handoff_addr, size);
    if (!dst)
        return; // not somewhere we may write: the app falls back to flash
    mb_handoff_t h;
    mb_handoff_build(p, log, cfg, hdr, c, &h);
    memcpy(dst, &h, size);
}

// Measured boot: tell the image what was checked and what ran (mimiboot/mb_record.h).
// Called once every check has passed, before the watchdog is armed (hashing the
// loader takes a moment on a slow part).
static void write_record(const mb_port_t *p, const mb_bcl_rec_t *log, const mb_slot_info_t *in, bool trial) {
#if MB_FEAT_BOOT_RECORD
    const mb_image_hdr_t *hdr = &in->hdr;
    if (!hdr->record_addr || !p->ram_ptr)
        return;
    mb_boot_record_t *dst = p->ram_ptr(hdr->record_addr, sizeof(mb_boot_record_t));
    if (!dst)
        return; // not somewhere we may write
    mb_boot_record_t r;
    memset(&r, 0, sizeof(r));
    r.magic = MB_RECORD_MAGIC;
    r.version = MB_RECORD_VERSION;
    r.size = sizeof(r);
    bool signed_ok = in->proof_sig == MB_PROOF_SIG;
    r.flags = (signed_ok ? MB_REC_SIGNED : 0) | (in->proof_hash == MB_PROOF_HASH ? MB_REC_HASHED : 0) |
              (trial ? MB_REC_TRIAL : 0) | (hdr->load_type == MB_LOAD_RAM ? MB_REC_RAM : 0);
    r.key_id = signed_ok ? hdr->key_id : 0;
    r.image_version = hdr->version;
    r.security_version = hdr->security_version;
    r.floor = security_floor(log);
    r.loader_version = MIMIBOOT_VERSION_NUM;
    memcpy(r.image_sha256, hdr->sha256, 32);
    if (p->loader_hash && p->loader_hash(r.loader_sha256) == MB_OK)
        r.flags |= MB_REC_LOADER;
    mb_sha256_t s;
    mb_sha256_init(&s);
    mb_sha256_update(&s, MB_RECORD_DOMAIN, sizeof(MB_RECORD_DOMAIN));
    mb_sha256_update(&s, r.loader_sha256, 32);
    mb_sha256_update(&s, hdr, MB_IMG_SIGNED_BYTES);
    mb_sha256_final(&s, r.measurement);
    r.crc = mb_crc32(0, &r, offsetof(mb_boot_record_t, crc));
    memcpy(dst, &r, sizeof(r));
#else
    (void)p; (void)log; (void)in; (void)trial;
#endif
}

static int hash_ram(const mb_port_t *p, const void *mem, uint32_t len, uint8_t out[32]) {
    if (p->hash_mem && p->hash_mem(mem, len, out) == MB_OK)
        return MB_OK;
    mb_sha256_t s;
    mb_sha256_init(&s);
    mb_sha256_update(&s, mem, len);
    mb_sha256_final(&s, out);
    return MB_OK;
}

// copy a RAM image's payload from its slot and check the copy (that is what runs)
static int stage_ram(const mb_port_t *p, int slot, const mb_image_hdr_t *hdr) {
    if (!MB_FEAT_RAM_IMAGES || !p->ram_ptr || !p->launch_ram)
        return MB_E_UNSUPP;
    uint8_t *dst = p->ram_ptr(hdr->load_addr, hdr->payload_size);
    if (!dst)
        return MB_E_REFUSED;
    if (p->flash_read(p->layout->slot[slot].offset + hdr->payload_offset, dst, hdr->payload_size) != MB_OK)
        return MB_E_IO;
    uint8_t got[32];
    hash_ram(p, dst, hdr->payload_size, got);
    if (mb_ct_diff(got, hdr->sha256, 32) != 0)
        return MB_E_CORRUPT;
    return mb_ct_diff(hdr->sha256, got, 32) == 0 ? MB_OK : MB_E_CORRUPT;
}

// An XIP image for the other architecture: don't do its bookkeeping here.
// Leave a one-shot request for it (entry + args, or the slot) and switch;
// the bootloader half on the other cores consumes the request and does the
// trial accounting itself, so every attempt is counted exactly once.
static int switch_for(const mb_port_t *p, mb_bcl_t *log, const mb_plan_t *plan, const mb_config_t *cfg, uint8_t arch) {
    mb_bcl_rec_t r = plan->base;
    const mb_choice_t *c = &plan->choice;
    if (c->entry >= 0) {
        r.request = MB_REQ_ENTRY_ONCE;
        r.request_arg = (uint8_t)c->entry;
        snprintf(r.args, sizeof(r.args), "%s", c->args);
    } else {
        r.request = MB_REQ_BOOT_ONCE;
        r.request_arg = (uint8_t)c->slot;
    }
    if (p->capabilities)
        mb_control_requeue(&r, cfg, c);
    r.flags |= MB_LF_HANDOVER;
    if (mb_bcl_commit(log, &r) != MB_OK)
        return MB_E_IO;
    p->switch_arch(arch);
    return MB_E_UNSUPP; // still here: the switch didn't happen
}

// The last look before the jump (MB_FEAT_FAULT_HARDENING), from a different
// place in the code than admit(): the checks must have left their proof
// tokens, and the image must still be at or above the rollback floor. A glitch
// that skipped a branch in admit() now has to skip this one too. Each
// condition is tested twice, the second time the other way round.
static bool launch_checks(const mb_port_t *p, const mb_bcl_rec_t *r, const mb_slot_info_t *in, int slot) {
#if MB_FEAT_FAULT_HARDENING
    volatile uint32_t sig = in->proof_sig, hash = in->proof_hash;
    volatile bool ok = true;
    if (sig != MB_PROOF_SIG && sig != MB_PROOF_UNSIGNED)
        ok = false;
    if (p->require_signature && sig != MB_PROOF_SIG)
        ok = false;
    if (MB_BOOT_VERIFY == MB_BOOT_VERIFY_EVERY && hash != MB_PROOF_HASH)
        ok = false;
    if (MB_FEAT_ANTI_ROLLBACK && mb_slot_role(p, slot) == MB_ROLE_AB && in->hdr.security_version < security_floor(r))
        ok = false;
    volatile uint32_t sig_x = in->proof_sig ^ MB_PROOF_SIG, hash_x = in->proof_hash ^ MB_PROOF_HASH;
    if (p->require_signature && sig_x != 0)
        ok = false;
    if (MB_BOOT_VERIFY == MB_BOOT_VERIFY_EVERY && hash_x != 0)
        ok = false;
    return ok;
#else
    (void)p; (void)r; (void)in; (void)slot;
    return true;
#endif
}

int mb_boot(const mb_port_t *p, mb_bcl_t *log, const mb_config_t *cfg, mb_slot_info_t info[MB_MAX_SLOTS],
            const mb_plan_t *plan) {
    int slot = plan->choice.slot;
    if (slot == MB_SLOT_NONE)
        return MB_E_BADARG;
    const mb_image_hdr_t *xh = &info[slot].hdr;
    if ((xh->load_type == MB_LOAD_CHAIN || plan->choice.topology.core0 != plan->choice.topology.core1) &&
        xh->arch != MB_ARCH_ANY && xh->arch != p->arch) {
        if (!p->switch_arch)
            return MB_E_UNSUPP;
        int rc = switch_for(p, log, plan, cfg, xh->arch);
        mb_bcl_rec_t r = log->cur; // clear the request: it can't be honoured
        r.request = MB_REQ_NONE;
        mark_bad(&r, slot, MB_BAD_LAUNCH);
        mb_bcl_commit(log, &r);
        return rc;
    }
    if (p->prepare_topology && plan->choice.topology.core0 == p->arch) {
        int prepared = p->prepare_topology(plan->choice.topology);
        if (prepared)
            return prepared;
    }
    // The log copy of the floors never drops below the protected copy (apps
    // read the floor from the log)
    load_floors(p);
    bool lift = plan->boot.min_security < hw_floor[MB_FLOOR_SECURITY] ||
                plan->boot.golden_version < hw_floor[MB_FLOOR_GOLDEN];
    if (plan->boot_dirty || lift) {
        mb_bcl_rec_t r = plan->boot;
        if (r.min_security < hw_floor[MB_FLOOR_SECURITY])
            r.min_security = hw_floor[MB_FLOOR_SECURITY];
        if (r.golden_version < hw_floor[MB_FLOOR_GOLDEN])
            r.golden_version = hw_floor[MB_FLOOR_GOLDEN];
        if (plan->boot_dirty)
            r.boot_count++;
        int rc = mb_bcl_commit(log, &r);
        // a trial that can't be recorded mustn't run: it could loop forever
        if (rc != MB_OK && plan->choice.trial)
            return MB_E_IO;
    }
    const mb_image_hdr_t *hdr = &info[slot].hdr;
    // Raise the protected floors to a *confirmed* image that is about to run:
    // never higher than a real, signed, accepted image, so an app that writes
    // a silly floor into the log can't brick everything it doesn't like. A
    // failed raise doesn't stop the boot (the log copy still holds).
    const mb_slot_rec_t *bs = &plan->boot.slot[slot];
    if (bs->state == MB_ST_GOOD) {
        int role = mb_slot_role(p, slot);
        if (MB_FEAT_ANTI_ROLLBACK && role == MB_ROLE_AB && hdr->security_version > hw_floor[MB_FLOOR_SECURITY])
            mb_floor_raise(p, MB_FLOOR_SECURITY, hdr->security_version);
        if (role == MB_ROLE_GOLDEN && hdr->version > hw_floor[MB_FLOOR_GOLDEN])
            mb_floor_raise(p, MB_FLOOR_GOLDEN, hdr->version);
    }
    // a signed config in force: an older signed one may not come back
    if (MB_FEAT_CFG_SIGNED && cfg && cfg->from_flash && cfg->version > hw_floor[MB_FLOOR_CONFIG])
        mb_floor_raise(p, MB_FLOOR_CONFIG, cfg->version);
    // two-stage: this stage 1 got as far as starting an image, so it works
    if (p->stage1_slot)
        mb_stage1_confirm(p);
    uint32_t wd = hdr->trial_timeout_ms ? hdr->trial_timeout_ms : MB_DEFAULT_TRIAL_MS;
    int rc;
    bool checked = launch_checks(p, &plan->boot, &info[slot], slot);
    if (checked)
        write_record(p, &plan->boot, &info[slot], plan->choice.trial);
    if (!checked) {
        rc = MB_E_REFUSED;                      // a check that "passed" without its proof: glitch or bug
    } else if (hdr->load_type == MB_LOAD_RAM) {
        rc = stage_ram(p, slot, hdr);
        if (rc == MB_OK) {
            if (MB_FEAT_TRIAL_WATCHDOG && plan->choice.trial && p->watchdog_arm)
                p->watchdog_arm(wd);
            write_handoff(p, &log->cur, cfg, hdr, &plan->choice);
            rc = p->launch_ram(hdr);
        }
    } else {
        if (MB_FEAT_TRIAL_WATCHDOG && plan->choice.trial && p->watchdog_arm)
            p->watchdog_arm(wd);
        write_handoff(p, &log->cur, cfg, hdr, &plan->choice);
        const mb_slot_def_t *reg = &p->layout->slot[slot];
        rc = p->launch(hdr, reg->offset, reg->size);
    }
    // still here: it didn't start
    if (p->watchdog_disarm)
        p->watchdog_disarm();
    mb_bcl_rec_t r = log->cur;
    mark_bad(&r, slot, rc == MB_E_CORRUPT ? MB_BAD_HASH : MB_BAD_LAUNCH);
    mb_bcl_commit(log, &r);
    return rc;
}

int mb_boot_ram(const mb_port_t *p, const mb_bcl_t *log, const mb_config_t *cfg, const mb_image_hdr_t *hdr,
                const char *args) {
    if (!MB_FEAT_RAM_IMAGES || !p->ram_ptr || !p->launch_ram || hdr->load_type != MB_LOAD_RAM)
        return MB_E_UNSUPP;
    if (!startable(p, hdr) || (hdr->flags & MB_IMG_F_STAGE1))
        return MB_E_UNSUPP;
    // With signatures required, a RAM image is held to the same floor, or an
    // old signed image with a known hole could be run this way. (With them
    // optional anyone may upload an unsigned image, so a floor would only get
    // in the way of lab tools.)
    load_floors(p);
    if (MB_FEAT_ANTI_ROLLBACK && p->require_signature && hdr->security_version < security_floor(&log->cur))
        return MB_E_REFUSED;
    mb_slot_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.hdr = *hdr;
    tmp.header_ok = true;
    if (MB_FEAT_LMS && (hdr->flags & MB_IMG_F_LMS)) { // a RAM image's LMS signature: the one its upload brought
#if MB_FEAT_LMS
        tmp.sig_ram = mb_upload_sig.buf;
        tmp.sig_ram_len = mb_upload_sig.len;
#endif
    }
    if (mb_image_check_sig(p, &tmp) != MB_OK)
        return MB_E_SIGNATURE;
    const uint8_t *mem = p->ram_ptr(hdr->load_addr, hdr->payload_size);
    if (!mem)
        return MB_E_REFUSED;
    uint8_t got[32];
    hash_ram(p, mem, hdr->payload_size, got);
    if (mb_ct_diff(got, hdr->sha256, 32) != 0)
        return MB_E_CORRUPT;
    if (mb_ct_diff(hdr->sha256, got, 32) == 0)
        tmp.proof_hash = MB_PROOF_HASH;
    if (!launch_checks(p, &log->cur, &tmp, -1))
        return MB_E_REFUSED;
    mb_choice_t c;
    memset(&c, 0, sizeof(c));
    c.slot = 0xFF;
    c.kind = MB_KIND_MENU;
    c.entry = -1;
    int topo = mb_topology_resolve(p, (mb_topology_t){0}, hdr->arch, &c.topology);
    if (topo)
        return topo;
    /* A console RAM upload cannot survive a loader reboot. */
    if (p->prepare_topology && c.topology.core0 == p->arch) {
        topo = p->prepare_topology(c.topology);
        if (topo)
            return topo;
    }
    set_args(&c, args);
    if (p->stage1_slot)
        mb_stage1_confirm(p);
    write_record(p, &log->cur, &tmp, false);
    write_handoff(p, &log->cur, cfg, hdr, &c);
    return p->launch_ram(hdr);
}

__attribute__((weak)) void mb_boot_progress(unsigned stage) {(void)stage;}
void mb_main(const mb_port_t *p) {
    mb_boot_progress(1);
    // the key is read once per power-up: if nobody opens the console, the
    // normal boot goes ahead even while the key is still held
    unsigned flags = p->button && p->button() ? MB_F_MENU : 0;
    // The CPU faulted while checking a slot last time (an ECC error or bus
    // fault on damaged flash): that image is bad, so the next pass falls back
    int faulted = p->fault_slot ? p->fault_slot() : -1;
    bool mailbox_read = false;      // the mailbox: read once per power-up, before the first decision
    for (;;) {
        static mb_bcl_t log;
        static mb_config_t cfg;
        static mb_slot_info_t info[MB_MAX_SLOTS];
        static mb_plan_t plan;
        mb_boot_progress(2);
        mb_bcl_load(&log, p);
        if (faulted >= 0 && faulted < p->layout->n_slots) {
            mb_bcl_rec_t r = log.cur;
            // the check never finished, so the log may not know this image yet:
            // name it, or the next reconcile would treat it as a new one
            if (mb_image_read_header(p, faulted, &info[faulted]) == MB_OK)
                r.slot[faulted].image_id = mb_image_id(&info[faulted].hdr);
            mark_bad(&r, faulted, MB_BAD_FAULT);
            mb_bcl_commit(&log, &r);
            faulted = -1;
        }
        if (!mailbox_read) { // once per power-up: why the last run ended, and what it asked for
            mb_mailbox_take(p, &log.cur);
            mailbox_read = true;
        }
#ifdef MB_BOOT_DIAGNOSTICS
        if(log.cur.request==MB_REQ_NONE)flags|=MB_F_MENU;
        else if(log.cur.request==MB_REQ_BOOT_ONCE||log.cur.request==MB_REQ_ENTRY_ONCE||log.cur.request==MB_REQ_CONTROL)flags&=~MB_F_MENU;
#endif
        mb_boot_progress(3);
        mb_config_load(p, &cfg);
        mb_boot_progress(4);
        mb_decide(p, &log, &cfg, info, flags, &plan);
        flags &= ~MB_F_MENU;
        flags |= MB_F_AGAIN;        // a later decision this power-up (after the menu) counts no crash again
        if (plan.choice.want_rom && p->reboot_rom) {
            if (plan.base_dirty)
                mb_bcl_commit(&log, &plan.base);
            p->reboot_rom();
        }
        if (plan.choice.want_menu || plan.choice.slot == MB_SLOT_NONE) {
            if (plan.base_dirty)
                mb_bcl_commit(&log, &plan.base);
            mb_boot_progress(5);
            mb_menu(p, &log, &cfg, info, &plan); // returns when it wants a fresh decision
                                                 // (text console by default; the watch UI overrides it)
            continue;
        }
        mb_boot_progress(6);
        int rc = mb_boot(p, &log, &cfg, info, &plan); // returns only on failure
        // the log can't record a trial attempt: boot only what needs no write
        if (rc == MB_E_UNSUPP || rc == MB_E_BADARG || rc == MB_E_TIMEOUT)
            flags |= MB_F_MENU;
        if (rc == MB_E_IO && plan.choice.trial)
            flags |= MB_F_NO_TRIAL;
    }
}
