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
        if (mb_slot_role(p, i) == MB_ROLE_GOLDEN && r->golden_id && id != r->golden_id &&
            info[i].hdr.version <= r->golden_version) {
            mark_bad(r, i, MB_BAD_GOLDEN_OLD); // monotonic golden: only a strictly newer one may replace it
            continue;
        }
        s->state = MB_ST_NEW;
        s->tries_left = MB_DEFAULT_TRIES;
    }
}

// Can `slot` be booted? Marks it bad in r if it never can.
static bool admit(const mb_port_t *p, mb_bcl_rec_t *r, mb_slot_info_t info[MB_MAX_SLOTS], int slot, uint8_t want_arch) {
    if (slot < 0 || slot >= p->layout->n_slots)
        return false;
    mb_slot_rec_t *s = &r->slot[slot];
    if (s->state == MB_ST_EMPTY || s->state == MB_ST_BAD)
        return false;
    if (s->state == MB_ST_TRIAL && s->tries_left == 0) {
        mark_bad(r, slot, MB_BAD_TRIALS);
        return false;
    }
    if (want_arch != MB_ARCH_ANY && info[slot].hdr.arch != want_arch)
        return false; // config mismatch, not the image's fault
#if MB_FEAT_ANTI_ROLLBACK
    if (mb_slot_role(p, slot) == MB_ROLE_AB && info[slot].hdr.security_version < r->min_security) {
        mark_bad(r, slot, MB_BAD_ROLLBACK);
        return false;
    }
#endif
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
    reconcile(p, &r, info);

    // crash-loop guard (an architecture handover reboot is not a crash: the
    // reset hardware may report it as one, so it is flagged in the log)
    int suspect = MB_SLOT_NONE;
    if (r.flags & MB_LF_HANDOVER) {
        r.flags &= (uint8_t)~MB_LF_HANDOVER;
    }
#if MB_FEAT_CRASH_GUARD
    else {
        uint32_t cause = p->reset_cause ? p->reset_cause() : 0;
        if ((cause & MB_RESET_WATCHDOG) && r.last_slot < p->layout->n_slots &&
            r.slot[r.last_slot].state == MB_ST_GOOD) {
            if (r.strikes < 0xFF)
                r.strikes++;
            if (r.strikes >= MB_STRIKES_MAX)
                suspect = r.last_slot;
        } else if (!(cause & MB_RESET_WATCHDOG) && r.strikes) {
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
    int control = mb_control_consume(p, &r, cfg, &plan->choice.topology, &action);
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
    reconcile(p, &r, info);
    r.request = MB_REQ_NONE;
    bool ok = admit(p, &r, info, slot, MB_ARCH_ANY);
    plan->base = r;
    plan->base_dirty = differs(&r, &log->cur);
    if (!ok) {
        // forced: a header, a startable image, a good signature and hash; its state stays as it is
        if (!force || !info[slot].header_ok || !startable(p, &info[slot].hdr))
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

void mb_handoff_build(const mb_port_t *p, const mb_bcl_rec_t *log, const mb_config_t *cfg, const mb_image_hdr_t *hdr,
                      const mb_choice_t *c, mb_handoff_t *h) {
    memset(h, 0, sizeof(*h));
    h->magic = MB_HANDOFF_MAGIC;
    h->version = MB_HANDOFF_VERSION;
    h->size = sizeof(*h);
    h->image_id = mb_image_id(hdr);
    h->boot_count = log->boot_count;
    h->slot = (uint8_t)c->slot;
    h->kind = (uint8_t)c->kind;
    h->entry = (uint8_t)(c->entry < 0 ? 0xFF : c->entry);
    h->arch = hdr->arch;
    h->reset_cause = p->reset_cause ? p->reset_cause() : 0;
    h->loader_version = MIMIBOOT_VERSION_NUM;
    h->reserved =
        MB_HOFF_NIGHT | c->topology.core0 | ((uint32_t)c->topology.core1 << 2) | ((mb_control_caps(p) & 0xffffu) << 8);
    snprintf(h->slot_name, sizeof(h->slot_name), "%s", c->slot == 0xFF ? "ram" : mb_slot_name(p, c->slot));
    if (cfg && c->entry >= 0 && c->entry < cfg->n)
        snprintf(h->entry_name, sizeof(h->entry_name), "%s", cfg->e[c->entry].name);
    snprintf(h->args, sizeof(h->args), "%s", c->args);
    h->crc = mb_crc32(0, h, offsetof(mb_handoff_t, crc));
}

static void write_handoff(const mb_port_t *p, const mb_bcl_rec_t *log, const mb_config_t *cfg,
                          const mb_image_hdr_t *hdr, const mb_choice_t *c) {
    if (!MB_FEAT_HANDOFF || !hdr->handoff_addr || !p->ram_ptr)
        return;
    mb_handoff_t *dst = p->ram_ptr(hdr->handoff_addr, sizeof(mb_handoff_t));
    if (!dst)
        return; // not somewhere we may write: the app falls back to flash
    mb_handoff_t h;
    mb_handoff_build(p, log, cfg, hdr, c, &h);
    memcpy(dst, &h, sizeof(h));
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
    return memcmp(got, hdr->sha256, 32) ? MB_E_CORRUPT : MB_OK;
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
    if (plan->boot_dirty) {
        mb_bcl_rec_t r = plan->boot;
        r.boot_count++;
        int rc = mb_bcl_commit(log, &r);
        // a trial that can't be recorded mustn't run: it could loop forever
        if (rc != MB_OK && plan->choice.trial)
            return MB_E_IO;
    }
    const mb_image_hdr_t *hdr = &info[slot].hdr;
    uint32_t wd = hdr->trial_timeout_ms ? hdr->trial_timeout_ms : MB_DEFAULT_TRIAL_MS;
    int rc;
    if (hdr->load_type == MB_LOAD_RAM) {
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
    if (!startable(p, hdr))
        return MB_E_UNSUPP;
    mb_slot_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.hdr = *hdr;
    tmp.header_ok = true;
    if (mb_image_check_sig(p, &tmp) != MB_OK)
        return MB_E_SIGNATURE;
    const uint8_t *mem = p->ram_ptr(hdr->load_addr, hdr->payload_size);
    if (!mem)
        return MB_E_REFUSED;
    uint8_t got[32];
    hash_ram(p, mem, hdr->payload_size, got);
    if (memcmp(got, hdr->sha256, 32))
        return MB_E_CORRUPT;
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
    write_handoff(p, &log->cur, cfg, hdr, &c);
    return p->launch_ram(hdr);
}

__attribute__((weak)) void mb_boot_progress(unsigned stage) {(void)stage;}
void mb_main(const mb_port_t *p) {
    mb_boot_progress(1);
    // the key is read once per power-up: if nobody opens the console, the
    // normal boot goes ahead even while the key is still held
    unsigned flags = p->button && p->button() ? MB_F_MENU : 0;
    for (;;) {
        static mb_bcl_t log;
        static mb_config_t cfg;
        static mb_slot_info_t info[MB_MAX_SLOTS];
        static mb_plan_t plan;
        mb_boot_progress(2);
        mb_bcl_load(&log, p);
#ifdef MB_BOOT_DIAGNOSTICS
        if(log.cur.request==MB_REQ_NONE)flags|=MB_F_MENU;
        else if(log.cur.request==MB_REQ_BOOT_ONCE||log.cur.request==MB_REQ_ENTRY_ONCE||log.cur.request==MB_REQ_NIGHT)flags&=~MB_F_MENU;
#endif
        mb_boot_progress(3);
        mb_config_load(p, &cfg);
        mb_boot_progress(4);
        mb_decide(p, &log, &cfg, info, flags, &plan);
        flags &= ~MB_F_MENU;
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
