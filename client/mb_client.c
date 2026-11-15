/*
 * MimiBoot client library (see mb_client.h)
 */
#include "client/mb_client.h"
#include <stdio.h>
#include <string.h>

static const mb_port_t *port;
static int self = MB_SLOT_NONE;
static struct {
    int slot;
    mb_image_hdr_t hdr;
    bool open;
    uint32_t next;              /* payload bytes taken so far */
    uint32_t page_at;           /* payload offset of the page being gathered */
    uint8_t page[256];          /* written whole, once (write-once flash units) */
} inst;
static mb_handoff_t ho; // our copy of this boot's handoff (v1: the v2 part zeroed)
static bool ho_valid;
static volatile mb_handoff_t *ho_buf; // the image's own buffer: the mailbox goes there
static mb_mailbox_t mbox;             // what this run leaves for the next boot (written at the reset)
static char args_buf[MB_ARGS_MAX];

int mb_client_init(const mb_port_t *p) {
    if (!p)
        return MB_E_BADARG;
    port = p;
    ho_valid = false;
    ho_buf = NULL;
    memset(&mbox, 0, sizeof(mbox));
    inst.open = false;
    self = p->self_slot ? p->self_slot() : MB_SLOT_NONE;
    return MB_OK;
}

int mb_client_other_slot(void) { return self == MB_SLOT_A ? MB_SLOT_B : MB_SLOT_A; }

// Take the handoff only if it was written for *this* image this boot, then
// clear it so nothing later mistakes it for a fresh one.
// A v1 block (160 bytes, an older MimiBoot) is taken as well: its v2 part reads as zeros.
void mb_client_set_handoff(volatile mb_handoff_t *h) {
    ho_valid = false;
    ho_buf = h;
    if (!h || !port)
        return;
    mb_handoff_t copy;
    memcpy(&copy, (const void *)h, sizeof(copy));
    h->magic = 0;
    if (copy.magic != MB_HANDOFF_MAGIC || mb_crc32(0, &copy, offsetof(mb_handoff_t, crc)) != copy.crc)
        return;
    if (copy.version == 1 && copy.size == MB_HANDOFF_V1_SIZE)
        memset((uint8_t *)&copy + MB_HANDOFF_V1_SIZE, 0, sizeof(copy) - MB_HANDOFF_V1_SIZE);
    else if (copy.version < 2 || copy.size != MB_HANDOFF_V2_SIZE ||
             mb_crc32(0, &copy, offsetof(mb_handoff_t, crc2)) != copy.crc2)
        return; // (a later version starts with a v2 block: its size says so)
    mb_slot_info_t info;
    if (self == MB_SLOT_NONE && copy.slot != 0xFF) {
        /* RAM images have no physical XIP mapping. Bind identity to both this
         * boot record and the signed image header before adopting its slot. */
        mb_bcl_t b;
        if (copy.slot >= port->layout->n_slots || mb_bcl_load(&b, port) != MB_OK || b.cur.last_slot != copy.slot ||
            b.cur.boot_count != copy.boot_count || mb_image_read_header(port, copy.slot, &info) != MB_OK ||
            info.hdr.load_type != MB_LOAD_RAM || mb_image_id(&info.hdr) != copy.image_id ||
            mb_image_check_sig(port, &info) != MB_OK)
            return;
        self = copy.slot;
    }
    if (self != MB_SLOT_NONE) {
        if (mb_image_read_header(port, self, &info) != MB_OK || mb_image_id(&info.hdr) != copy.image_id)
            return;
    }
    copy.args[sizeof(copy.args) - 1] = 0;
    copy.prev.msg[sizeof(copy.prev.msg) - 1] = 0;
    ho = copy;
    ho_valid = true;
}

const mb_handoff_t *mb_client_handoff(void) { return ho_valid ? &ho : NULL; }

const char *mb_client_args(void) {
    if (ho_valid)
        return ho.args;
    // fallback: the config entry the log says we were booted as
    args_buf[0] = 0;
    if (!port)
        return args_buf;
    mb_bcl_t log;
    mb_config_t cfg;
    if (mb_bcl_load(&log, port) != MB_OK || mb_config_load(port, &cfg) != MB_OK)
        return args_buf;
    int e = log.cur.last_entry;
    if (log.cur.last_slot == self && e < cfg.n)
        snprintf(args_buf, sizeof(args_buf), "%s", cfg.e[e].args);
    return args_buf;
}

int mb_client_status(mb_client_status_t *st) {
    memset(st, 0, sizeof(*st));
    st->slot = self;
    st->handoff = ho_valid;
    mb_bcl_t log;
    if (!port || mb_bcl_load(&log, port) != MB_OK)
        return MB_E_IO;
    st->active = log.cur.active;
    uint32_t hw[MB_FLOOR_COUNT];
    mb_floor_get(port, hw); // the bootloader's protected copy, when the port has one
    st->min_security = log.cur.min_security > hw[MB_FLOOR_SECURITY] ? log.cur.min_security : hw[MB_FLOOR_SECURITY];
    st->last_kind = log.cur.last_kind;
    st->strikes = log.cur.last_slot == self ? log.cur.strikes : 0;
    if (ho_valid)
        snprintf(st->entry, sizeof(st->entry), "%s", ho.entry_name);
    if (self == MB_SLOT_NONE)
        return MB_OK;
    mb_slot_info_t info;
    if (mb_image_read_header(port, self, &info) == MB_OK) {
        st->version = info.hdr.version;
        st->security_version = info.hdr.security_version;
        memcpy(st->name, info.hdr.name, sizeof(st->name));
        st->name[sizeof(st->name) - 1] = 0;
    }
    st->state = log.cur.slot[self].state;
    st->tries_left = log.cur.slot[self].tries_left;
    return MB_OK;
}

int mb_client_confirm(void) {
    if (!port || self == MB_SLOT_NONE)
        return MB_E_BADARG;
    mb_slot_info_t info;
    if (mb_image_read_header(port, self, &info) != MB_OK)
        return MB_E_CORRUPT;
    mb_bcl_t log;
    if (mb_bcl_load(&log, port) != MB_OK)
        return MB_E_IO;
    mb_bcl_rec_t r = log.cur;
    mb_slot_rec_t *s = &r.slot[self];
    bool ab = mb_slot_role(port, self) == MB_ROLE_AB;
    uint64_t id = mb_image_id(&info.hdr);
    bool already = s->state == MB_ST_GOOD && s->image_id == id &&
                   (!ab || (r.active == self && r.min_security >= info.hdr.security_version)) &&
                   !(r.last_slot == self && r.strikes);
    if (already)
        return MB_OK; // no flash write on every boot
    s->image_id = id;
    s->state = MB_ST_GOOD;
    s->bad_reason = MB_BAD_NONE;
    s->tries_left = 0;
    if (ab) {
        r.active = (uint8_t)self;
        // anti-rollback: once an image is confirmed, nothing older may run
        if (info.hdr.security_version > r.min_security)
            r.min_security = info.hdr.security_version;
    }
    if (r.last_slot == self)
        r.strikes = 0; // it's healthy: forget the watchdog resets
    return mb_bcl_commit(&log, &r);
}

int mb_client_reject(int slot) {
    if (!port || slot < 0 || slot >= port->layout->n_slots || slot == self)
        return MB_E_BADARG;
    mb_bcl_t log;
    if (mb_bcl_load(&log, port) != MB_OK)
        return MB_E_IO;
    mb_bcl_rec_t r = log.cur;
    r.slot[slot].state = MB_ST_BAD;
    r.slot[slot].bad_reason = MB_BAD_REJECTED;
    r.slot[slot].tries_left = 0;
    return mb_bcl_commit(&log, &r);
}

// Empty a slot for good: its header goes (so nothing reads an image there) and
// so does its log record. Not the running image, not golden, not a stage-1
// copy, and not the confirmed image the board falls back to.
int mb_client_vacate(int slot) {
    if (!port || slot < 0 || slot >= port->layout->n_slots || slot == self)
        return MB_E_BADARG;
    int role = mb_slot_role(port, slot);
    if (role == MB_ROLE_GOLDEN || role == MB_ROLE_STAGE1)
        return MB_E_REFUSED;
    mb_bcl_t log;
    if (mb_bcl_load(&log, port) != MB_OK)
        return MB_E_IO;
    if (slot == log.cur.active && log.cur.slot[slot].state == MB_ST_GOOD)
        return MB_E_REFUSED;
    int rc = mb_slot_erase(port, slot, 0);              // the header sector (and an MCUboot trailer)
    if (rc != MB_OK)
        return rc;
    if (inst.open && inst.slot == slot)
        inst.open = false;
    mb_bcl_rec_t r = log.cur;
    memset(&r.slot[slot], 0, sizeof(r.slot[slot]));
    return mb_bcl_commit(&log, &r);
}

int mb_client_request(int request, int arg) {
    if (!port)
        return MB_E_BADARG;
    mb_bcl_t log;
    if (mb_bcl_load(&log, port) != MB_OK)
        return MB_E_IO;
    mb_bcl_rec_t r = log.cur;
    r.request = (uint8_t)request;
    r.request_arg = (uint8_t)arg;
    memset(r.args, 0, sizeof(r.args));
    return mb_bcl_commit(&log, &r);
}

int mb_client_request_entry(const char *entry, const char *args) {
    if (!port)
        return MB_E_BADARG;
    mb_config_t cfg;
    mb_config_load(port, &cfg);
    int e = mb_config_find(&cfg, entry);
    if (e < 0)
        return MB_E_BADARG;
    mb_bcl_t log;
    if (mb_bcl_load(&log, port) != MB_OK)
        return MB_E_IO;
    mb_bcl_rec_t r = log.cur;
    r.request = MB_REQ_ENTRY_ONCE;
    r.request_arg = (uint8_t)e;
    memset(r.args, 0, sizeof(r.args));
    if (args)
        snprintf(r.args, sizeof(r.args), "%s", args);
    return mb_bcl_commit(&log, &r);
}

int mb_client_install_begin(int slot, const mb_image_hdr_t *hdr) {
    if (!port || slot < 0 || slot >= port->layout->n_slots)
        return MB_E_BADARG;
    if (slot == self || mb_slot_role(port, slot) == MB_ROLE_GOLDEN)
        return MB_E_REFUSED; // never the running image or recovery
    if (port->layout->page_size > sizeof(inst.page))
        return MB_E_UNSUPP;
    if (mb_image_check_header(port, hdr, port->layout->slot[slot].size) != MB_OK)
        return MB_E_CORRUPT;
    if (mb_stage1_accepts(port, slot, hdr) != MB_OK)
        return MB_E_REFUSED; // a bootloader stage 1 in an app slot, or anything in a stage-1 slot
    if (hdr->flags & MB_IMG_F_ENCRYPTED)
        return MB_E_UNSUPP; // only MimiBoot holds the key: send encrypted images to its console / SMP
    mb_slot_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.hdr = *hdr;
    tmp.header_ok = true;
    bool lms = (hdr->flags & MB_IMG_F_LMS) != 0;
    if (lms) { // the signature handed over with mb_client_install_sig()
#if MB_FEAT_LMS
        tmp.sig_ram = mb_upload_sig.buf;
        tmp.sig_ram_len = mb_upload_sig.len;
#endif
    }
    if (mb_image_check_sig(port, &tmp) != MB_OK)
        return MB_E_SIGNATURE; // it could never boot: don't wipe the slot for it
    int rc = mb_slot_erase(port, slot, hdr->payload_size);
    if (rc == MB_OK && lms)
        rc = mb_slot_write_lms(port, slot, mb_upload_sig.buf, mb_upload_sig.len);
    if (rc != MB_OK)
        return rc;
    inst.slot = slot;
    inst.hdr = *hdr;
    inst.open = true;
    inst.next = inst.page_at = 0;
    memset(inst.page, 0xFF, sizeof(inst.page));
    return MB_OK;
}

static int flush_page(void) {
    int rc = mb_slot_write(port, inst.slot, inst.page_at, inst.page, port->layout->page_size);
    inst.page_at += port->layout->page_size;
    memset(inst.page, 0xFF, sizeof(inst.page));
    return rc;
}

int mb_client_install_write(uint32_t offset, const void *data, size_t len) {
    if (!inst.open)
        return MB_E_BADARG;
    if (offset > inst.hdr.payload_size || len > inst.hdr.payload_size - offset)
        return MB_E_NOSPACE;
    if (offset + len <= inst.next)
        return MB_OK; // sent again (a retry): already taken
    if (offset != inst.next)
        return MB_E_BADARG; // in order only
    const uint8_t *d = data;
    uint32_t page = port->layout->page_size;
    while (len) {
        uint32_t at = inst.next - inst.page_at;
        uint32_t n = page - at < len ? page - at : (uint32_t)len;
        memcpy(inst.page + at, d, n);
        inst.next += n;
        d += n;
        len -= n;
        if (inst.next - inst.page_at == page) {
            int rc = flush_page();
            if (rc != MB_OK) {
                inst.open = false;
                return rc;
            }
        }
    }
    return MB_OK;
}

int mb_client_install_end(void) {
    if (!inst.open)
        return MB_E_BADARG;
    inst.open = false;
    if (inst.next != inst.hdr.payload_size)
        return MB_E_CORRUPT; // not all of it arrived: the slot stays empty
    if (inst.next > inst.page_at && flush_page() != MB_OK)
        return MB_E_IO;
    mb_slot_info_t info;
    memset(&info, 0, sizeof(info));
    info.hdr = inst.hdr;
    info.header_ok = true;
    if (mb_image_verify(port, inst.slot, &info) != MB_OK)
        return MB_E_CORRUPT; // slot stays empty
    if (inst.hdr.flags & MB_IMG_F_LMS) { // what boots is the copy in flash: check that one
#if MB_FEAT_LMS
        info.tlv_flash = port->layout->slot[inst.slot].offset + MB_IMG_HDR_SIZE;
#endif
        if (mb_image_check_sig(port, &info) != MB_OK)
            return MB_E_SIGNATURE;
    }
    return mb_slot_write_header(port, inst.slot, &inst.hdr);
}

int mb_client_install_sig(const void *sig, size_t len) {
    if (!MB_FEAT_LMS)
        return MB_E_UNSUPP;
    if (len > sizeof(mb_upload_sig.buf))
        return MB_E_NOSPACE;
    memcpy(mb_upload_sig.buf, sig, len);
    mb_upload_sig.len = (uint16_t)len;
    return MB_OK;
}

int mb_client_install_abort(void) {
    inst.open = false; // the header was erased at begin: the slot already reads as empty
    return MB_OK;
}

// ---------------------------------------------------------------------------
// OTA over a byte stream
// ---------------------------------------------------------------------------

typedef struct {
    void *io;
    int (*getc)(void *io, uint32_t ms);
    void (*puts)(void *io, const char *s);
    int slot;
} ota_t;

static int ota_getc(void *ctx, uint32_t ms) {
    ota_t *o = ctx;
    return o->getc(o->io, ms);
}
static void ota_puts(void *ctx, const char *s) {
    ota_t *o = ctx;
    o->puts(o->io, s);
}
static int ota_begin(void *ctx, const mb_image_hdr_t *hdr) {
    return mb_client_install_begin(((ota_t *)ctx)->slot, hdr);
}
static int ota_data(void *ctx, uint32_t off, const void *d, size_t n) {
    (void)ctx;
    return mb_client_install_write(off, d, n);
}
static int ota_end(void *ctx) {
    (void)ctx;
    return mb_client_install_end();
}

int mb_client_recv(int slot, void *io, int (*getc)(void *io, uint32_t ms), void (*puts)(void *io, const char *s),
                   uint16_t max_frame) {
    ota_t o = {io, getc, puts, slot};
    mb_recv_t r = {.ctx = &o,
                   .getc = ota_getc,
                   .puts = ota_puts,
                   .max_frame = max_frame,
                   .where = port ? mb_slot_name(port, slot) : "?",
                   .begin = ota_begin,
                   .data = ota_data,
                   .end = ota_end};
    int rc = mb_recv(&r, NULL);
    if (rc != MB_OK)
        inst.open = false;
    return rc;
}

uint32_t mb_client_capabilities(void) {
    if (!ho_valid)
        return 0;
    if (ho.version >= 2)
        return ho.caps;
    return (ho.reserved & MB_HOFF_HAS_CAPS) && ho.loader_version >= MB_VERSION(2, 0, 0) ? (ho.reserved >> 8) & 0xffffu
                                                                                        : 0;
}

// ---------------------------------------------------------------------------
// OS hooks: the next boot, reboots with a reason, panics, power-off
// ---------------------------------------------------------------------------

// The RAM mailbox is there when this boot's handoff was v2 and the bootloader reads it
static bool mailbox_ok(void) { return ho_valid && ho_buf && ho.version >= 2 && (ho.caps & MB_CAP_MAILBOX); }

int mb_client_transport(void) {
    return mailbox_ok() && (ho.caps & MB_CAP_CONTROL) ? MB_VIA_MAILBOX
           : mb_client_capabilities() & MB_CAP_CONTROL ? MB_VIA_FLASH
                                                         : MB_VIA_LEGACY;
}

// The old one-shot requests in the log (any MimiBoot): what they can say
static int legacy(const mb_control_request_t *q) {
    switch (q->action) {
    case MB_CONTROL_MENU:
        return mb_client_request(MB_REQ_MENU, 0);
    case MB_CONTROL_FLASH:
        return mb_client_request(MB_REQ_FLASH, 0);
    case MB_CONTROL_ROM:
        return mb_client_request(MB_REQ_BOOTSEL, 0);
    case MB_CONTROL_SLOT:
        return q->args[0] ? MB_E_UNSUPP : mb_client_request(MB_REQ_BOOT_ONCE, q->slot);
    case MB_CONTROL_ENTRY:
        return mb_client_request_entry(q->entry, q->args);
    case MB_CONTROL_RESTART:
        return MB_OK;
    default:
        return MB_E_UNSUPP; // config mode, topologies: the control service only
    }
}

int mb_client_next_boot(const mb_control_request_t *q, int how) {
    if (!port || !q || q->version != MB_CONTROL_API_VERSION || q->size != sizeof(*q))
        return MB_E_BADARG;
    int via = how == MB_VIA_FLASH && mb_client_transport() == MB_VIA_MAILBOX ? MB_VIA_FLASH : mb_client_transport();
    if (via == MB_VIA_MAILBOX) {
        // the bootloader checks it again before it acts on it; this catches mistakes early
        if (q->action > MB_CONTROL_SLOT || !memchr(q->entry, 0, sizeof(q->entry)) || !memchr(q->args, 0, sizeof(q->args)))
            return MB_E_BADARG;
        mbox.next = *q; // goes into RAM with the reset (mb_client_reboot)
        return MB_VIA_MAILBOX;
    }
    memset(&mbox.next, 0, sizeof(mbox.next)); // the log has it now: not twice
    int rc = via == MB_VIA_FLASH ? mb_control_submit(port, q) : legacy(q);
    return rc < 0 ? rc : via;
}

static mb_control_request_t request(unsigned action, const char *target, const char *args, int *err) {
    mb_control_request_t q;
    memset(&q, 0, sizeof(q));
    q.version = MB_CONTROL_API_VERSION;
    q.size = sizeof(q);
    q.action = action;
    *err = MB_OK;
    if (args && strlen(args) >= sizeof(q.args))
        *err = MB_E_BADARG;
    else if (args)
        memcpy(q.args, args, strlen(args) + 1);
    if (action == MB_CONTROL_ENTRY) {
        if (!target || !*target || strlen(target) >= sizeof(q.entry))
            *err = MB_E_BADARG;
        else
            memcpy(q.entry, target, strlen(target) + 1);
    } else if (action == MB_CONTROL_SLOT) {
        int s = target ? mb_slot_parse(port, target) : -1;
        if (s < 0)
            *err = MB_E_BADARG;
        q.slot = (uint8_t)(s < 0 ? 0 : s);
    }
    return q;
}

int mb_client_next(unsigned action, const char *target, const char *args, int how) {
    if (!port)
        return MB_E_BADARG;
    int err;
    mb_control_request_t q = request(action, target, args, &err);
    return err ? err : mb_client_next_boot(&q, how);
}

// Fill in the note for the next boot and put the mailbox into RAM (right before the
// reset, so a note never sits there while the system keeps running)
static bool post(int reason, const char *msg, uint32_t pc, uint32_t lr, uint32_t info) {
    if (!mailbox_ok())
        return false;
    mbox.magic = MB_MAILBOX_MAGIC;
    mbox.version = MB_MAILBOX_VERSION;
    mbox.size = sizeof(mbox);
    mbox.image_id = ho.image_id;
    memset(&mbox.end, 0, sizeof(mbox.end));
    mbox.end.reason = (uint8_t)reason;
    mbox.end.pc = pc;
    mbox.end.lr = lr;
    mbox.end.info = info;
    if (msg) {
        size_t n = strlen(msg);
        memcpy(mbox.end.msg, msg, n < sizeof(mbox.end.msg) - 1 ? n : sizeof(mbox.end.msg) - 1);
    }
    mbox.crc = mb_crc32(0, &mbox, offsetof(mb_mailbox_t, crc));
    volatile uint8_t *dst = (volatile uint8_t *)ho_buf;
    const uint8_t *src = (const uint8_t *)&mbox;
    for (size_t i = 0; i < sizeof(mbox); i++) // (volatile: the compiler may not drop a store before a reset)
        dst[i] = src[i];
    return true;
}

int mb_client_reboot(int reason, const char *msg) {
    if (!port || !port->reboot)
        return MB_E_UNSUPP;
    post(reason, msg, 0, 0, 0);
    port->reboot();
    return MB_E_UNSUPP; // still here: the port couldn't reset
}

// A crash has to reach the crash-loop guard: with the mailbox the note says so; without
// one, a watchdog reset does (never a flash write from here: this runs from fault handlers).
__attribute__((noreturn)) static void crash(int reason, const char *msg, uint32_t pc, uint32_t lr, uint32_t info) {
    if (port && !post(reason, msg, pc, lr, info) && port->watchdog_arm) {
        port->watchdog_arm(1);
        for (;;) {
        }
    }
    if (port && port->reboot)
        port->reboot();
    for (;;) {
    }
}

void mb_client_panic(const char *msg) {
    crash(MB_END_PANIC, msg, (uint32_t)(uintptr_t)__builtin_return_address(0), 0, 0);
}

void mb_client_fault(uint32_t pc, uint32_t lr, uint32_t info) { crash(MB_END_FAULT, "fault", pc, lr, info); }

int mb_client_poweroff(const char *msg) {
    if (!port || !port->poweroff)
        return MB_E_UNSUPP;
    post(MB_END_POWEROFF, msg, 0, 0, 0);
    port->poweroff();
    return MB_E_UNSUPP;
}

int mb_client_last_end(mb_end_t *out) {
    if (!ho_valid || ho.version < 2)
        return MB_E_UNSUPP;
    *out = ho.prev;
    return MB_OK;
}

// ---------------------------------------------------------------------------
// What is on the board: slots, entries, the bootloader
// ---------------------------------------------------------------------------

static uint32_t floor_now(const mb_bcl_rec_t *r) {
    uint32_t hw[MB_FLOOR_COUNT];
    mb_floor_get(port, hw); // the protected copy wins when it is higher
    return r->min_security > hw[MB_FLOOR_SECURITY] ? r->min_security : hw[MB_FLOOR_SECURITY];
}

int mb_client_slot_info(int slot, mb_client_slot_t *out) {
    if (!port || !out || slot < 0 || slot >= port->layout->n_slots)
        return MB_E_BADARG;
    memset(out, 0, sizeof(*out));
    mb_bcl_t log;
    if (mb_bcl_load(&log, port) != MB_OK)
        return MB_E_IO;
    const mb_slot_def_t *d = &port->layout->slot[slot];
    out->slot = slot;
    out->role = d->role;
    out->size = d->size;
    snprintf(out->name, sizeof(out->name), "%s", d->name);
    out->running = slot == self;
    out->active = slot == log.cur.active;
    mb_slot_info_t in;
    if (mb_image_read_header(port, slot, &in) != MB_OK)
        return MB_OK; // empty
    out->present = true;
    out->format = in.fmt;
    out->version = in.hdr.version;
    out->security_version = in.hdr.security_version;
    out->flags = in.hdr.flags;
    out->image_id = mb_image_id(&in.hdr);
    out->payload_size = in.hdr.payload_size;
    memcpy(out->image_name, in.hdr.name, sizeof(out->image_name));
    out->image_name[sizeof(out->image_name) - 1] = 0;
    const mb_slot_rec_t *s = &log.cur.slot[slot];
    if (s->image_id == out->image_id) { // the log's record is about this image
        out->state = s->state;
        out->bad_reason = s->bad_reason;
        out->tries_left = s->tries_left;
    } else {
        out->state = MB_ST_NEW;
    }
    out->below_floor = d->role == MB_ROLE_AB && in.hdr.security_version < floor_now(&log.cur);
    return MB_OK;
}

// Rollback (or forward) on demand: make another confirmed A/B image the preferred one.
// Only a GOOD image at or above the rollback floor (the protected copy counts), so this
// never brings back an image the board has moved past.
int mb_client_set_active(int slot) {
    if (!port || slot < 0 || slot >= port->layout->n_slots || mb_slot_role(port, slot) != MB_ROLE_AB)
        return MB_E_BADARG;
    mb_client_slot_t s;
    int rc = mb_client_slot_info(slot, &s);
    if (rc != MB_OK)
        return rc;
    if (!s.present || s.state != MB_ST_GOOD || s.below_floor)
        return MB_E_REFUSED;
    mb_bcl_t log;
    if (mb_bcl_load(&log, port) != MB_OK)
        return MB_E_IO;
    if (log.cur.active == slot)
        return MB_OK;
    mb_bcl_rec_t r = log.cur;
    r.active = (uint8_t)slot;
    return mb_bcl_commit(&log, &r);
}

int mb_client_rollback(void) {
    int other = mb_client_other_slot();
    return mb_client_set_active(other);
}

int mb_client_entries(mb_client_entry_t *out, int max) {
    if (!port || !out || max <= 0)
        return MB_E_BADARG;
    static mb_config_t cfg;
    mb_config_load(port, &cfg);
    int n = 0;
    for (int i = 0; i < cfg.n && n < max; i++, n++) {
        memset(&out[n], 0, sizeof(out[n]));
        snprintf(out[n].name, sizeof(out[n].name), "%s", cfg.e[i].name);
        snprintf(out[n].title, sizeof(out[n].title), "%s", cfg.e[i].title);
        out[n].slot = cfg.e[i].slot;
        out[n].is_default = i == cfg.def;
    }
    return n;
}

int mb_client_loader_info(mb_client_loader_t *out) {
    if (!port || !out)
        return MB_E_BADARG;
    memset(out, 0, sizeof(*out));
    out->board = port->name;
    out->target = port->target;
    out->n_slots = port->layout->n_slots;
    if (!ho_valid)
        return MB_E_UNSUPP; // (board and layout only: no handoff this boot)
    out->version = ho.loader_version;
    out->caps = mb_client_capabilities();
    out->features = ho.features;
    out->handoff_version = ho.version;
    out->boot_ms = ho.boot_ms;
    return MB_OK;
}

int mb_client_control(const mb_control_request_t *q, bool now) {
    if (!port)
        return MB_E_BADARG;
    if (!(mb_client_capabilities() & MB_CAP_CONTROL))
        return MB_E_UNSUPP;
    if (!now)
        return mb_control_submit(port, q);
    int rc = mb_client_next_boot(q, MB_VIA_AUTO); // the mailbox when there is one (no flash write)
    return rc < 0 ? rc : mb_client_reboot(MB_END_REBOOT, NULL);
}
static int reboot_mode(unsigned action) {
    mb_control_request_t q = {0};
    q.version = 1;
    q.size = sizeof q;
    q.action = action;
    return mb_client_control(&q, true);
}
int mb_client_reboot_menu(void) { return reboot_mode(MB_CONTROL_MENU); }
int mb_client_reboot_config(void) { return reboot_mode(MB_CONTROL_CONFIG); }
int mb_client_reboot_profile(const char *entry, mb_topology_t t, const char *args) {
    mb_control_request_t q = {0};
    if (!entry || strlen(entry) >= sizeof q.entry || (args && strlen(args) >= sizeof q.args))
        return MB_E_BADARG;
    q.version = 1;
    q.size = sizeof q;
    q.action = MB_CONTROL_ENTRY;
    q.topology = t;
    memcpy(q.entry, entry, strlen(entry) + 1);
    if (args)
        memcpy(q.args, args, strlen(args) + 1);
    return mb_client_control(&q, true);
}
int mb_client_get_config(char *b, size_t n) { return port ? mb_config_read_text(port, b, n, 0) : MB_E_BADARG; }
int mb_client_set_config(const char *t, size_t n, char *e, size_t cap) {
    return !port                                         ? MB_E_BADARG
           : !(mb_client_capabilities() & MB_CAP_CONFIG) ? MB_E_UNSUPP
                                                         : mb_config_validate_save(port, t, n, e, cap);
}
int mb_client_set_default(const char *name) {
    return !port                                         ? MB_E_BADARG
           : !(mb_client_capabilities() & MB_CAP_CONFIG) ? MB_E_UNSUPP
                                                         : mb_config_set_default(port, name);
}
