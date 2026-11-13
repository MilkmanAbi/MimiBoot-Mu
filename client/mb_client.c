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
} inst;
static mb_handoff_t ho; // our copy of this boot's handoff
static bool ho_valid;
static char args_buf[MB_ARGS_MAX];

int mb_client_init(const mb_port_t *p) {
    if (!p)
        return MB_E_BADARG;
    port = p;
    ho_valid = false;
    inst.open = false;
    self = p->self_slot ? p->self_slot() : MB_SLOT_NONE;
    return MB_OK;
}

int mb_client_other_slot(void) { return self == MB_SLOT_A ? MB_SLOT_B : MB_SLOT_A; }

// Take the handoff only if it was written for *this* image this boot, then
// clear it so nothing later mistakes it for a fresh one.
void mb_client_set_handoff(volatile mb_handoff_t *h) {
    ho_valid = false;
    if (!h || !port)
        return;
    mb_handoff_t copy;
    memcpy(&copy, (const void *)h, sizeof(copy));
    h->magic = 0;
    if (copy.magic != MB_HANDOFF_MAGIC || copy.version != MB_HANDOFF_VERSION || copy.size != sizeof(copy))
        return;
    if (mb_crc32(0, &copy, offsetof(mb_handoff_t, crc)) != copy.crc)
        return;
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
    st->min_security = log.cur.min_security;
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
    if (mb_image_check_header(port, hdr, port->layout->slot[slot].size) != MB_OK)
        return MB_E_CORRUPT;
    mb_slot_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.hdr = *hdr;
    tmp.header_ok = true;
    if (mb_image_check_sig(port, &tmp) != MB_OK)
        return MB_E_SIGNATURE; // it could never boot: don't wipe the slot for it
    int rc = mb_slot_erase(port, slot, hdr->payload_size);
    if (rc != MB_OK)
        return rc;
    inst.slot = slot;
    inst.hdr = *hdr;
    inst.open = true;
    return MB_OK;
}

int mb_client_install_write(uint32_t offset, const void *data, size_t len) {
    if (!inst.open)
        return MB_E_BADARG;
    if (offset > inst.hdr.payload_size || len > inst.hdr.payload_size - offset)
        return MB_E_NOSPACE;
    return mb_slot_write(port, inst.slot, offset, data, len);
}

int mb_client_install_end(void) {
    if (!inst.open)
        return MB_E_BADARG;
    inst.open = false;
    mb_slot_info_t info;
    memset(&info, 0, sizeof(info));
    info.hdr = inst.hdr;
    info.header_ok = true;
    if (mb_image_verify(port, inst.slot, &info) != MB_OK)
        return MB_E_CORRUPT; // slot stays empty
    return mb_slot_write_header(port, inst.slot, &inst.hdr);
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
    return ho_valid && (ho.reserved & MB_HOFF_NIGHT) && ho.loader_version >= MB_VERSION(2, 0, 0)
               ? (ho.reserved >> 8) & 0xffffu
               : 0;
}
int mb_client_control(const mb_control_request_t *q, bool now) {
    if (!port)
        return MB_E_BADARG;
    if (!(mb_client_capabilities() & MB_CAP_CONTROL))
        return MB_E_UNSUPP;
    return now ? mb_control_reboot(port, q) : mb_control_submit(port, q);
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
