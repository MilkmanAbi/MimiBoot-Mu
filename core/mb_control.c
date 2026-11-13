#include "core/mimiboot.h"
#include <stdio.h>
#include <string.h>
/* BCL v2 keeps its 256-byte size. Its CRC covers this reserved-space extension. */
#define NIGHT_MAGIC 0x314e424du
typedef struct {
    uint32_t magic;
    uint8_t version, action, core0, core1;
    char entry[16];
} stored_t;
_Static_assert(sizeof(stored_t) == 24, "BCL extension ABI");
uint32_t mb_control_caps(const mb_port_t *p) {
    if (!p)
        return 0;
    if (p->capabilities)
        return p->capabilities();
    return MB_CAP_CONTROL | MB_CAP_CONFIG | (p->ram_ptr && p->launch_ram ? MB_CAP_RAM : 0) |
           (p->arch == MB_ARCH_ARM ? MB_CAP_ARM : MB_CAP_RISCV) | (p->launch ? MB_CAP_XIP : 0) |
           (p->switch_arch ? MB_CAP_ARCH_SWITCH : 0);
}
int mb_topology_validate(const mb_port_t *p, mb_topology_t t) {
    if (!p || t.reserved || t.core0 > 2 || t.core1 > 2)
        return MB_E_BADARG;
    uint8_t a = t.core0 ? t.core0 : p->arch, b = t.core1 ? t.core1 : a;
    uint32_t caps = mb_control_caps(p);
    if ((a == MB_ARCH_ARM || b == MB_ARCH_ARM) && !(caps & MB_CAP_ARM))
        return MB_E_UNSUPP;
    if ((a == MB_ARCH_RISCV || b == MB_ARCH_RISCV) && !(caps & MB_CAP_RISCV))
        return MB_E_UNSUPP;
    if (a != b && !(caps & MB_CAP_MIXED))
        return MB_E_UNSUPP;
    return MB_OK;
}
int mb_topology_resolve(const mb_port_t *p, mb_topology_t t, uint8_t image, mb_topology_t *out) {
    if (!p || !out || image > 2 || t.reserved || t.core0 > 2 || t.core1 > 2)
        return MB_E_BADARG;
    bool explicit = t.core0 || t.core1;
    uint8_t primary = image ? image : p->arch;
    if (t.core0 && t.core0 != primary)
        return MB_E_UNSUPP;
    t.core0 = primary;
    if (!t.core1)
        t.core1 = primary;
    /* Legacy ports have no topology service; preserve their existing launch path. */
    if (t.core0 != t.core1 && (!p->prepare_topology || (t.core0 != p->arch && !p->switch_arch)))
        return MB_E_UNSUPP;
    int rc = explicit || p->capabilities ? mb_topology_validate(p, t) : MB_OK;
    if (!rc)
        *out = t;
    return rc;
}
#if !MB_FEAT_CONTROL
/* No OS control service: requests are refused, the log's Night area is ignored. */
int mb_control_submit(const mb_port_t *p, const mb_control_request_t *q) { (void)p; (void)q; return MB_E_UNSUPP; }
int mb_control_reboot(const mb_port_t *p, const mb_control_request_t *q) { (void)p; (void)q; return MB_E_UNSUPP; }
int mb_control_consume(const mb_port_t *p, mb_bcl_rec_t *r, const mb_config_t *cfg, mb_topology_t *t, int *action) {
    (void)p; (void)cfg; (void)t; (void)action;
    if (r->request == MB_REQ_NIGHT) { memset(r->reserved, 0, sizeof r->reserved); r->request = MB_REQ_NONE; }
    return 0;
}
void mb_control_requeue(mb_bcl_rec_t *r, const mb_config_t *cfg, const struct mb_choice *c) { (void)r; (void)cfg; (void)c; }
#else
static void store(mb_bcl_rec_t *r, unsigned action, mb_topology_t t, const char *entry) {
    stored_t s = {0};
    s.magic = NIGHT_MAGIC;
    s.version = 1;
    s.action = action;
    s.core0 = t.core0;
    s.core1 = t.core1;
    if (entry)
        snprintf(s.entry, sizeof s.entry, "%s", entry);
    memcpy(r->reserved, &s, sizeof s);
    r->request = MB_REQ_NIGHT;
}
int mb_control_submit(const mb_port_t *p, const mb_control_request_t *q) {
    if (!p || !q || q->version != MB_CONTROL_API_VERSION || q->size != sizeof *q || q->action > MB_CONTROL_SLOT ||
        q->reserved[0] || q->reserved[1] || q->reserved[2] || !memchr(q->entry, 0, sizeof q->entry) ||
        !memchr(q->args, 0, sizeof q->args))
        return MB_E_BADARG;
    int rc = mb_topology_validate(p, q->topology);
    if (rc)
        return rc;
    if ((q->topology.core0 || q->topology.core1) && q->action != MB_CONTROL_ENTRY && q->action != MB_CONTROL_SLOT &&
        q->action != MB_CONTROL_RESTART)
        return MB_E_BADARG;
    mb_bcl_t b;
    if (mb_bcl_load(&b, p) != MB_OK)
        return MB_E_IO;
    mb_bcl_rec_t r = b.cur;
    unsigned arg = 0;
    char entry[16] = {0};
    if (q->action == MB_CONTROL_ENTRY) {
        mb_config_t c;
        mb_config_load(p, &c);
        int i = mb_config_find(&c, q->entry);
        if (i < 0)
            return MB_E_BADARG;
        arg = (unsigned)i;
        snprintf(entry, sizeof entry, "%s", c.e[i].name);
    }
    if (q->action == MB_CONTROL_SLOT) {
        if (q->slot >= p->layout->n_slots)
            return MB_E_BADARG;
        arg = q->slot;
    }
    store(&r, q->action, q->topology, entry);
    r.request_arg = (uint8_t)arg;
    memset(r.args, 0, sizeof r.args);
    memcpy(r.args, q->args, strlen(q->args));
    return mb_bcl_commit(&b, &r);
}
int mb_control_reboot(const mb_port_t *p, const mb_control_request_t *q) {
    if (!p || !p->reboot)
        return MB_E_UNSUPP;
    int rc = mb_control_submit(p, q);
    if (rc)
        return rc;
    p->reboot();
    return MB_E_UNSUPP;
}
int mb_control_consume(const mb_port_t *p, mb_bcl_rec_t *r, const mb_config_t *cfg, mb_topology_t *t, int *action) {
    if (r->request != MB_REQ_NIGHT)
        return 0;
    stored_t s;
    memcpy(&s, r->reserved, sizeof s);
    memset(r->reserved, 0, sizeof r->reserved);
    *action = -1;
    if (s.magic != NIGHT_MAGIC || s.version != 1 || s.action > MB_CONTROL_SLOT)
        return MB_E_CORRUPT;
    if (!memchr(s.entry, 0, sizeof s.entry))
        return MB_E_CORRUPT;
    if (s.action == MB_CONTROL_ENTRY) {
        int i = mb_config_find(cfg, s.entry);
        if (i < 0)
            return MB_E_BADARG;
        r->request_arg = (uint8_t)i;
    } else
        for (unsigned i = 0; i < sizeof s.entry; i++)
            if (s.entry[i])
                return MB_E_CORRUPT;
    *t = (mb_topology_t){s.core0, s.core1, 0};
    int rc = mb_topology_validate(p, *t);
    if (rc)
        return rc;
    *action = s.action;
    return 1;
}
void mb_control_requeue(mb_bcl_rec_t *r, const mb_config_t *cfg, const struct mb_choice *c) {
    store(r, c->entry >= 0 ? MB_CONTROL_ENTRY : MB_CONTROL_SLOT, c->topology,
          c->entry >= 0 ? cfg->e[c->entry].name : NULL);
    r->request_arg = (uint8_t)(c->entry >= 0 ? c->entry : c->slot);
    memcpy(r->args, c->args, sizeof r->args);
}
#endif /* MB_FEAT_CONTROL */
