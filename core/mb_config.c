/*
 * MimiBoot - boot config (see mimiboot.h for the format)
 *
 * Storage: two sectors, each [header 256 B][text]. The header carries a
 * sequence number and CRCs of itself and the text; the newest valid copy
 * wins. A save erases the *older* copy, writes the text, and writes the
 * header last, so a power cut mid-save leaves the previous config in force.
 *
 * Parsing never fails as a whole: bad lines are counted and skipped, a bad
 * entry is dropped, and a config with no usable entry falls back to the
 * built-in one. Nothing in here can affect security (keys, signature
 * requirements and the rollback floor are not config keys).
 */
#include "core/mimiboot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Boot services are serialized: these workspaces are shared by parsing and editing. */
#if MB_FEAT_CFG_FILE
static char cfg_source[MB_CFG_MAX + 1], cfg_translated[MB_CFG_MAX + 1];
#endif

#define CFG_MAGIC 0x4643424Du /* "MBCF" */
#define CFG_HDR 256

typedef struct {
    uint32_t magic, seq, len, text_crc;
    uint8_t reserved[CFG_HDR - 20];
    uint32_t crc;
} cfg_hdr_t;

_Static_assert(sizeof(cfg_hdr_t) == CFG_HDR, "config header must be one page");

// ---------------------------------------------------------------------------
// Built-in
// ---------------------------------------------------------------------------

static void add_entry(mb_config_t *c, const char *name, const char *title, int slot) {
    if (c->n >= MB_MAX_ENTRIES)
        return;
    mb_entry_t *e = &c->e[c->n++];
    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", name);
    snprintf(e->title, sizeof(e->title), "%s", title);
    e->slot = (uint8_t)slot;
}

void mb_config_builtin(const mb_port_t *p, mb_config_t *c) {
    memset(c, 0, sizeof(*c));
    c->timeout_s = -1;
    add_entry(c, "os", "A/B (newest good image)", MB_SLOT_AB);
    add_entry(c, "recovery", "golden recovery image", MB_SLOT_GOLDEN);
    for (int i = 0; i < p->layout->n_slots; i++) {
        if (p->layout->slot[i].role != MB_ROLE_AUX)
            continue;
        char title[32];
        snprintf(title, sizeof(title), "slot %s", p->layout->slot[i].name);
        add_entry(c, p->layout->slot[i].name, title, i);
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

#if MB_FEAT_CFG_FILE
static const char *skip_ws(const char *s, const char *end) {
    while (s < end && (*s == ' ' || *s == '\t'))
        s++;
    return s;
}

static bool word_is(const char *w, size_t n, const char *kw) { return strlen(kw) == n && !memcmp(w, kw, n); }
#endif

int mb_config_find(const mb_config_t *c, const char *name) {
    if (!name || !*name)
        return -1;
    for (int i = 0; i < c->n; i++)
        if (!strcmp(c->e[i].name, name))
            return i;
    char *end;
    long v = strtol(name, &end, 10);
    if (!*end && v >= 1 && v <= c->n)
        return (int)v - 1; // menu numbers are 1-based
    return -1;
}

#if !MB_FEAT_CFG_FILE
/* No config in flash: the built-in entries (A/B, golden, each aux slot) are
 * the whole config. The cfg regions of the layout are left alone. */
int mb_config_parse(const mb_port_t *p, const char *text, size_t len, mb_config_t *c, char *err, size_t cap) {
    (void)text; (void)len;
    if (err && cap) snprintf(err, cap, "config files are not built in");
    if (p && c) mb_config_builtin(p, c);
    return MB_E_UNSUPP;
}
int mb_config_load(const mb_port_t *p, mb_config_t *c) { mb_config_builtin(p, c); return MB_OK; }
int mb_config_read_text(const mb_port_t *p, char *buf, size_t cap, uint32_t *seq) { (void)p; (void)buf; (void)cap; (void)seq; return MB_E_UNSUPP; }
int mb_config_save(const mb_port_t *p, const char *text, size_t len) { (void)p; (void)text; (void)len; return MB_E_UNSUPP; }
int mb_config_validate_save(const mb_port_t *p, const char *t, size_t len, char *err, size_t cap) {
    (void)p; (void)t; (void)len;
    if (err && cap) snprintf(err, cap, "config files are not built in");
    return MB_E_UNSUPP;
}
int mb_config_set_default(const mb_port_t *p, const char *name) { (void)p; (void)name; return MB_E_UNSUPP; }
#else

static void note(int line, const char *what, char *err, size_t cap, int *errors) {
    if (!*errors && err && cap)
        snprintf(err, cap, "line %d: %s", line, what);
    (*errors)++;
}

static int parse_legacy(const mb_port_t *p, const char *text, size_t len, mb_config_t *c, char *err, size_t errcap) {
    memset(c, 0, sizeof(*c));
    c->timeout_s = -1;
    if (err && errcap)
        err[0] = 0;
    char def_name[16] = "";
    mb_entry_t *cur = NULL;
    bool cur_ok = false;
    int line = 0;
    const char *end = text + len;
    for (const char *s = text; s < end;) {
        const char *eol = s;
        while (eol < end && *eol != '\n')
            eol++;
        line++;
        const char *e = eol;
        while (e > s && (e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
            e--;
        const char *w = skip_ws(s, e);
        s = eol < end ? eol + 1 : end;
        if (w >= e || *w == '#')
            continue;
        const char *we = w;
        while (we < e && *we != ' ' && *we != '\t')
            we++;
        size_t wl = (size_t)(we - w);
        const char *arg = skip_ws(we, e);
        size_t al = (size_t)(e - arg);
        // strings must not contain NULs (binary garbage)
        if (memchr(w, 0, (size_t)(e - w))) {
            note(line, "binary data", err, errcap, &c->errors);
            continue;
        }

        if (word_is(w, wl, "entry")) {
            if (cur && !cur_ok)
                c->n--; // drop the previous one: it never got a slot
            cur = NULL;
            if (c->n >= MB_MAX_ENTRIES) {
                note(line, "too many entries", err, errcap, &c->errors);
                continue;
            }
            if (!al || al >= sizeof(cur->name) || memchr(arg, ' ', al)) {
                note(line, "bad entry name", err, errcap, &c->errors);
                continue;
            }
            bool duplicate = false;
            for (int k = 0; k < c->n; k++)
                if (strlen(c->e[k].name) == al && !memcmp(c->e[k].name, arg, al))
                    duplicate = true;
            if (duplicate) {
                note(line, "duplicate entry ID", err, errcap, &c->errors);
                continue;
            }
            cur = &c->e[c->n++];
            memset(cur, 0, sizeof(*cur));
            memcpy(cur->name, arg, al);
            cur_ok = false;
        } else if (word_is(w, wl, "timeout")) {
            char *x;
            char tmp[12] = "";
            memcpy(tmp, arg, al < sizeof(tmp) - 1 ? al : sizeof(tmp) - 1);
            long v = strtol(tmp, &x, 10);
            if (x == tmp || *x || v < 0 || v > 600)
                note(line, "timeout: 0..600 seconds", err, errcap, &c->errors);
            else
                c->timeout_s = (int)v;
        } else if (word_is(w, wl, "default")) {
            if (!al || al >= sizeof(def_name))
                note(line, "bad default", err, errcap, &c->errors);
            else {
                memset(def_name, 0, sizeof(def_name));
                memcpy(def_name, arg, al);
            }
        } else if (!cur) {
            note(line, "unknown setting (or entry setting outside an entry)", err, errcap, &c->errors);
        } else if (word_is(w, wl, "title")) {
            size_t n = al < sizeof(cur->title) - 1 ? al : sizeof(cur->title) - 1;
            memcpy(cur->title, arg, n);
            cur->title[n] = 0;
        } else if (word_is(w, wl, "args")) {
            if (al >= sizeof(cur->args)) {
                note(line, "args longer than 95 characters", err, errcap, &c->errors);
                continue;
            }
            memcpy(cur->args, arg, al);
            cur->args[al] = 0;
        } else if (word_is(w, wl, "slot")) {
            char tmp[8] = "";
            if (al >= sizeof(tmp)) {
                note(line, "bad slot", err, errcap, &c->errors);
                continue;
            }
            memcpy(tmp, arg, al);
            int sl = !strcmp(tmp, "ab") ? MB_SLOT_AB : mb_slot_parse(p, tmp);
            if (sl < 0) {
                note(line, "no such slot", err, errcap, &c->errors);
                continue;
            }
            cur->slot = (uint8_t)sl;
            cur_ok = true;
        } else if (word_is(w, wl, "topology")) {
            char a[12] = {0}, b[12] = {0};
            char row[40] = {0};
            if (al >= sizeof row) {
                note(line, "invalid topology", err, errcap, &c->errors);
                continue;
            }
            memcpy(row, arg, al);
            size_t na = strcspn(row, " \t");
            const char *second = row + na;
            second += strspn(second, " \t");
            size_t nb = strcspn(second, " \t");
            const char *tail = second + nb;
            tail += strspn(tail, " \t");
            if (!na || na >= sizeof a || !nb || nb >= sizeof b || *tail) {
                note(line, "topology requires two CPUs", err, errcap, &c->errors);
                continue;
            }
            memcpy(a, row, na);
            memcpy(b, second, nb);
            int cpus[2] = {-1, -1};
            char *names[2] = {a, b};
            for (int k = 0; k < 2; k++) {
                if (!strcmp(names[k], "arm"))
                    cpus[k] = MB_ARCH_ARM;
                else if (!strcmp(names[k], "riscv"))
                    cpus[k] = MB_ARCH_RISCV;
                else if (!strcmp(names[k], "auto"))
                    cpus[k] = MB_ARCH_ANY;
            }
            if (cpus[0] < 0 || cpus[1] < 0)
                note(line, "CPU must be arm/riscv/auto", err, errcap, &c->errors);
            else
                cur->topology = (mb_topology_t){(uint8_t)cpus[0], (uint8_t)cpus[1], 0};
        } else if (word_is(w, wl, "arch")) {
            if (word_is(arg, al, "arm"))
                cur->arch = MB_ARCH_ARM;
            else if (word_is(arg, al, "riscv"))
                cur->arch = MB_ARCH_RISCV;
            else if (word_is(arg, al, "any"))
                cur->arch = MB_ARCH_ANY;
            else
                note(line, "arch: arm, riscv or any", err, errcap, &c->errors);
        } else {
            note(line, "unknown entry setting", err, errcap, &c->errors);
        }
    }
    if (cur && !cur_ok)
        c->n--;
    for (int i = 0; i < c->n; i++)
        if (!c->e[i].title[0])
            snprintf(c->e[i].title, sizeof(c->e[i].title), "%s", c->e[i].name);
    if (!c->n) {
        int errors = c->errors;
        mb_config_builtin(p, c);
        c->errors = errors;
        if (err && errcap && !err[0])
            snprintf(err, errcap, "no usable entry: built-in config");
        return MB_E_CORRUPT;
    }
    c->def = 0;
    if (def_name[0]) {
        int d = mb_config_find(c, def_name);
        if (d >= 0)
            c->def = d;
        else
            note(0, "default names no entry", err, errcap, &c->errors);
    }
    return MB_OK;
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

static bool read_copy(const mb_port_t *p, int i, cfg_hdr_t *h) {
    const mb_region_t *r = &p->layout->cfg[i];
    if (!r->size || p->flash_read(r->offset, h, sizeof(*h)) != MB_OK)
        return false;
    if (h->magic != CFG_MAGIC || mb_crc32(0, h, offsetof(cfg_hdr_t, crc)) != h->crc)
        return false;
    if (h->len > r->size - CFG_HDR || h->len > MB_CFG_MAX)
        return false;
    // the text must match its CRC
    uint32_t crc = 0;
    uint8_t buf[128];
    for (uint32_t done = 0; done < h->len;) {
        uint32_t n = h->len - done < sizeof(buf) ? h->len - done : (uint32_t)sizeof(buf);
        if (p->flash_read(r->offset + CFG_HDR + done, buf, n) != MB_OK)
            return false;
        crc = mb_crc32(crc, buf, n);
        done += n;
    }
    return crc == h->text_crc;
}

static int newest(const mb_port_t *p, cfg_hdr_t *h) {
    cfg_hdr_t a, b;
    bool va = read_copy(p, 0, &a), vb = read_copy(p, 1, &b);
    if (va && vb) {
        bool pick_b = (int32_t)(b.seq - a.seq) > 0;
        *h = pick_b ? b : a;
        return pick_b;
    }
    if (va) {
        *h = a;
        return 0;
    }
    if (vb) {
        *h = b;
        return 1;
    }
    return -1;
}

int mb_config_read_text(const mb_port_t *p, char *buf, size_t cap, uint32_t *seq) {
    cfg_hdr_t h;
    int i = newest(p, &h);
    if (i < 0)
        return MB_E_CORRUPT;
    if (h.len + 1 > cap)
        return MB_E_NOSPACE;
    if (p->flash_read(p->layout->cfg[i].offset + CFG_HDR, buf, h.len) != MB_OK)
        return MB_E_IO;
    buf[h.len] = 0;
    if (seq)
        *seq = h.seq;
    return (int)h.len;
}

int mb_config_load(const mb_port_t *p, mb_config_t *c) {
    char *text = cfg_source;
    uint32_t seq = 0;
    int n = mb_config_read_text(p, text, sizeof(cfg_source), &seq);
    if (n < 0) {
        mb_config_builtin(p, c);
        return MB_OK;
    }
    mb_config_parse(p, text, (size_t)n, c, NULL, 0);
    c->from_flash = true;
    c->seq = seq;
    return MB_OK;
}

int mb_config_save(const mb_port_t *p, const char *text, size_t len) {
    if (len > MB_CFG_MAX)
        return MB_E_NOSPACE;
    cfg_hdr_t cur;
    int have = newest(p, &cur);
    int to = have < 0 ? 0 : 1 - have;
    const mb_region_t *r = &p->layout->cfg[to];
    if (!r->size || len > r->size - CFG_HDR)
        return MB_E_NOSPACE;
    int rc = p->flash_erase(r->offset, r->size);
    if (rc != MB_OK)
        return rc;
    // text first, page by page
    uint32_t page = p->layout->page_size;
    uint8_t buf[256];
    if (page > sizeof(buf))
        return MB_E_UNSUPP;
    for (uint32_t done = 0; done < len; done += page) {
        uint32_t n = len - done < page ? (uint32_t)(len - done) : page;
        memset(buf, 0xFF, page);
        memcpy(buf, text + done, n);
        if ((rc = p->flash_program(r->offset + CFG_HDR + done, buf, page)) != MB_OK)
            return rc;
    }
    // the header makes it real
    cfg_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = CFG_MAGIC;
    h.seq = have < 0 ? 1 : cur.seq + 1;
    h.len = (uint32_t)len;
    h.text_crc = mb_crc32(0, text, len);
    h.crc = mb_crc32(0, &h, offsetof(cfg_hdr_t, crc));
    return p->flash_program(r->offset, &h, sizeof(h));
}

int mb_config_parse(const mb_port_t *p, const char *text, size_t len, mb_config_t *c, char *err, size_t cap) {
    if (!p || !text || !c || len > MB_CFG_MAX)
        return MB_E_BADARG;
    char *translated = cfg_translated;
    int rc = mb_grub_translate(text, len, translated, sizeof cfg_translated, err, cap);
    if (rc < 0) {
        mb_config_builtin(p, c);
        c->errors = 1;
        return rc;
    }
    return parse_legacy(p, rc ? translated : text, rc ? strlen(translated) : len, c, err, cap);
}
int mb_config_validate_save(const mb_port_t *p, const char *t, size_t len, char *err, size_t cap) {
    static mb_config_t c;
    int rc = mb_config_parse(p, t, len, &c, err, cap);
    if (rc || c.errors)
        return MB_E_BADARG;
    for (int i = 0; i < c.n; i++)
        if (c.e[i].topology.core0 || c.e[i].topology.core1) {
            rc = mb_topology_validate(p, c.e[i].topology);
            if (rc) {
                if (err && cap)
                    snprintf(err, cap, "entry %s: topology unsupported by this board", c.e[i].name);
                return rc;
            }
        }
    return mb_config_save(p, t, len);
}
int mb_config_set_default(const mb_port_t *p, const char *name) {
    mb_config_t c;
    mb_config_load(p, &c);
    int index = mb_config_find(&c, name);
    if (index < 0)
        return MB_E_BADARG;
    char selected[16];
    snprintf(selected, sizeof selected, "%s", c.e[index].name);
    char *source = cfg_source;
    int n = mb_config_read_text(p, source, sizeof cfg_source, 0);
    if (n < 0) {
        size_t at = 0;
        source[0] = 0;
        for (int i = 0; i < c.n; i++) {
            int k = snprintf(source + at, sizeof cfg_source - at, "entry %s\ntitle %s\nslot %s\nargs %s\n", c.e[i].name,
                             c.e[i].title, mb_slot_name(p, c.e[i].slot), c.e[i].args);
            if (k < 0 || (size_t)k >= sizeof cfg_source - at)
                return MB_E_NOSPACE;
            at += (size_t)k;
        }
        n = (int)at;
    }
    int rc = mb_grub_translate(source, (size_t)n, cfg_translated, sizeof cfg_translated, 0, 0);
    if (rc < 0)
        return rc;
    if (rc)
        memcpy(source, cfg_translated, strlen(cfg_translated) + 1);
    size_t at = 0;
    size_t total = strlen(source);
    for (size_t pos = 0; pos < total;) {
        const char *s = source + pos;
        const char *end = memchr(s, '\n', total - pos);
        if (!end)
            end = source + total;
        const char *w = s;
        while (w < end && (*w == ' ' || *w == '\t'))
            w++;
        bool def = end - w >= 7 && !memcmp(w, "default", 7) && (w + 7 == end || w[7] == ' ' || w[7] == '\t');
        size_t len = (size_t)(end - s);
        size_t next = (size_t)(end - source) + (end < source + total ? 1 : 0);
        if (!def) {
            if (at + len + 1 >= sizeof cfg_source)
                return MB_E_NOSPACE;
            memmove(source + at, s, len);
            at += len;
            source[at++] = '\n';
        }
        pos = next;
    }
    source[at] = 0;
    char row[32];
    int k = snprintf(row, sizeof row, "default %s\n", selected);
    if (k < 0 || at + (size_t)k >= sizeof cfg_source)
        return MB_E_NOSPACE;
    memmove(source + k, source, at + 1);
    memcpy(source, row, (size_t)k);
    return mb_config_validate_save(p, source, at + (size_t)k, 0, 0);
}

#endif /* MB_FEAT_CFG_FILE */
