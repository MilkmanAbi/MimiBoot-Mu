/*
 * MimiBoot - console: boot menu and command line
 *
 * Reached when the port's boot key fires (RP2350: BOOT pressed in the window
 * just after power-up), when an app asks for it (MB_REQ_MENU), or when
 * nothing is bootable. The menu lists the config's entries and boots the
 * default after the countdown unless a key is pressed:
 *
 *   up/down, 1-8, enter   boot an entry
 *   e                     edit the selected entry's args, then boot it (this boot only)
 *   c                     command line
 *   r / u                 reboot / ROM USB loader
 */
#include "core/mimiboot.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if MB_FEAT_CONSOLE

#define LINE_MAX    128

void mb_printf(const mb_port_t* p, const char* fmt, ...) {
    if (!p->write) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(buf) - 1) n = sizeof(buf) - 1;
    if (n > 0) p->write(buf, (size_t)n);
}

static void put(const mb_port_t* p, const char* s) { if (p->write) p->write(s, strlen(s)); }

static const char* state_name(int st) {
    static const char* n[] = { "empty", "NEW", "TRIAL", "GOOD", "BAD" };
    return st >= 0 && st <= MB_ST_BAD ? n[st] : "?";
}

static const char* bad_name(int r) {
    static const char* n[] = { "", "header", "hash", "never confirmed", "rollback", "can't start here",
                               "launch failed", "rejected", "golden not newer", "signature" };
    return r >= 0 && r <= MB_BAD_SIGNATURE ? n[r] : "?";
}

__attribute__((unused)) static const char* kind_name(int k) {
    static const char* n[] = { "-", "normal", "trial", "once", "fallback", "golden", "menu", "entry" };
    return k >= 0 && k <= MB_KIND_ENTRY ? n[k] : "?";
}

__attribute__((unused)) static const char* arch_name(int a) { return a == MB_ARCH_ARM ? "arm" : a == MB_ARCH_RISCV ? "riscv" : "any"; }

static void fmt_version(char* out, size_t cap, uint32_t v) {
    snprintf(out, cap, "%lu.%lu.%lu", (unsigned long)MB_VERSION_MAJOR(v), (unsigned long)MB_VERSION_MINOR(v),
             (unsigned long)MB_VERSION_PATCH(v));
}

static int getc_wait(const mb_port_t* p, uint32_t ms) { return p->getc ? p->getc(ms) : -1; }

__attribute__((unused)) static void refresh_headers(const mb_port_t* p, mb_slot_info_t* info) {
    for (int i = 0; i < p->layout->n_slots; i++) {
        mb_slot_info_t fresh;
        mb_image_read_header(p, i, &fresh);
        // keep check results only for the very same image
        if (!(fresh.header_ok && info[i].header_ok && !memcmp(&fresh.hdr, &info[i].hdr, sizeof(fresh.hdr)))) info[i] = fresh;
    }
}

#if MB_FEAT_SHELL
// ---------------------------------------------------------------------------
// Listings
// ---------------------------------------------------------------------------

static void slot_line(const mb_port_t* p, const mb_bcl_t* log, mb_slot_info_t* info, int i) {
    const mb_slot_rec_t* s = &log->cur.slot[i];
    char ver[16] = "";
    if (info[i].header_ok) fmt_version(ver, sizeof(ver), info[i].hdr.version);
    mb_printf(p, "%-3s %-20.20s %-9s %-5s %-6s", mb_slot_name(p, i), info[i].header_ok ? info[i].hdr.name : "(empty)", ver,
              info[i].header_ok ? arch_name(info[i].hdr.arch) : "", state_name(s->state));
    if ((s->state == MB_ST_TRIAL || s->state == MB_ST_NEW) && mb_slot_role(p, i) == MB_ROLE_AB)
        mb_printf(p, " %u tries left", s->tries_left);
    if (s->state == MB_ST_BAD) mb_printf(p, " (%s)", bad_name(s->bad_reason));
    if (info[i].header_ok && (info[i].hdr.flags & MB_IMG_F_SIGNED)) put(p, " signed");
    if (log->cur.active == i) put(p, " *active");
    if (log->cur.last_slot == i && log->cur.strikes) mb_printf(p, " %u strikes", log->cur.strikes);
}

static void cmd_ls(const mb_port_t* p, const mb_bcl_t* log, mb_slot_info_t* info) {
    put(p, "    name                 version   arch  state\n");
    for (int i = 0; i < p->layout->n_slots; i++) {
        slot_line(p, log, info, i);
        put(p, "\n");
    }
}

static void cmd_entries(const mb_port_t* p, const mb_config_t* cfg) {
    mb_printf(p, "config: %s (seq %lu)%s, timeout %d s\n", cfg->from_flash ? "from flash" : "built-in", (unsigned long)cfg->seq,
              cfg->errors ? ", with errors" : "", cfg->timeout_s < 0 ? MB_MENU_SECS : cfg->timeout_s);
    for (int i = 0; i < cfg->n; i++) {
        const mb_entry_t* e = &cfg->e[i];
        mb_printf(p, " %c %d %-15s slot %-3s %-5s %s\n", i == cfg->def ? '*' : ' ', i + 1, e->name, mb_slot_name(p, e->slot),
                  arch_name(e->arch), e->title);
        if (e->args[0]) mb_printf(p, "        args: %s\n", e->args);
    }
}

static void cmd_info(const mb_port_t* p, const mb_bcl_t* log, mb_slot_info_t* info, int i) {
    const mb_slot_def_t* r = &p->layout->slot[i];
    static const char* roles[] = { "-", "A/B", "golden", "aux" };
    mb_printf(p, "slot %s (%s): flash 0x%06lx, %lu KB\n", mb_slot_name(p, i), roles[r->role & 3], (unsigned long)r->offset,
              (unsigned long)(r->size / 1024));
    if (!info[i].header_ok) { put(p, "  no valid image header\n"); return; }
    const mb_image_hdr_t* h = &info[i].hdr;
    char ver[16];
    fmt_version(ver, sizeof(ver), h->version);
    mb_printf(p, "  name      %s\n  version   %s   security %lu\n", h->name, ver, (unsigned long)h->security_version);
    mb_printf(p, "  target    %.16s/%s   load %s", h->target, arch_name(h->arch), h->load_type == MB_LOAD_CHAIN ? "xip" : "ram");
    if (h->load_type == MB_LOAD_RAM) mb_printf(p, " @0x%08lx", (unsigned long)h->load_addr);
    mb_printf(p, "   %lu bytes\n", (unsigned long)h->payload_size);
    put(p, "  sha256    ");
    for (int k = 0; k < 32; k++) mb_printf(p, "%02x", h->sha256[k]);
    mb_printf(p, "\n  signed    %s", h->flags & MB_IMG_F_SIGNED ? "yes" : "no");
    if (h->flags & MB_IMG_F_SIGNED) mb_printf(p, " (key %08lx)", (unsigned long)h->key_id);
    if (h->handoff_addr) mb_printf(p, "   handoff @0x%08lx", (unsigned long)h->handoff_addr);
    mb_printf(p, "\n  trial watchdog %lu ms\n", (unsigned long)(h->trial_timeout_ms ? h->trial_timeout_ms : MB_DEFAULT_TRIAL_MS));
    const mb_slot_rec_t* s = &log->cur.slot[i];
    mb_printf(p, "  log       %s", state_name(s->state));
    if (s->state == MB_ST_BAD) mb_printf(p, " (%s)", bad_name(s->bad_reason));
    mb_printf(p, ", %u trial starts, %u tries left%s\n", s->boots, s->tries_left, s->flags & MB_SF_SIG_OK ? ", signature checked" : "");
}

static void cmd_verify(const mb_port_t* p, mb_slot_info_t* info, int i) {
    if (!info[i].header_ok) { mb_printf(p, "%s: no image\n", mb_slot_name(p, i)); return; }
    info[i].hash_state = 0;
    info[i].sig_state = 0;
    uint32_t t0 = p->time_ms ? p->time_ms() : 0;
    int rc = mb_image_verify(p, i, &info[i]);
    uint32_t t1 = p->time_ms ? p->time_ms() : 0;
    int sr = mb_image_check_sig(p, &info[i]);
    uint32_t t2 = p->time_ms ? p->time_ms() : 0;
    bool signd = info[i].hdr.flags & MB_IMG_F_SIGNED;
    mb_printf(p, "%s: sha256 %s (%lu KB in %lu ms), signature %s", mb_slot_name(p, i), rc == MB_OK ? "OK" : "MISMATCH",
              (unsigned long)(info[i].hdr.payload_size / 1024), (unsigned long)(t1 - t0),
              signd ? (sr == MB_OK ? "OK" : "BAD") : (sr == MB_OK ? "none (allowed)" : "none (REQUIRED)"));
    if (signd) mb_printf(p, " in %lu ms", (unsigned long)(t2 - t1));
    put(p, "\n");
}

#if MB_FEAT_SHELL_DIAG
static void cmd_log(const mb_port_t* p, const mb_bcl_t* log) {
    const mb_bcl_rec_t* r = &log->cur;
    mb_printf(p, "log: %s, sector %d, generation %lu, record seq %lu, next free +0x%lx\n", log->fresh ? "empty" : "ok",
              log->sector, (unsigned long)log->generation, (unsigned long)r->seq, (unsigned long)log->next_off);
    mb_printf(p, "active %s, last boot %s (%s, entry %d), strikes %u, security floor %lu, golden v%lu, %lu logged boots\n",
              mb_slot_name(p, r->active), mb_slot_name(p, r->last_slot), kind_name(r->last_kind),
              r->last_entry == 0xFF ? 0 : r->last_entry + 1, r->strikes, (unsigned long)r->min_security,
              (unsigned long)r->golden_version, (unsigned long)r->boot_count);
    for (int i = 0; i < p->layout->n_slots; i++)
        mb_printf(p, "  %-3s id %08lx%08lx %s\n", mb_slot_name(p, i), (unsigned long)(r->slot[i].image_id >> 32),
                  (unsigned long)r->slot[i].image_id, state_name(r->slot[i].state));
}

static void cmd_layout(const mb_port_t* p) {
    const mb_layout_t* l = p->layout;
    mb_printf(p, "flash %lu KB, sector %lu, page %lu\n", (unsigned long)(l->flash_size / 1024), (unsigned long)l->sector_size,
              (unsigned long)l->page_size);
    mb_printf(p, "  boot   0x%06lx %5lu KB\n", (unsigned long)l->boot.offset, (unsigned long)(l->boot.size / 1024));
    for (int i = 0; i < 2; i++) mb_printf(p, "  log%d   0x%06lx %5lu KB\n", i, (unsigned long)l->log[i].offset, (unsigned long)(l->log[i].size / 1024));
    for (int i = 0; i < 2; i++) mb_printf(p, "  cfg%d   0x%06lx %5lu KB\n", i, (unsigned long)l->cfg[i].offset, (unsigned long)(l->cfg[i].size / 1024));
    for (int i = 0; i < l->n_slots; i++)
        mb_printf(p, "  %-6s 0x%06lx %5lu KB\n", mb_slot_name(p, i), (unsigned long)l->slot[i].offset, (unsigned long)(l->slot[i].size / 1024));
    mb_printf(p, "  data   0x%06lx %5lu KB\n", (unsigned long)l->data.offset, (unsigned long)(l->data.size / 1024));
}

static void cmd_md(const mb_port_t* p, uint32_t off, uint32_t len) {
    if (len > 1024) len = 1024;
    if(off>UINT32_MAX-len)return;
    const uint8_t*ram=p->ram_ptr?p->ram_ptr(off,len):NULL;
    for (uint32_t a = off; a < off + len; a += 16) {
        uint8_t b[16];
        if(ram){size_t n=off+len-a<16?off+len-a:16;memset(b,0,16);memcpy(b,ram+a-off,n);}
        else if (p->flash_read(a, b, 16) != MB_OK) return;
        mb_printf(p, "%06lx ", (unsigned long)a);
        for (int k = 0; k < 16; k++) mb_printf(p, "%s%02x", k == 8 ? "  " : " ", b[k]);
        put(p, "  |");
        for (int k = 0; k < 16; k++) mb_printf(p, "%c", b[k] >= 32 && b[k] < 127 ? b[k] : '.');
        put(p, "|\n");
    }
}

static void cmd_sha(const mb_port_t* p, uint32_t off, uint32_t len) {
    mb_sha256_t s;
    uint8_t buf[256], d[32];
    mb_sha256_init(&s);
    for (uint32_t done = 0; done < len;) {
        uint32_t n = len - done < sizeof(buf) ? len - done : (uint32_t)sizeof(buf);
        if (p->flash_read(off + done, buf, n) != MB_OK) { put(p, "read error\n"); return; }
        mb_sha256_update(&s, buf, n);
        done += n;
    }
    mb_sha256_final(&s, d);
    for (int k = 0; k < 32; k++) mb_printf(p, "%02x", d[k]);
    mb_printf(p, "  flash 0x%06lx +%lu\n", (unsigned long)off, (unsigned long)len);
}

static void cmd_keys(const mb_port_t* p) {
    mb_printf(p, "signatures: %s\n", p->require_signature ? "REQUIRED (unsigned images are refused)" : "optional (checked when present)");
    if (!p->keys || !p->keys->count) { put(p, "no trusted keys built in\n"); return; }
    for (int k = 0; k < p->keys->count; k++) {
        mb_printf(p, "  key %d  ", k);
        for (int i = 0; i < 32; i++) mb_printf(p, "%02x", p->keys->keys[k][i]);
        put(p, "\n");
    }
}

#endif /* MB_FEAT_SHELL_DIAG */

static int commit_state(const mb_port_t* p, mb_bcl_t* log, int slot, int state, int reason, int tries) {
    mb_bcl_rec_t r = log->cur;
    r.slot[slot].state = (uint8_t)state;
    r.slot[slot].bad_reason = (uint8_t)reason;
    r.slot[slot].tries_left = (uint8_t)tries;
    int rc = mb_bcl_commit(log, &r);
    mb_printf(p, "%s -> %s%s\n", mb_slot_name(p, slot), state_name(state), rc ? "  (log write FAILED)" : "");
    return rc;
}
#endif /* MB_FEAT_SHELL */

// ---------------------------------------------------------------------------
// Line input
// ---------------------------------------------------------------------------

// Idle limit for the prompt (flash mode): read_line gives up after this long without input
static uint32_t idle_limit_ms;

// Read a line, starting from `init` (for editing args). Esc / Ctrl-C cancels: returns -1.
// -2: nothing typed for idle_limit_ms.
static int read_line(const mb_port_t* p, char* buf, int cap, const char* init) {
    uint32_t idle = 0;
    int n = 0;
    if (init) {
        n = (int)strlen(init);
        if (n > cap - 1) n = cap - 1;
        memcpy(buf, init, (size_t)n);
        buf[n] = 0;
        put(p, buf);
    }
    for (;;) {
        int c = getc_wait(p, 1000);
        if (c < 0) {
            idle += 1000;
            if (idle_limit_ms && idle >= idle_limit_ms) { buf[0] = 0; return -2; }
            continue;
        }
        idle = 0;
        if (c == '\r' || c == '\n') { put(p, "\n"); buf[n] = 0; return n; }
        if ((c == 0x7F || c == 0x08) && n) { n--; put(p, "\b \b"); continue; }
        if (c == 0x15) { while (n) { n--; put(p, "\b \b"); } continue; }      // Ctrl-U
        if (c == 0x03 || c == 0x1B) { put(p, " (cancelled)\n"); buf[0] = 0; return -1; }
        if (c >= 32 && c < 127 && n < cap - 1) { buf[n++] = (char)c; char e[2] = { (char)c, 0 }; put(p, e); }
    }
}

#if MB_FEAT_SHELL
static int split(char* s, char** argv, int max) {
    int n = 0;
    while (*s && n < max) {
        while (*s == ' ') *s++ = 0;
        if (!*s) break;
        argv[n++] = s;
        while (*s && *s != ' ') s++;
    }
    return n;
}

// the rest of the line after the first `skip` words, for args
static const char* rest(const char* line, int skip) {
    const char* s = line;
    for (int i = 0; i < skip; i++) {
        while (*s == ' ') s++;
        while (*s && *s != ' ') s++;
    }
    while (*s == ' ') s++;
    return s;
}
#endif /* MB_FEAT_SHELL */

// ---------------------------------------------------------------------------
// Booting from the console
// ---------------------------------------------------------------------------

static void report_refused(const mb_port_t* p, const mb_bcl_t* log, int slot) {
    if (slot < 0 || slot >= p->layout->n_slots) { put(p, "not bootable\n"); return; }
    const mb_slot_rec_t* s = &log->cur.slot[slot];
    mb_printf(p, "%s: not bootable (%s%s%s)\n", mb_slot_name(p, slot), state_name(s->state), s->state == MB_ST_BAD ? ": " : "",
              s->state == MB_ST_BAD ? bad_name(s->bad_reason) : "");
}

static void launch_plan(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, mb_slot_info_t* info, const mb_plan_t* plan) {
    mb_printf(p, "booting %s%s%s%s...\n", mb_slot_name(p, plan->choice.slot), plan->choice.trial ? " (trial)" : "",
              plan->choice.args[0] ? ", args: " : "", plan->choice.args);
    if (p->console_close) p->console_close();
    int rc = mb_boot(p, log, cfg, info, plan);
    mb_printf(p, "launch failed (%d)\n", rc);
}

static void boot_entry(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, mb_slot_info_t* info, int entry, const char* args) {
    mb_plan_t plan;
    if (mb_plan_entry(p, log, cfg, info, entry, args, &plan) != MB_OK) {
        if (plan.base_dirty) mb_bcl_commit(log, &plan.base);       // keep what we learned (a bad hash...)
        mb_printf(p, "entry %s: ", cfg->e[entry].name);
        report_refused(p, log, cfg->e[entry].slot == MB_SLOT_AB ? (int)log->cur.active : cfg->e[entry].slot);
        return;
    }
    launch_plan(p, log, cfg, info, &plan);
}

#if MB_FEAT_SHELL
static void boot_slot(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, mb_slot_info_t* info, int slot, bool force, const char* args) {
    mb_plan_t plan;
    if (mb_plan_slot(p, log, info, slot, force, args, &plan) != MB_OK) {
        if (plan.base_dirty) mb_bcl_commit(log, &plan.base);
        report_refused(p, log, slot);
        if (!force) put(p, "  ('boot <slot> force' boots an image with a good hash and signature regardless of its state)\n");
        return;
    }
    launch_plan(p, log, cfg, info, &plan);
}

// ---------------------------------------------------------------------------
// recv / ramboot / cfg recv
// ---------------------------------------------------------------------------

// I/O adapters: every sink context starts with the port pointer
typedef struct { const mb_port_t* p; } io_ctx_t;
static int io_getc(void* ctx, uint32_t ms) { return getc_wait(((io_ctx_t*)ctx)->p, ms); }
static void io_puts(void* ctx, const char* s) { put(((io_ctx_t*)ctx)->p, s); }

typedef struct { const mb_port_t* p; mb_image_hdr_t hdr; uint8_t* mem; } ram_sink_t;

static int ram_begin(void* ctx, const mb_image_hdr_t* hdr) {
    ram_sink_t* s = ctx;
    if (hdr->load_type != MB_LOAD_RAM) return MB_E_UNSUPP;
    if (strncmp(hdr->target, s->p->target, sizeof(hdr->target))) return MB_E_UNSUPP;
    s->mem = s->p->ram_ptr ? s->p->ram_ptr(hdr->load_addr, hdr->payload_size) : NULL;
    if (!s->mem) return MB_E_REFUSED;
    mb_slot_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.hdr = *hdr;
    tmp.header_ok = true;
    if (mb_image_check_sig(s->p, &tmp) != MB_OK) return MB_E_SIGNATURE;
    s->hdr = *hdr;
    return MB_OK;
}

static int ram_data(void* ctx, uint32_t off, const void* d, size_t n) {
    ram_sink_t* s = ctx;
    memcpy(s->mem + off, d, n);
    return MB_OK;
}

static int ram_end(void* ctx) {
    ram_sink_t* s = ctx;
    mb_sha256_t h;
    uint8_t got[32];
    mb_sha256_init(&h);
    mb_sha256_update(&h, s->mem, s->hdr.payload_size);
    mb_sha256_final(&h, got);
    return memcmp(got, s->hdr.sha256, 32) ? MB_E_CORRUPT : MB_OK;
}

_Static_assert(offsetof(mb_slot_sink_t, p) == 0 && offsetof(ram_sink_t, p) == 0, "sinks must start with the port");

static void cmd_recv(const mb_port_t* p, int slot, bool force) {
    if (mb_slot_role(p, slot) == MB_ROLE_GOLDEN && !force) {
        put(p, "golden is the recovery image: 'recv g force' (and it must be a newer version)\n");
        return;
    }
    mb_slot_sink_t sink = { .p = p, .slot = slot };
    mb_recv_t r = { .ctx = &sink, .getc = io_getc, .puts = io_puts, .max_frame = 1024, .where = mb_slot_name(p, slot),
                    .begin = mb_sink_slot_begin, .data = mb_sink_slot_data, .end = mb_sink_slot_end };
    mb_recv(&r, NULL);
}

static void cmd_ramboot(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, const char* args) {
    if (!p->ram_ptr || !p->launch_ram) { put(p, "this port can't run RAM images\n"); return; }
    ram_sink_t sink = { .p = p };
    mb_recv_t r = { .ctx = &sink, .getc = io_getc, .puts = io_puts, .max_frame = 1024, .where = "ram",
                    .begin = ram_begin, .data = ram_data, .end = ram_end };
    mb_image_hdr_t hdr;
    if (mb_recv(&r, &hdr) != MB_OK) return;
    mb_printf(p, "starting %s from RAM at 0x%08lx...\n", hdr.name, (unsigned long)hdr.load_addr);
    if (p->console_close) p->console_close();
    int rc = mb_boot_ram(p, log, cfg, &hdr, args);
    mb_printf(p, "launch failed (%d)\n", rc);
}

#if MB_FEAT_CFG_FILE
// one text buffer for both config commands (they never run at the same time)
static char cfg_text[MB_CFG_MAX + 1];

// config text upload: "MB CFG READY <max>\n", then u16 length + text + u32 crc
static void cmd_cfg_recv(const mb_port_t* p, mb_config_t* cfg) {
    char* text = cfg_text;
    mb_printf(p, "MB CFG READY %d\n", MB_CFG_MAX);
    uint8_t h[2], t[4];
    for (int i = 0; i < 2; i++) { int c = getc_wait(p, 5000); if (c < 0) { put(p, "MB ERR timeout\n"); return; } h[i] = (uint8_t)c; }
    size_t len = (size_t)h[0] | (size_t)h[1] << 8;
    if (len > MB_CFG_MAX) { put(p, "MB ERR too long\n"); return; }
    for (size_t i = 0; i < len; i++) { int c = getc_wait(p, 2000); if (c < 0) { put(p, "MB ERR timeout\n"); return; } text[i] = (char)c; }
    for (int i = 0; i < 4; i++) { int c = getc_wait(p, 2000); if (c < 0) { put(p, "MB ERR timeout\n"); return; } t[i] = (uint8_t)c; }
    uint32_t crc = (uint32_t)t[0] | (uint32_t)t[1] << 8 | (uint32_t)t[2] << 16 | (uint32_t)t[3] << 24;
    if (mb_crc32(0, text, len) != crc) { put(p, "MB ERR crc\n"); return; }
    mb_config_t c;
    char err[64];
    if (mb_config_parse(p, text, len, &c, err, sizeof(err)) != MB_OK) { mb_printf(p, "MB ERR %s\n", err); return; }
    if (c.errors) {mb_printf(p,"MB ERR config: %s\n",err);return;}
    if (mb_config_validate_save(p, text, len,err,sizeof err) != MB_OK) { put(p, "MB ERR flash\n"); return; }
    mb_config_load(p, cfg);
    put(p, "MB DONE\n");
}

static void cmd_cfg(const mb_port_t* p, mb_config_t* cfg, int argc, char** argv) {
    char* text = cfg_text;
    const char* sub = argc > 1 ? argv[1] : "show";
    if (!strcmp(sub, "show")) {
        uint32_t seq;
        int n = mb_config_read_text(p, text, sizeof(cfg_text), &seq);
        if (n < 0) { put(p, "(no config in flash: built-in entries)\n"); cmd_entries(p, cfg); return; }
        mb_printf(p, "# config seq %lu, %d bytes\n", (unsigned long)seq, n);
        p->write(text, (size_t)n);
        if (n && text[n - 1] != '\n') put(p, "\n");
    } else if (!strcmp(sub, "recv")) {
        cmd_cfg_recv(p, cfg);
    } else if (!strcmp(sub, "reset")) {
        int rc = mb_config_save(p, "# built-in\n", 11);         // no entries: the built-in ones apply
        mb_config_load(p, cfg);
        mb_printf(p, "%s\n", rc == MB_OK ? "config reset to built-in" : "flash write FAILED");
    } else {
        put(p, "cfg show | cfg recv (from mbtool) | cfg reset\n");
    }
}
#else
static void cmd_cfg(const mb_port_t* p, mb_config_t* cfg, int argc, char** argv) {
    (void)argc; (void)argv;
    put(p, "this build has no config file: the built-in entries apply\n");
    cmd_entries(p, cfg);
}
#endif
#endif /* MB_FEAT_SHELL */

// ---------------------------------------------------------------------------
// Boot menu
// ---------------------------------------------------------------------------

typedef enum { MENU_AUTO, MENU_BOOT, MENU_EDIT, MENU_SHELL, MENU_REBOOT, MENU_ROM } menu_result_t;

static void draw_menu(const mb_port_t* p, const mb_bcl_t* log, const mb_config_t* cfg, mb_slot_info_t* info, int sel, int dflt, int secs) {
    mb_printf(p, "\033[H\033[2J\033[1;38;5;208m  MimiBoot-Night %s \"%s\"\033[0m   %s, %s\n\n", MIMIBOOT_VERSION, MIMIBOOT_CODENAME,
              p->name, p->reset_reason ? p->reset_reason() : "");
    for (int i = 0; i < cfg->n; i++) {
        const mb_entry_t* e = &cfg->e[i];
        int slot = e->slot == MB_SLOT_AB ? (log->cur.active < 2 ? log->cur.active : MB_SLOT_A) : e->slot;
        bool has = slot < p->layout->n_slots && info[slot].header_ok;
        mb_printf(p, "%s %d  %-28.28s", i == sel ? "\033[7m>" : " ", i + 1, e->title);
        if (!has) put(p, "\033[2m");
        if (has) {
            char v[16];
            fmt_version(v, sizeof(v), info[slot].hdr.version);
            mb_printf(p, " %-3s %-16.16s %-8s %s", mb_slot_name(p, e->slot), info[slot].hdr.name, v, state_name(log->cur.slot[slot].state));
        } else {
            mb_printf(p, " %-3s (empty)", mb_slot_name(p, e->slot));
        }
        mb_printf(p, "%s\033[0m\n", i == dflt ? "  <- default" : "");
    }
    put(p, MB_FEAT_SHELL ? "\n   e  edit args    c  command line    r  reboot" : "\n   e  edit args    r  reboot");
    put(p, p->reboot_rom ? "    u  USB bootloader\n\n" : "\n\n");
    if (secs >= 0) mb_printf(p, "   booting %s in %d s, any key stops the countdown   ", cfg->e[dflt].name, secs);
    else put(p, "   up/down + enter, or 1-8                                    ");
}

static menu_result_t menu(const mb_port_t* p, const mb_bcl_t* log, const mb_config_t* cfg, mb_slot_info_t* info, int dflt, int* pick) {
    int sel = dflt >= 0 && dflt < cfg->n ? dflt : 0;
    int secs = dflt >= 0 && dflt < cfg->n ? (cfg->timeout_s < 0 ? MB_MENU_SECS : cfg->timeout_s) : -1;
    if (secs == 0) secs = 1;                            // the menu was asked for: show it at least briefly
    draw_menu(p, log, cfg, info, sel, dflt, secs);
    for (;;) {
        int c = getc_wait(p, 1000);
        if (c < 0) {
            if (secs > 0 && --secs == 0) { *pick = dflt; return MENU_AUTO; }
            if (secs > 0) draw_menu(p, log, cfg, info, sel, dflt, secs);
            continue;
        }
        secs = -1;
        if (c == 0x1B) {                                    // ESC [ A / B
            int a = getc_wait(p, 50), b = getc_wait(p, 50);
            if (a == '[' && b == 'A') sel = (sel + cfg->n - 1) % cfg->n;
            if (a == '[' && b == 'B') sel = (sel + 1) % cfg->n;
        } else if (c >= '1' && c < '1' + cfg->n) { *pick = c - '1'; return MENU_BOOT; }
        else if (c == '\r' || c == '\n') { *pick = sel; return MENU_BOOT; }
        else if (c == 'e' || c == 'E') { *pick = sel; return MENU_EDIT; }
        else if (MB_FEAT_SHELL && (c == 'c' || c == 'C')) return MENU_SHELL;
        else if (c == 'r' || c == 'R') return MENU_REBOOT;
        else if (c == 'u' || c == 'U') return MENU_ROM;
        draw_menu(p, log, cfg, info, sel, dflt, secs);
    }
}

#if MB_FEAT_SHELL
// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

static const char* help =
    "  ls                      slots and their state\n"
    "  entries                 config entries (* = default)\n"
    "  info <slot>             image header and log entry\n"
    "  verify [slot]           SHA-256 + signature check (all slots when none given)\n"
    "  boot <entry|slot> [args...]   boot it now (a new A/B image boots as a trial)\n"
    "  boot <slot> force       boot an image with a good hash/signature whatever its state\n"
    "  once <entry> [args...]  boot it on the next reset only (args for that boot), then reboot\n"
    "  confirm|reject <slot>   mark GOOD (+active) | BAD\n"
    "  retry <slot> [n]        give an image n more tries\n"
    "  recv <slot>             install an image sent by mbtool (install)\n"
    "  ramboot [args...]       receive a RAM image (mbtool ramboot) and start it, flash untouched\n"
    "  erase <slot>            wipe a slot (asks first)\n"
    "  cfg show|recv|reset     the boot config\n"
#if MB_FEAT_SHELL_DIAG
    "  keys                    signature policy and trusted keys\n"
    "  log | layout            boot log state | flash map\n"
#endif
    "  capabilities           query OS services and supported CPU modes\n"
    "  default <entry>        save the default boot entry\n"
    "  request <mode>         restart/menu/config/flash/bootsel\n"
    "  profile <entry> <cpu0> <cpu1>   one-shot topology, then reboot\n"
#if MB_FEAT_SHELL_DIAG
    "  md <off> [len]          dump flash        sha <off> <len>   hash a flash range\n"
#endif
    "  menu | reboot | bootsel | exit\n";

// returns true for "exit" (boot normally), false for "menu"
static bool shell(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, mb_slot_info_t* info) {
    put(p, "\nMimiBoot-Night command line. 'help' for commands.\n");
    char line[LINE_MAX], copy[LINE_MAX];
    char* argv[8];
    for (;;) {
        put(p, "\033[38;5;208mmimiboot\033[0m> ");
        int got = read_line(p, line, sizeof(line), NULL);
        if (got == -2) { put(p, "\nidle: leaving flash mode, booting normally\n"); return true; }
        if (got < 0) continue;
        memcpy(copy, line, sizeof(copy));
        int argc = split(line, argv, 8);
        if (!argc) continue;
        const char* cmd = argv[0];
        int slot = argc > 1 ? mb_slot_parse(p, argv[1]) : -1;
        bool needs_slot = !strcmp(cmd, "info") || !strcmp(cmd, "confirm") || !strcmp(cmd, "reject") || !strcmp(cmd, "retry") ||
                          !strcmp(cmd, "recv") || !strcmp(cmd, "erase");
        if (needs_slot && slot < 0) {
            mb_printf(p, "%s: which slot? (", cmd);
            for (int i = 0; i < p->layout->n_slots; i++) mb_printf(p, "%s%s", i ? ", " : "", mb_slot_name(p, i));
            put(p, ")\n");
            continue;
        }
        refresh_headers(p, info);
        if (!strcmp(cmd, "help") || !strcmp(cmd, "?")) put(p, help);
        else if (!strcmp(cmd, "ls")) cmd_ls(p, log, info);
        else if (!strcmp(cmd, "entries")) cmd_entries(p, cfg);
        else if (!strcmp(cmd, "info")) cmd_info(p, log, info, slot);
        else if (!strcmp(cmd, "verify")) {
            if (slot >= 0) cmd_verify(p, info, slot);
            else for (int i = 0; i < p->layout->n_slots; i++) cmd_verify(p, info, i);
        } else if (!strcmp(cmd, "boot")) {
            if (argc < 2) { put(p, "boot <entry|slot> [args...]\n"); continue; }
            int e = mb_config_find(cfg, argv[1]);
            if (argc > 2 && !strcmp(argv[2], "force") && slot >= 0) boot_slot(p, log, cfg, info, slot, true, NULL);
            else if (e >= 0) boot_entry(p, log, cfg, info, e, argc > 2 ? rest(copy, 2) : NULL);
            else if (slot >= 0) boot_slot(p, log, cfg, info, slot, false, rest(copy, 2));
            else mb_printf(p, "no entry or slot '%s'\n", argv[1]);
#ifdef MB_BOOT_DIAGNOSTICS
        } else if (!strcmp(cmd,"trace")) {
            const volatile uint32_t *v=(const volatile uint32_t*)0x401000bcu;
            char row[10];row[8]='\n';row[9]=0;
            for(unsigned j=0;j<5;j++){uint32_t x=v[j];for(unsigned k=0;k<8;k++)row[k]="0123456789abcdef"[(x>>(28-k*4))&15];put(p,row);}
#endif
        } else if (!strcmp(cmd, "once")) {
            int e = argc > 1 ? mb_config_find(cfg, argv[1]) : -1;
            mb_bcl_rec_t r = log->cur;
            if (e >= 0) {
                r.request = MB_REQ_ENTRY_ONCE;
                r.request_arg = (uint8_t)e;
                snprintf(r.args, sizeof(r.args), "%s", argc > 2 ? rest(copy, 2) : "");
            } else if (slot >= 0) {
                r.request = MB_REQ_BOOT_ONCE;
                r.request_arg = (uint8_t)slot;
            } else { put(p, "once <entry|slot> [args...]\n"); continue; }
            if (mb_bcl_commit(log, &r) == MB_OK && p->reboot) { put(p, "rebooting for one boot of it\n"); p->reboot(); }
        } else if (!strcmp(cmd, "confirm")) {
            if (!info[slot].header_ok) { put(p, "no image\n"); continue; }
            mb_bcl_rec_t r = log->cur;
            r.slot[slot].state = MB_ST_GOOD;
            r.slot[slot].bad_reason = MB_BAD_NONE;
            r.slot[slot].tries_left = 0;
            r.slot[slot].image_id = mb_image_id(&info[slot].hdr);
            if (mb_slot_role(p, slot) == MB_ROLE_AB) {
                r.active = (uint8_t)slot;
                if (info[slot].hdr.security_version > r.min_security) r.min_security = info[slot].hdr.security_version;
            }
            if (r.last_slot == slot) r.strikes = 0;
            mb_printf(p, "%s\n", mb_bcl_commit(log, &r) == MB_OK ? "confirmed" : "log write FAILED");
        } else if (!strcmp(cmd, "reject")) commit_state(p, log, slot, MB_ST_BAD, MB_BAD_REJECTED, 0);
        else if (!strcmp(cmd, "retry")) {
            int n = argc > 2 ? atoi(argv[2]) : MB_DEFAULT_TRIES;
            if (n < 1 || n > 255) n = MB_DEFAULT_TRIES;
            commit_state(p, log, slot, mb_slot_role(p, slot) == MB_ROLE_AB ? MB_ST_TRIAL : MB_ST_NEW, MB_BAD_NONE, n);
        } else if (!strcmp(cmd, "recv")) cmd_recv(p, slot, argc > 2 && !strcmp(argv[2], "force"));
        else if (!strcmp(cmd, "ramboot")) cmd_ramboot(p, log, cfg, rest(copy, 1));
        else if (!strcmp(cmd, "erase")) {
            mb_printf(p, "erase slot %s? type 'yes': ", mb_slot_name(p, slot));
            char ans[8];
            if (read_line(p, ans, sizeof(ans), NULL) < 0 || strcmp(ans, "yes")) { put(p, "kept\n"); continue; }
            int rc = mb_slot_erase(p, slot, p->layout->slot[slot].size - MB_IMG_PAYLOAD_OFF);
            mb_printf(p, "%s\n", rc == MB_OK ? "erased" : "erase FAILED");
        } else if (!strcmp(cmd, "cfg")) cmd_cfg(p, cfg, argc, argv);
#if MB_FEAT_SHELL_DIAG
        else if (!strcmp(cmd, "keys")) cmd_keys(p);
        else if (!strcmp(cmd, "log")) cmd_log(p, log);
        else if (!strcmp(cmd, "layout")) cmd_layout(p);
        else if (!strcmp(cmd, "md")) cmd_md(p, argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 0) : 0, argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 0) : 256);
        else if (!strcmp(cmd, "sha")) {
            if (argc < 3) { put(p, "sha <offset> <length>\n"); continue; }
            cmd_sha(p, (uint32_t)strtoul(argv[1], NULL, 0), (uint32_t)strtoul(argv[2], NULL, 0));
        }
#endif
        else if (!strcmp(cmd, "menu")) return false;
        else if (!strcmp(cmd, "exit")) return true;
        else if (!strcmp(cmd, "reboot")) { if (p->reboot) p->reboot(); }
        else if (!strcmp(cmd, "bootsel")) { if (p->reboot_rom) p->reboot_rom(); }

        else if(!strcmp(cmd,"capabilities")){mb_printf(p,"api %u caps 0x%08lx target %s primary %s\n",MB_CONTROL_API_VERSION,(unsigned long)mb_control_caps(p),p->target,arch_name(p->arch));}
        else if(!strcmp(cmd,"default")){int rc=argc==2?mb_config_set_default(p,argv[1]):MB_E_BADARG;if(!rc)mb_config_load(p,cfg);mb_printf(p,"default: %d\n",rc);}
        else if(!strcmp(cmd,"request")||!strcmp(cmd,"profile")){
            mb_control_request_t q={0};q.version=1;q.size=sizeof q;bool valid=true;
            if(!strcmp(cmd,"profile")){
                valid=argc==4;if(valid){q.action=MB_CONTROL_ENTRY;snprintf(q.entry,sizeof q.entry,"%s",argv[1]);q.topology.core0=!strcmp(argv[2],"arm")?MB_ARCH_ARM:!strcmp(argv[2],"riscv")?MB_ARCH_RISCV:255;q.topology.core1=!strcmp(argv[3],"arm")?MB_ARCH_ARM:!strcmp(argv[3],"riscv")?MB_ARCH_RISCV:255;}
            }else{valid=argc==2;if(valid){if(!strcmp(argv[1],"restart"))q.action=MB_CONTROL_RESTART;else if(!strcmp(argv[1],"menu"))q.action=MB_CONTROL_MENU;else if(!strcmp(argv[1],"config"))q.action=MB_CONTROL_CONFIG;else if(!strcmp(argv[1],"flash"))q.action=MB_CONTROL_FLASH;else if(!strcmp(argv[1],"bootsel"))q.action=MB_CONTROL_ROM;else valid=false;}}
            int rc=valid?mb_control_submit(p,&q):MB_E_BADARG;mb_printf(p,"control: %d\n",rc);if(!rc&&p->reboot)p->reboot();
        }
        else if (!strcmp(cmd, "version")) mb_printf(p, "MimiBoot-Night %s \"%s\" on %s (%s)\n", MIMIBOOT_VERSION, MIMIBOOT_CODENAME, p->name, arch_name(p->arch));
        else mb_printf(p, "unknown command '%s' (help)\n", cmd);
    }
}
#endif /* MB_FEAT_SHELL */

void mb_console(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, mb_slot_info_t info[MB_MAX_SLOTS], const mb_plan_t* plan) {
    bool bootable = plan->choice.slot != MB_SLOT_NONE;
    // Wait for someone to open the console. With an image to boot, give up
    // after a while and boot it; with nothing, hand over to the ROM loader
    // so the device can still be flashed.
    uint32_t wait = plan->choice.flash_mode ? MB_FLASH_WAIT_MS : bootable ? 15000 : 120000;
    if (!p->console_open || !p->console_open(wait)) {
        if (bootable) return;                       // the caller boots the normal choice
        if (p->reboot_rom) p->reboot_rom();
        return;
    }
#if MB_FEAT_SHELL                                   /* without a command line both fall back to the menu */
    if (plan->choice.config_mode) {
        if(plan->choice.control_error)mb_printf(p,"control request refused (%d)\n",plan->choice.control_error);
        put(p,"MimiBoot-Night configuration mode (no countdown)\n");
        if(shell(p,log,cfg,info))return;
    }
    if (plan->choice.flash_mode) {
        // Asked for by the running OS: straight to the command line, no
        // countdown; mbtool takes it from here. Idle for 5 min: boot normally.
        mb_printf(p, "\nMB FLASH READY %s %s\n", MIMIBOOT_VERSION, p->name);
        put(p, "MimiBoot flash mode: waiting for mbtool (install / ramboot / cfg push), 'exit' boots normally\n");
        idle_limit_ms = MB_FLASH_IDLE_MS;
        bool leave = shell(p, log, cfg, info);
        idle_limit_ms = 0;
        if (leave) return;
    }
#endif
    if (!bootable) put(p, p->reboot_rom ? "\n\033[33mnothing bootable: install an image (mbtool.py install) or 'u' for the ROM loader\033[0m\n"
                                        : "\n\033[33mnothing bootable: install an image (mbtool.py install)\033[0m\n");
    int dflt = bootable ? cfg->def : -1;
    for (;;) {
        int pick = dflt;
        menu_result_t m = menu(p, log, cfg, info, dflt, &pick);
        put(p, "\n");
        switch (m) {
            case MENU_AUTO:                                 // countdown ran out: the normal boot
                mb_printf(p, "booting %s...\n", cfg->e[pick].name);
                return;
            case MENU_BOOT:
                boot_entry(p, log, cfg, info, pick, NULL);  // returns only if it didn't boot
                put(p, "(press a key)\n");
                getc_wait(p, 60000);
                break;
            case MENU_EDIT: {
                char args[MB_ARGS_MAX];
                mb_printf(p, "args for %s (enter boots, esc cancels):\n> ", cfg->e[pick].name);
                if (read_line(p, args, sizeof(args), cfg->e[pick].args) >= 0) {
                    boot_entry(p, log, cfg, info, pick, args);
                    put(p, "(press a key)\n");
                    getc_wait(p, 60000);
                }
                break;
            }
            case MENU_SHELL:
#if MB_FEAT_SHELL
                if (shell(p, log, cfg, info)) return;
#endif
                break;
            case MENU_REBOOT:
                if (p->reboot) p->reboot();
                return;
            case MENU_ROM:
                if (p->reboot_rom) p->reboot_rom();
                return;
        }
        dflt = -1;              // state may have changed: no countdown on a stale choice
    }
}

#else /* !MB_FEAT_CONSOLE */

void mb_printf(const mb_port_t* p, const char* fmt, ...) { (void)p; (void)fmt; }

// No console: nobody to talk to. With something bootable the caller boots it.
// With nothing: hand over to the chip's own ROM loader so the board can still
// be flashed (STM32 system memory, RP BOOTSEL); without one, wait a second
// (a debugger may be writing a slot) and let mb_main decide again.
void mb_console(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg, mb_slot_info_t info[MB_MAX_SLOTS], const mb_plan_t* plan) {
    (void)log; (void)cfg; (void)info;
    if (plan->choice.slot != MB_SLOT_NONE) return;
    if (p->reboot_rom) p->reboot_rom();
    if (p->time_ms) {
        uint32_t t0 = p->time_ms();
        while (p->time_ms() - t0 < 1000) {}
    }
}

#endif /* MB_FEAT_CONSOLE */

// The default menu is the text console. A port that wants a different UI (the
// watch's graphical menu) sets mb_menu_override at startup.
mb_menu_fn mb_menu_override;

void mb_menu(const mb_port_t* p, mb_bcl_t* log, mb_config_t* cfg,
             mb_slot_info_t info[MB_MAX_SLOTS], const mb_plan_t* plan) {
    if (mb_menu_override) mb_menu_override(p, log, cfg, info, plan);
    else mb_console(p, log, cfg, info, plan);
}
