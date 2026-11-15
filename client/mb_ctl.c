/*
 * mbctl: the bootloader as shell commands (see mb_ctl.h)
 */
#include "client/mb_ctl.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    mb_ctl_print_t print;
    void *ctx;
} out_t;

static void say(const out_t *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(const out_t *o, const char *fmt, ...) {
    char line[120];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    o->print(o->ctx, line);
}

static const char *err_text(int rc) {
    switch (rc) {
    case MB_E_IO: return "flash error";
    case MB_E_BADARG: return "bad argument";
    case MB_E_CORRUPT: return "corrupt";
    case MB_E_NOSPACE: return "no room";
    case MB_E_UNSUPP: return "not supported by this bootloader or board";
    case MB_E_TIMEOUT: return "timed out";
    case MB_E_REFUSED: return "refused";
    case MB_E_SIGNATURE: return "bad or missing signature";
    default: return "failed";
    }
}

static int fail(const out_t *o, const char *what, int rc) {
    say(o, "mbctl: %s: %s\n", what, err_text(rc));
    return rc;
}

static void version_text(uint32_t v, char *out, size_t n) {
    snprintf(out, n, "%u.%u.%u", (unsigned)MB_VERSION_MAJOR(v), (unsigned)MB_VERSION_MINOR(v), (unsigned)MB_VERSION_PATCH(v));
}

static const char *state_text(int st) {
    static const char *names[] = {"empty", "new", "trial", "good", "bad"};
    return st >= 0 && st <= MB_ST_BAD ? names[st] : "?";
}

static const char *bad_text(int why) {
    static const char *names[] = {"", "header", "hash", "never confirmed", "below the rollback floor", "not for this chip",
                                  "wouldn't start", "rejected", "older golden", "signature", "faulted while checked"};
    return why >= 0 && why <= MB_BAD_FAULT ? names[why] : "?";
}

static const char *end_text(int reason) {
    static const char *names[] = {"unknown (a reset nobody announced)", "power-on (a fresh start)", "reboot", "reboot for an update",
                                  "power-off", "panic", "fault", "watchdog", "the bootloader reset"};
    return reason >= 0 && reason <= MB_END_LOADER ? names[reason] : "?";
}

static const char *kind_text(int kind) {
    static const char *names[] = {"-", "a normal boot", "a trial boot", "a one-time boot", "a fallback (the preferred image failed)",
                                  "the golden image", "picked in the menu", "a chosen entry"};
    return kind >= 0 && kind <= MB_KIND_ENTRY ? names[kind] : "?";
}

static const char *via_text(int via) {
    return via == MB_VIA_MAILBOX ? "through RAM (no flash write)"
           : via == MB_VIA_FLASH ? "through the boot log in flash"
                                 : "through the boot log (old one-shot requests: menu, entry, slot, flash, rom)";
}

static void print_end(const out_t *o, const char *label, const mb_end_t *e) {
    char where[40] = "";
    if (e->reason == MB_END_PANIC || e->reason == MB_END_FAULT)
        snprintf(where, sizeof(where), " at 0x%08lx", (unsigned long)e->pc);
    say(o, "%-9s %s%s%s%s%s\n", label, end_text(e->reason), where, e->msg[0] ? ": \"" : "", e->msg, e->msg[0] ? "\"" : "");
    if (e->reason == MB_END_FAULT)
        say(o, "          lr 0x%08lx, info 0x%08lx\n", (unsigned long)e->lr, (unsigned long)e->info);
}

static int cmd_status(const out_t *o) {
    mb_client_loader_t li;
    int lrc = mb_client_loader_info(&li);
    char v[16];
    if (lrc == MB_OK) {
        version_text(li.version, v, sizeof(v));
        say(o, "loader    MimiBoot %s on %s (%s), handoff v%d\n", v, li.board, li.target, li.handoff_version);
        if (li.boot_ms)
            say(o, "          the boot took %lu ms\n", (unsigned long)li.boot_ms);
    } else {
        say(o, "loader    %s (%s): no handoff this boot, so only what flash says\n", li.board ? li.board : "?",
            li.target ? li.target : "?");
    }
    mb_client_status_t st;
    int rc = mb_client_status(&st);
    if (rc != MB_OK)
        return fail(o, "status", rc);
    if (st.slot == MB_SLOT_NONE) {
        say(o, "running   not from a slot (a debugger, or a RAM image without a handoff)\n");
    } else {
        version_text(st.version, v, sizeof(v));
        mb_client_slot_t si;
        mb_client_slot_info(st.slot, &si);
        say(o, "running   slot %s: \"%s\" %s (security %lu), %s\n", si.name, st.name, v,
            (unsigned long)st.security_version, kind_text(st.last_kind));
        const char *args = mb_client_args();
        if (st.entry[0])
            say(o, "          entry '%s'%s%s%s\n", st.entry, args[0] ? ", args \"" : "", args, args[0] ? "\"" : "");
    }
    if (st.state == MB_ST_TRIAL)
        say(o, "trial     not confirmed: %d boot%s left, then the previous image ('mbctl confirm' when it works)\n",
            st.tries_left, st.tries_left == 1 ? "" : "s");
    if (st.strikes)
        say(o, "crashes   %d in a row (the crash-loop guard counts them)\n", st.strikes);
    mb_end_t e;
    if (mb_client_last_end(&e) == MB_OK)
        print_end(o, "previous", &e);
    say(o, "floor     security %lu (nothing older boots)\n", (unsigned long)st.min_security);
    say(o, "requests  %s\n", via_text(mb_client_transport()));
    return MB_OK;
}

static int cmd_slots(const out_t *o) {
    say(o, "slot     image                            version     sec  state\n");
    for (int i = 0;; i++) {
        mb_client_slot_t s;
        if (mb_client_slot_info(i, &s) != MB_OK)
            break;
        static const char *roles[] = {"", "", "golden", "aux", "bootloader"};
        const char *role = s.role <= MB_ROLE_STAGE1 ? roles[s.role] : "";
        char v[16] = "-", state[48];
        if (!s.present) {
            say(o, "%-3s %c%c  (empty)%*s%s\n", s.name, ' ', ' ', 41, "", role);
            continue;
        }
        version_text(s.version, v, sizeof(v));
        snprintf(state, sizeof(state), "%s%s%s%s", state_text(s.state), s.state == MB_ST_BAD ? " (" : "",
                 s.state == MB_ST_BAD ? bad_text(s.bad_reason) : "", s.state == MB_ST_BAD ? ")" : "");
        say(o, "%-3s %c%c  %-32s %-11s %3lu  %s%s%s%s\n", s.name, s.running ? '>' : ' ', s.active ? '*' : ' ', s.image_name,
            v, (unsigned long)s.security_version, state, s.below_floor ? ", below the floor" : "", role[0] ? ", " : "", role);
    }
    say(o, "(> running, * preferred A/B image)\n");
    return MB_OK;
}

static int cmd_entries(const out_t *o) {
    mb_client_entry_t e[8];
    int n = mb_client_entries(e, 8);
    if (n < 0)
        return fail(o, "entries", n);
    if (n == 0)
        say(o, "no boot config: the built-in entries apply (os = the A/B pair, recovery = golden)\n");
    for (int i = 0; i < n; i++) {
        char slot[8];
        snprintf(slot, sizeof(slot), "%s", e[i].slot == MB_SLOT_AB ? "a/b" : "");
        if (!slot[0]) {
            mb_client_slot_t s;
            if (mb_client_slot_info(e[i].slot, &s) == MB_OK)
                snprintf(slot, sizeof(slot), "%s", s.name);
        }
        say(o, "%c %-15s %-32s %s\n", e[i].is_default ? '*' : ' ', e[i].name, e[i].title, slot);
    }
    return MB_OK;
}

static int cmd_info(const out_t *o) {
    mb_client_loader_t li;
    int rc = mb_client_loader_info(&li);
    if (rc != MB_OK)
        return fail(o, "info (needs this boot's handoff)", rc);
    static const char *names[] = {"ed25519", "ecdsa-p256", "lms", "signatures-required", "anti-rollback", "trial-boots",
                                  "trial-watchdog", "crash-guard", "console", "shell", "uploads", "smp", "boot-config",
                                  "signed-config", "console-lock", "encrypted-images", "boot-record", "two-stage",
                                  "protected-floor", "boot-lock", "debug-lock", "key-revocation", "ram-images",
                                  "mcuboot-images", "raw-images", "scrub-ram", "fault-hardening", "control",
                                  "mailbox", "usb-console"};
    char v[16];
    version_text(li.version, v, sizeof(v));
    say(o, "MimiBoot %s, %s / %s, %d slots, handoff v%d\n", v, li.board, li.target, li.n_slots, li.handoff_version);
    if (li.handoff_version < 2) {
        say(o, "built with: (an older bootloader: v2 handoffs list it)\n");
    } else {
        char line[100] = "built with:";
        for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            if (!(li.features & (1ull << i)))
                continue;
            if (strlen(line) + strlen(names[i]) + 2 > 78) {
                say(o, "%s\n", line);
                snprintf(line, sizeof(line), "           ");
            }
            strncat(line, " ", sizeof(line) - strlen(line) - 1);
            strncat(line, names[i], sizeof(line) - strlen(line) - 1);
        }
        say(o, "%s\n", line);
    }
    say(o, "requests: %s\n", via_text(mb_client_transport()));
    return MB_OK;
}

// "menu" | "config" | "flash" | "rom" | "entry NAME [ARGS..]" | "slot S [ARGS..]" -> a request
static int target(const out_t *o, int argc, char **argv, int *used, unsigned *action, const char **name, char *args,
                  size_t cap) {
    *used = 0;
    *name = NULL;
    args[0] = 0;
    if (argc < 1)
        return MB_E_BADARG;
    static const struct { const char *word; unsigned action; } simple[] = {
        {"menu", MB_CONTROL_MENU}, {"config", MB_CONTROL_CONFIG}, {"flash", MB_CONTROL_FLASH}, {"rom", MB_CONTROL_ROM}};
    for (unsigned i = 0; i < 4; i++)
        if (!strcmp(argv[0], simple[i].word)) {
            *action = simple[i].action;
            *used = 1;
            return MB_OK;
        }
    if (strcmp(argv[0], "entry") && strcmp(argv[0], "slot"))
        return MB_E_BADARG;
    if (argc < 2) {
        say(o, "mbctl: %s needs a name\n", argv[0]);
        return MB_E_BADARG;
    }
    *action = argv[0][0] == 'e' ? MB_CONTROL_ENTRY : MB_CONTROL_SLOT;
    *name = argv[1];
    int i = 2;
    for (; i < argc && strcmp(argv[i], "--") && strcmp(argv[i], "--flash"); i++) {
        if (strlen(args) + strlen(argv[i]) + 2 > cap)
            return MB_E_NOSPACE;
        if (args[0])
            strcat(args, " ");
        strcat(args, argv[i]);
    }
    *used = i;
    return MB_OK;
}

static void why_text(int argc, char **argv, int from, char *out, size_t cap) {
    out[0] = 0;
    for (int i = from; i < argc; i++) {
        if (!strcmp(argv[i], "--"))
            continue;
        if (strlen(out) + strlen(argv[i]) + 2 > cap)
            break;
        if (out[0])
            strcat(out, " ");
        strcat(out, argv[i]);
    }
}

static int queue(const out_t *o, int argc, char **argv, bool flash, int *used) {
    unsigned action;
    const char *name;
    char args[MB_ARGS_MAX];
    int rc = target(o, argc, argv, used, &action, &name, args, sizeof(args));
    if (rc != MB_OK)
        return rc;
    rc = mb_client_next(action, name, args[0] ? args : NULL, flash ? MB_VIA_FLASH : MB_VIA_AUTO);
    if (rc < 0)
        return fail(o, "request", rc);
    say(o, "next boot: %s%s%s, %s\n", argv[0], name ? " " : "", name ? name : "", via_text(rc));
    return MB_OK;
}

static int slot_arg(const out_t *o, const char *s) {
    for (int i = 0;; i++) {
        mb_client_slot_t si;
        if (mb_client_slot_info(i, &si) != MB_OK)
            break;
        if (!strcmp(si.name, s) || (s[0] >= '0' && s[0] <= '9' && !s[1] && s[0] - '0' == i))
            return i;
    }
    say(o, "mbctl: no slot '%s' ('mbctl slots' lists them)\n", s);
    return -1;
}

static int help(const out_t *o) {
    static const char *lines[] = {
        "mbctl status                  what runs, how the last run ended, how requests travel",
        "mbctl slots | entries | info  the slots, the boot config's entries, the bootloader",
        "mbctl last                    how the previous run ended",
        "mbctl confirm                 this image works (ends its trial)",
        "mbctl reboot [TARGET] [-- why]  TARGET: menu, config, flash, rom, entry NAME [ARGS], slot S [ARGS]",
        "mbctl next TARGET [--flash]   the same for the next reset (--flash: survives a power cut)",
        "mbctl rollback | active SLOT  prefer the other / that confirmed A/B image",
        "mbctl reject SLOT | vacate SLOT   mark it bad / empty it",
        "mbctl default ENTRY           set the boot config's default",
        "mbctl poweroff [why]          off, where the chip can",
    };
    for (unsigned i = 0; i < sizeof(lines) / sizeof(lines[0]); i++)
        say(o, "%s\n", lines[i]);
    return MB_OK;
}

int mb_ctl(int argc, char **argv, mb_ctl_print_t print, void *ctx) {
    out_t o = {print, ctx};
    if (argc > 0 && !strcmp(argv[0], "mbctl")) {
        argc--;
        argv++;
    }
    const char *cmd = argc ? argv[0] : "status";
    int n = argc - 1;
    char **a = argv + 1;
    int rc, used;
    char why[48];
    if (!strcmp(cmd, "status"))
        return cmd_status(&o);
    if (!strcmp(cmd, "slots"))
        return cmd_slots(&o);
    if (!strcmp(cmd, "entries"))
        return cmd_entries(&o);
    if (!strcmp(cmd, "info"))
        return cmd_info(&o);
    if (!strcmp(cmd, "last")) {
        mb_end_t e;
        if ((rc = mb_client_last_end(&e)) != MB_OK)
            return fail(&o, "last (needs a v2 handoff: OS_HOOKS)", rc);
        print_end(&o, "previous", &e);
        return MB_OK;
    }
    if (!strcmp(cmd, "confirm")) {
        if ((rc = mb_client_confirm()) != MB_OK)
            return fail(&o, "confirm", rc);
        say(&o, "confirmed: this image is the one to come back to\n");
        return MB_OK;
    }
    if (!strcmp(cmd, "next")) {
        bool flash = n && !strcmp(a[n - 1], "--flash");
        if ((rc = queue(&o, n, a, flash, &used)) == MB_E_BADARG && !used)
            say(&o, "mbctl next: menu, config, flash, rom, entry NAME [ARGS], slot S [ARGS]\n");
        return rc;
    }
    if (!strcmp(cmd, "reboot")) {
        used = 0;
        if (n && strcmp(a[0], "--") && (rc = queue(&o, n, a, false, &used)) != MB_OK) {
            if (!used)
                say(&o, "mbctl reboot: menu, config, flash, rom, entry NAME [ARGS], slot S [ARGS], or -- why\n");
            return rc;
        }
        why_text(n, a, used, why, sizeof(why));
        rc = mb_client_reboot(MB_END_REBOOT, why[0] ? why : NULL);
        return fail(&o, "reboot", rc);
    }
    if (!strcmp(cmd, "poweroff")) {
        why_text(n, a, 0, why, sizeof(why));
        rc = mb_client_poweroff(why[0] ? why : NULL);
        return fail(&o, "poweroff", rc);
    }
    if (!strcmp(cmd, "rollback")) {
        if ((rc = mb_client_rollback()) != MB_OK)
            return fail(&o, "rollback (the other image must be confirmed and at or above the floor)", rc);
        say(&o, "the other A/B image is preferred from the next boot\n");
        return MB_OK;
    }
    if (!strcmp(cmd, "active") || !strcmp(cmd, "reject") || !strcmp(cmd, "vacate")) {
        if (n < 1)
            return fail(&o, cmd, MB_E_BADARG);
        int s = slot_arg(&o, a[0]);
        if (s < 0)
            return MB_E_BADARG;
        rc = cmd[0] == 'a' ? mb_client_set_active(s) : cmd[0] == 'r' ? mb_client_reject(s) : mb_client_vacate(s);
        if (rc != MB_OK)
            return fail(&o, cmd, rc);
        say(&o, "%s %s: done\n", cmd, a[0]);
        return MB_OK;
    }
    if (!strcmp(cmd, "default")) {
        if (n < 1)
            return fail(&o, "default", MB_E_BADARG);
        if ((rc = mb_client_set_default(a[0])) != MB_OK)
            return fail(&o, "default", rc);
        say(&o, "default entry: %s\n", a[0]);
        return MB_OK;
    }
    if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help"))
        return help(&o);
    say(&o, "mbctl: unknown command '%s'\n", cmd);
    help(&o);
    return MB_E_BADARG;
}

int mb_ctl_line(char *line, mb_ctl_print_t print, void *ctx) {
    char *argv[16];
    int argc = 0;
    for (char *p = line; *p && argc < 16;) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            *p++ = 0;
        if (!*p)
            break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            p++;
    }
    return mb_ctl(argc, argv, print, ctx);
}
