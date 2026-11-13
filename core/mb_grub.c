/* A bounded declarative GRUB-style grammar. No shell or expression evaluator. */
#include "core/mimiboot.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#if !MB_FEAT_GRUB
/* 0: not GRUB syntax, the caller parses the text as the plain format */
int mb_grub_translate(const char *text, size_t len, char *out, size_t cap, char *err, size_t errcap) {
    (void)text; (void)len; (void)out; (void)cap; (void)err; (void)errcap;
    return 0;
}
#else
static char *trim(char *s) {
    while (*s == ' ' || *s == '\t')
        s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r'))
        s[--n] = 0;
    return s;
}
static int error(char *e, size_t n, int line, const char *why) {
    if (e && n)
        snprintf(e, n, "line %d: %s", line, why);
    return MB_E_BADARG;
}
static bool id_ok(const char *s) {
    size_t n = strlen(s);
    if (!n || n >= 16)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-')
            return false;
    return true;
}
static bool append(char *out, size_t cap, size_t *at, const char *s) {
    size_t n = strlen(s);
    if (*at >= cap || n + 1 >= cap - *at)
        return false;
    memcpy(out + *at, s, n);
    *at += n;
    out[(*at)++] = '\n';
    out[*at] = 0;
    return true;
}
int mb_grub_translate(const char *text, size_t len, char *out, size_t cap, char *err, size_t errcap) {
    if (!text || !out || !cap || len > MB_CFG_MAX)
        return MB_E_BADARG;
    bool grub = false;
    for (size_t i = 0; i < len;) {
        size_t a = i;
        while (a < len && (text[a] == ' ' || text[a] == '\t'))
            a++;
        if ((len - a >= 10 && !memcmp(text + a, "menuentry ", 10)) || (len - a >= 4 && !memcmp(text + a, "set ", 4)))
            grub = true;
        while (i < len && text[i] != '\n')
            i++;
        if (i < len)
            i++;
    }
    if (!grub)
        return 0;
    size_t at = 0;
    out[0] = 0;
    bool in = false;
    int line = 0;
    char buffer[384];
    for (size_t pos = 0; pos < len;) {
        size_t end = pos;
        while (end < len && text[end] != '\n')
            end++;
        size_t n = end - pos;
        line++;
        if (n >= sizeof buffer || memchr(text + pos, 0, n))
            return error(err, errcap, line, "invalid line");
        memcpy(buffer, text + pos, n);
        buffer[n] = 0;
        pos = end < len ? end + 1 : end;
        char *s = trim(buffer);
        if (!*s || *s == '#')
            continue;
        if (!strncmp(s, "menuentry ", 10)) {
            if (in)
                return error(err, errcap, line, "nested menuentry is not supported");
            s = trim(s + 10);
            char *split = s;
            while (*split && *split != ' ' && *split != '\t')
                split++;
            if (!*split)
                return error(err, errcap, line, "menuentry needs a quoted title and {");
            *split++ = 0;
            if (!id_ok(s))
                return error(err, errcap, line, "invalid entry ID");
            char name[32];
            snprintf(name, sizeof name, "entry %s", s);
            if (!append(out, cap, &at, name))
                return MB_E_NOSPACE;
            split = trim(split);
            if (*split++ != '"')
                return error(err, errcap, line, "title must be quoted");
            char title[64];
            size_t j = 0;
            bool closed = false;
            while (*split) {
                char c = *split++;
                if (c == '"') {
                    closed = true;
                    break;
                }
                if (c == '\\') {
                    if (*split != '"' && *split != '\\')
                        return error(err, errcap, line, "invalid quoted escape");
                    c = *split++;
                }
                if (j >= 31)
                    return error(err, errcap, line, "title exceeds 31 characters");
                title[j++] = c;
            }
            title[j] = 0;
            if (!closed || strcmp(trim(split), "{"))
                return error(err, errcap, line, "expected { after title");
            char row[80];
            snprintf(row, sizeof row, "title %s", title);
            if (!append(out, cap, &at, row))
                return MB_E_NOSPACE;
            in = true;
        } else if (!strcmp(s, "}")) {
            if (!in)
                return error(err, errcap, line, "unmatched }");
            in = false;
        } else if (!strncmp(s, "set ", 4)) {
            if (in)
                return error(err, errcap, line, "set is global");
            char *key = trim(s + 4);
            char *eq = strchr(key, '=');
            if (!eq)
                return error(err, errcap, line, "set requires =");
            *eq++ = 0;
            key = trim(key);
            char *value = trim(eq);
            if (strcmp(key, "default") && strcmp(key, "timeout"))
                return error(err, errcap, line, "unknown global setting");
            char row[96];
            if (strlen(value) > 64)
                return error(err, errcap, line, "setting too long");
            snprintf(row, sizeof row, "%s %s", key, value);
            if (!append(out, cap, &at, row))
                return MB_E_NOSPACE;
        } else {
            if (!in)
                return error(err, errcap, line, "entry directive outside a block");
            const char *keys[] = {"slot ", "arch ", "args ", "topology "};
            bool known = false;
            for (unsigned k = 0; k < 4; k++)
                if (!strncmp(s, keys[k], strlen(keys[k])))
                    known = true;
            if (!known)
                return error(err, errcap, line, "unknown entry directive");
            if (!append(out, cap, &at, s))
                return MB_E_NOSPACE;
        }
    }
    if (in)
        return error(err, errcap, line, "unclosed menuentry");
    return 1;
}

#endif /* MB_FEAT_GRUB */
