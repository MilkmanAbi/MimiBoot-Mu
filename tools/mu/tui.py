"""menuconfig for MimiBoot-Mu.

TuiState is the whole UI as plain data (testable without a terminal); run()
draws it with curses: a header, a breadcrumb, the list on the left, a details
pane on the right (below the list on narrow terminals), warnings, key hints.

  up/down PgUp/PgDn Home/End  move         Enter / Right   open, toggle, edit
  Space   toggle / next choice             Esc / Left / Backspace   back
  /       search options                   ?   full help for the item
  P       presets                          L   flash layout
  B       build                            S   save        Q   quit (asks to save)
"""
from __future__ import annotations

import os
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from .model import Config, Db


@dataclass
class Item:
    kind: str           # section | maker | category | board | menu | option | preset | action | info
    key: str
    label: str
    value: str = ""
    enabled: bool = True


@dataclass
class View:
    kind: str           # makers | categories | boards | main | menu | presets | search | text
    arg: str = ""
    title: str = ""
    lines: list = field(default_factory=list)
    cursor: int = 0
    top: int = 0


class TuiState:
    def __init__(self, db: Db, path: Path, cfg: Config | None = None):
        from . import sizes
        self.db, self.path = db, path
        self.cfg = cfg
        self.dirty = False
        self.message = ""
        self.last_build = None
        self.sizes = sizes.load()
        self.views = [View("main", title="Home")] if cfg else [View("makers", title="Pick a board")]
        self.quit = False
        self.prompt = None          # (option id, current text) while editing a value
        self._fix_cursor()

    # ---- what's on screen -------------------------------------------------
    @property
    def view(self) -> View:
        return self.views[-1]

    def items(self, v: View | None = None) -> list[Item]:
        v = v or self.view
        db = self.db
        if v.kind == "makers":
            out = []
            for m, cats in db.tree().items():
                n = sum(len(b) for b in cats.values())
                out.append(Item("maker", m, db.maker_title(m), f"{n} boards"))
            return out
        if v.kind == "categories":
            cats = db.tree()[v.arg]
            return [Item("category", f"{v.arg}\0{c}", c, f"{len(b)}") for c, b in cats.items()]
        if v.kind == "boards":
            maker, cat = v.arg.split("\0")
            out = []
            for name in db.tree()[maker][cat]:
                t = db.target(name)
                out.append(Item("board", name, name, t.status))
            return out
        if v.kind == "text":
            return [Item("info", str(i), line) for i, line in enumerate(v.lines)]
        if v.kind == "presets":
            return [Item("preset", p.id, p.title) for p in self.cfg.presets()]
        cfg = self.cfg
        if v.kind == "main":
            t = cfg.t
            out = [Item("section", "", "Board"),
                   Item("action", "board", t.name, t.title),
                   Item("section", "", "Start from"),
                   Item("action", "presets", "Presets", "minimal / hobby / product / secure")]
            out.append(Item("section", "", "Features"))
            for mid, title in cfg.menus():
                if mid == "output":
                    continue
                opts = [o for o in cfg.options(mid) if o.kind == "bool"]
                on = sum(1 for o in opts if cfg.effective(o.id))
                out.append(Item("menu", mid, title, f"{on}/{len(opts)} on" if opts else ""))
            out.append(Item("section", "", "Build"))
            if t.build == "mcu":
                out.append(Item("action", "layout", "Show the flash map", "bootloader, log, config and slot addresses"))
            out.append(self._opt_item("OUTPUT_DIR"))
            out.append(self._opt_item("EXPORT_SOURCE"))
            out.append(Item("action", "build", "Build now", str(cfg.output_dir())))
            return out
        if v.kind == "search":
            q = v.arg.lower()
            ids = [o.id for o in cfg.options() if q in (o.id + " " + o.title + " " + o.help).lower()]
            return [self._opt_item(oid) for oid in ids]
        return [self._opt_item(o.id) for o in cfg.options(v.arg)]

    def _opt_item(self, oid) -> Item:
        o = self.db.options[oid]
        en = self.cfg.enabled(oid)
        v = self.cfg.values[oid]
        if o.kind == "bool":
            val = "[x]" if (v and en) else "[ ]"
        elif o.kind == "int":
            val = f"({v})"
        elif o.kind == "choice":
            val = f"<{v}>"
        else:
            val = f'"{v}"' if v else '""'
        return Item("option", oid, o.title, val, en)

    def current(self) -> Item | None:
        its = self.items()
        return its[self.view.cursor] if its and self.view.cursor < len(its) else None

    def details(self) -> list[tuple[str, str]]:
        """the details pane: [(style, text)], style in title / text / label / dim / good / warn / bad"""
        it = self.current()
        v = self.view
        db = self.db
        if not it:
            return []
        out: list[tuple[str, str]] = []
        if it.kind == "maker":
            out += [("title", it.label), ("text", db.makers.get(it.key, {}).get("about", "")), ("text", "")]
            for c, boards in db.tree()[it.key].items():
                out.append(("label", f"{c}  ({len(boards)})"))
            return out
        if it.kind == "category":
            maker, cat = it.key.split("\0")
            out += [("title", cat), ("dim", db.maker_title(maker)), ("text", "")]
            for name in db.tree()[maker][cat]:
                out.append(("text", f"{name:20} {db.target(name).title}"))
            return out
        if it.kind == "board":
            t = db.target(it.key)
            out += [("title", t.title), ("dim", f"{db.maker_title(t.maker)} / {t.category}"), ("text", "")]
            for label, text in t.facts():
                style = "text"
                if label == "tested":
                    style = "good" if t.status in ("hardware", "emulator") else "warn"
                out.append((style, f"{label:8} {text}"))
            out += [("text", ""), ("dim", "Enter picks this board; its defaults fit the chip.")]
            return out
        if it.kind == "preset":
            p = db.presets[it.key]
            out += [("title", p.title), ("text", p.help), ("text", ""), ("label", "sets:")]
            for k, val in p.values.items():
                if k in self.cfg.values:
                    shown = ("on" if val else "off") if isinstance(val, bool) else str(val)
                    out.append(("dim", f"  {k} = {shown}"))
            out += [("text", ""), ("warn", "Enter applies it: every option back to its default first.")]
            return out
        if it.kind == "menu":
            m = db.menu_defs[it.key]
            out += [("title", m.title), ("text", m.help), ("text", "")]
            for o in self.cfg.options(it.key):
                val = self.cfg.effective(o.id)
                shown = ("on" if val else "off") if o.kind == "bool" else str(val)
                out.append(("dim" if not self.cfg.enabled(o.id) else "text", f"  {shown:>10}  {o.title}"))
            return out
        if it.kind == "option":
            o = db.options[it.key]
            cfg = self.cfg
            out += [("title", o.title), ("dim", f"MU_{o.id}" + (f"  ->  {o.macro}" if o.macro else ""))]
            if not cfg.enabled(o.id):
                out.append(("warn", "not selectable: needs " + ", ".join(o.depends)))
            out.append(("text", ""))
            out += [("text", para) for para in (o.help or o.title).split("\n")]
            out.append(("text", ""))
            val = cfg.values[o.id]
            if o.kind == "choice":
                out.append(("label", "choices: " + " | ".join(o.choices)))
            if o.kind == "int" and o.range:
                out.append(("label", f"range: {o.range[0]} .. {o.range[1]}"))
            def show(x):
                return ("on" if x else "off") if o.kind == "bool" else (str(x) if x != "" else "(empty)")
            out.append(("label", f"value: {show(val)}   default: {show(cfg.default(o))}"))
            if cfg.locked(o.id) is not None:
                out.append(("warn", f"fixed to {cfg.locked(o.id)} on this board"))
            from .sizes import cost_text
            cost = cost_text(self.sizes, cfg, o.id)
            if cost:
                out.append(("good", cost))
            return out
        if it.kind == "action":
            texts = {
                "board": (self.cfg.t.title, "Enter picks another board (options that still apply are kept)."),
                "presets": ("Presets", "Start from a ready-made configuration and adjust from there."),
                "layout": ("Flash map", "Where the bootloader, boot log, config and slots sit in flash, and where to link apps."),
                "build": ("Build", f"Saves {self.path} and builds into {self.cfg.output_dir()}."),
            }
            title, text = texts.get(it.key, (it.label, ""))
            out = [("title", title), ("text", text)]
            if it.key == "board":
                out.append(("text", ""))
                out += [("text", f"{label:8} {val}") for label, val in self.cfg.t.facts()]
            return out
        if v.kind == "text":
            return []
        return [("text", it.label)]

    def help_text(self) -> str:
        return "\n".join(t for _, t in self.details())

    def header(self) -> str:
        if not self.cfg:
            return "MimiBoot-Mu  -  pick a board"
        t = self.cfg.t
        return f"MimiBoot-Mu  -  {t.name} ({t.chip_name}, {t.core} core)  -  {self.path.name}{' *' if self.dirty else ''}"

    def breadcrumb(self) -> list[str]:
        out = []
        for v in self.views:
            if v.kind == "main":
                out.append("Home")
            elif v.kind == "makers":
                out.append("Boards")
            elif v.kind == "categories":
                out.append(self.db.maker_title(v.arg))
            elif v.kind == "boards":
                out.append(v.arg.split("\0")[1])
            elif v.kind == "menu":
                out.append(self.db.menu_defs[v.arg].title)
            elif v.kind == "search":
                out.append(f"search '{v.arg}'")
            else:
                out.append(v.title or v.kind)
        return out

    def problems(self):
        return self.cfg.problems() if self.cfg else []

    # ---- keys --------------------------------------------------------------------
    def _selectable(self, it: Item) -> bool:
        return it.kind != "section"

    def _fix_cursor(self, d: int = 1):
        its = self.items()
        if not its:
            return
        c = max(0, min(len(its) - 1, self.view.cursor))
        step = 1 if d >= 0 else -1
        while 0 <= c < len(its) and not self._selectable(its[c]):
            c += step
        if not 0 <= c < len(its):           # ran off the end: search the other way
            c = max(0, min(len(its) - 1, self.view.cursor))
            while 0 <= c < len(its) and not self._selectable(its[c]):
                c -= step
        self.view.cursor = max(0, min(len(its) - 1, c))

    def move(self, d: int):
        its = self.items()
        if not its:
            return
        if abs(d) == 1:
            c = self.view.cursor + d
            while 0 <= c < len(its) and not self._selectable(its[c]):
                c += d
            if 0 <= c < len(its):
                self.view.cursor = c
            return
        self.view.cursor = max(0, min(len(its) - 1, self.view.cursor + d))
        self._fix_cursor(d)

    def select(self, key: str) -> bool:
        """put the cursor on the item with this key"""
        for i, it in enumerate(self.items()):
            if it.key == key:
                self.view.cursor = i
                return True
        return False

    def back(self):
        if len(self.views) > 1:
            self.views.pop()
        elif self.view.kind == "makers" and not self.cfg:
            self.quit = True

    def open(self, view: View):
        self.views.append(view)
        self._fix_cursor()

    def enter(self):
        it = self.current()
        if not it:
            return None
        if it.kind == "maker":
            self.open(View("categories", it.key))
            return None
        if it.kind == "category":
            self.open(View("boards", it.key))
            return None
        if it.kind == "board":
            self.pick_board(it.key)
            return None
        if it.kind == "menu":
            self.open(View("menu", it.key, it.label))
            return None
        if it.kind == "preset":
            self.apply_preset(it.key)
            return None
        if it.kind == "action":
            if it.key == "board":
                self.open(View("makers", title="Pick a board"))
                return None
            if it.key == "presets":
                self.open(View("presets", title="Presets"))
                return None
            return it.key           # the UI layer runs layout / build
        if it.kind == "option":
            return self.activate(it.key)
        return None

    def pick_board(self, name: str):
        old = self.cfg
        self.cfg = Config(self.db, name)
        if old:     # keep what still applies
            for k, v in old.values.items():
                if k in self.cfg.values and k != "BAUD" and self.cfg.locked(k) is None and not self.cfg.trimmed(k):
                    try:
                        self.cfg.set(k, v)
                    except (KeyError, ValueError):
                        pass
        self.dirty = True
        self.views = [View("main", title="Home")]
        self._fix_cursor()
        self.message = f"board: {name}"

    def apply_preset(self, pid: str):
        done = self.cfg.apply_preset(pid)
        self.dirty = True
        self.views = [View("main", title="Home")]
        self._fix_cursor()
        kept = f"; kept off (too big for this chip): {', '.join(self.cfg.preset_kept)}" if self.cfg.preset_kept else ""
        self.message = f"preset {pid}: {len(done)} options set{kept}"

    def activate(self, oid: str, space=False):
        o = self.db.options[oid]
        if not self.cfg.enabled(oid):
            self.message = f"{oid} needs {', '.join(o.depends)}"
            return None
        if self.cfg.locked(oid) is not None:
            self.message = f"{oid} is fixed on this board"
            return None
        if o.kind in ("bool", "choice"):
            self.cfg.toggle(oid)
            self.dirty = True
            return None
        if space:
            return None
        self.prompt = (oid, str(self.cfg.values[oid]))
        return "prompt"

    def space(self):
        it = self.current()
        if it and it.kind == "option":
            self.activate(it.key, space=True)

    def finish_prompt(self, text: str | None):
        oid, _ = self.prompt
        self.prompt = None
        if text is None:
            return
        try:
            self.cfg.set(oid, text)
            self.dirty = True
            self.message = f"{oid} = {self.cfg.values[oid]}"
        except (KeyError, ValueError) as e:
            self.message = str(e)

    def search(self, text: str):
        if text:
            self.open(View("search", text, f"options matching '{text}'"))

    def show_text(self, title: str, lines: list[str]):
        self.open(View("text", title=title, lines=lines))

    def save(self):
        self.cfg.save(self.path)
        self.dirty = False
        self.message = f"saved {self.path}"


# ---------------------------------------------------------------------------
# curses
# ---------------------------------------------------------------------------
UTF = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "").startswith("utf8")
G = {"sep": " › " if UTF else " > ", "full": "█" if UTF else "#", "empty": "░" if UTF else ".",
     "more": "▸" if UTF else ">", "ok": "✓" if UTF else "OK", "vline": "│" if UTF else "|",
     "hline": "─" if UTF else "-"}


def layout_lines(cfg: Config) -> list[str]:
    if cfg.t.build != "mcu":
        return ["RP boards use fixed layouts (2/4/16 MB presets: include/mimiboot/mb_layout.h);",
                "AVR keeps one app at address 0 and the bootloader in the boot section."]
    from . import gen
    try:
        lay = gen.mcu_layout(cfg)
    except Exception as e:      # noqa: BLE001 - shown to the user
        return [f"layout error: {e}"]
    fb = gen.flash_base(cfg)
    total = lay.flash_size
    out = [f"{cfg.t.chip_name}: {total // 1024} KB flash at 0x{fb:08x}", ""]
    for r in lay.regions():
        bar = G["full"] * max(1, round(36 * r.size / total))
        out.append(f"  {r.name:6} 0x{fb + r.offset:08x} {r.size // 1024:6} KB  {bar}")
    return out + [""] + [f"note: {n}" for n in lay.notes]


def bar(used: int, total: int, width: int = 30) -> str:
    n = max(0, min(width, round(width * used / total))) if total else 0
    return G["full"] * n + G["empty"] * (width - n)


def run(db: Db, path: Path):
    try:
        import curses
    except ImportError:
        raise SystemExit("this Python has no curses (Windows: pip install windows-curses). "
                         "The CLI does everything too: python mimiconf.py show / set / preset / build")
    cfg = Config.load(db, path) if path.exists() else None
    st = TuiState(db, path, cfg)
    os.environ.setdefault("ESCDELAY", "25")     # Esc is "back": don't wait a second for a sequence
    if UTF:
        import locale
        locale.setlocale(locale.LC_ALL, "")
    curses.wrapper(lambda scr: _loop(curses, scr, st))
    if st.last_build:
        print(st.last_build)


class _Pal:
    def __init__(self, curses):
        self.c = curses
        self.attr = {k: 0 for k in ("title", "text", "label", "dim", "good", "warn", "bad", "head", "sel", "section", "key")}
        self.attr.update(title=curses.A_BOLD, dim=curses.A_DIM, head=curses.A_REVERSE, sel=curses.A_REVERSE,
                         section=curses.A_BOLD, bad=curses.A_BOLD, warn=curses.A_BOLD, key=curses.A_REVERSE)
        try:
            if curses.has_colors():
                curses.start_color()
                try:
                    curses.use_default_colors()
                    bg = -1
                except curses.error:
                    bg = curses.COLOR_BLACK
                pairs = {"head": (curses.COLOR_BLACK, curses.COLOR_CYAN), "sel": (curses.COLOR_BLACK, curses.COLOR_YELLOW),
                         "title": (curses.COLOR_YELLOW, bg), "section": (curses.COLOR_CYAN, bg),
                         "good": (curses.COLOR_GREEN, bg), "warn": (curses.COLOR_YELLOW, bg), "bad": (curses.COLOR_RED, bg),
                         "label": (curses.COLOR_CYAN, bg), "key": (curses.COLOR_BLACK, curses.COLOR_WHITE)}
                for i, (k, (fg, b)) in enumerate(pairs.items(), start=1):
                    curses.init_pair(i, fg, b)
                    extra = curses.A_BOLD if k in ("title", "section", "bad") else 0
                    self.attr[k] = curses.color_pair(i) | extra
        except curses.error:
            pass

    def __getitem__(self, k):
        return self.attr.get(k, 0)


def _put(scr, y, x, text, width, attr=0):
    if width <= 0:
        return
    try:
        scr.addnstr(y, x, text, width, attr)
    except Exception:           # noqa: BLE001 - writing the bottom-right cell raises in curses
        pass


def _ask(curses, scr, pal, label: str, initial: str = "") -> str | None:
    h, w = scr.getmaxyx()
    curses.curs_set(1)
    buf = list(initial)
    while True:
        scr.move(h - 2, 0)
        scr.clrtoeol()
        _put(scr, h - 2, 1, f"{label}: {''.join(buf)}", w - 2, pal["title"])
        scr.refresh()
        k = scr.get_wch()
        if k in ("\n", "\r", curses.KEY_ENTER):
            curses.curs_set(0)
            return "".join(buf)
        if k in ("\x1b",):
            curses.curs_set(0)
            return None
        if k in (curses.KEY_BACKSPACE, "\b", "\x7f", "\x08"):
            if buf:
                buf.pop()
        elif isinstance(k, str) and k.isprintable():
            buf.append(k)


def _row_text(it: Item, width: int) -> str:
    if it.kind == "option":
        return f" {it.value:<14} {it.label}"
    if it.kind in ("menu", "maker", "category"):
        right = f"{it.value}  {G['more']}" if it.value else G["more"]
        return f" {it.label}".ljust(max(1, width - len(right) - 1)) + right
    if it.kind == "board":
        return f" {it.label}".ljust(max(1, width - 11)) + f"{it.value:>9} "
    if it.kind == "action":
        return f" {it.label}" + (f"   {it.value}" if it.value else "")
    if it.kind == "preset":
        return f" {it.label}"
    return f" {it.label}"


def _draw(curses, scr, st: TuiState, pal):
    scr.erase()
    h, w = scr.getmaxyx()
    v = st.view
    _put(scr, 0, 0, (" " + st.header()).ljust(w), w, pal["head"])
    _put(scr, 1, 1, G["sep"].join(st.breadcrumb()), w - 2, pal["section"])
    probs = st.problems()
    n_probs = min(len(probs), 3)
    msg_rows = 1 if st.message else 0
    body_top, body_bot = 3, h - 2 - n_probs - msg_rows       # rows [body_top, body_bot)
    wide = w >= 100 and v.kind != "text"
    list_w = (w * 11) // 20 if wide else w
    body_h = max(3, body_bot - body_top) if wide else max(3, (body_bot - body_top) * 3 // 5)
    if v.kind == "text":
        body_h = max(3, body_bot - body_top)
    items = st.items()
    if v.cursor < v.top:
        v.top = v.cursor
    if v.cursor >= v.top + body_h:
        v.top = v.cursor - body_h + 1
    for row, it in enumerate(items[v.top:v.top + body_h]):
        i = v.top + row
        y = body_top + row
        if it.kind == "section":
            _put(scr, y, 0, (" " + it.label.upper()).ljust(list_w - 1), list_w - 1, pal["section"])
            continue
        attr = pal["sel"] if (i == v.cursor and v.kind != "text") else 0
        if not it.enabled:
            attr |= pal["dim"]
        if it.kind == "board" and i != v.cursor:
            attr |= pal["good"] if it.value in ("hardware", "emulator") else 0
        _put(scr, y, 0, _row_text(it, list_w - 1).ljust(list_w - 1), list_w - 1, attr)
    # details pane
    det = st.details()
    if wide:
        x0, y0, dw, dh = list_w + 2, body_top, w - list_w - 3, body_bot - body_top
        for y in range(body_top, body_bot):
            _put(scr, y, list_w, G["vline"], 1, pal["dim"])
    else:
        x0, y0, dw, dh = 1, body_top + body_h + 1, w - 2, body_bot - (body_top + body_h + 1)
        if dh > 0:
            _put(scr, body_top + body_h, 0, G["hline"] * w, w - 1, pal["dim"])
    y = y0
    for style, text in det:
        for line in (textwrap.wrap(text, max(10, dw)) or [""]):
            if y >= y0 + dh:
                break
            _put(scr, y, x0, line.ljust(dw), dw, pal[style])
            y += 1
    while y < y0 + dh:
        _put(scr, y, x0, " " * dw, dw)
        y += 1
    # warnings, message, keys
    y = body_bot
    for lvl, m in probs[:3]:
        _put(scr, y, 1, f"{'error' if lvl == 'error' else 'warn '}: {m}", w - 2, pal["bad" if lvl == "error" else "warn"])
        y += 1
    if st.message:
        _put(scr, y, 1, st.message, w - 2, pal["title"])
    keys = (" Up/Dn move  Enter open  Space toggle  Esc back  / search  P presets  L layout  B build  S save  Q quit"
            if w >= 104 else " Enter open  Space toggle  Esc back  / find  P presets  B build  S save  Q quit")
    if not st.cfg:
        keys = " Up/Dn move  Enter open  Esc back  Q quit"
    _put(scr, h - 1, 0, keys.ljust(w), w - 1, pal["key"])
    scr.refresh()


def _loop(curses, scr, st: TuiState):
    curses.curs_set(0)
    scr.keypad(True)
    pal = _Pal(curses)
    while not st.quit:
        _draw(curses, scr, st, pal)
        k = scr.get_wch()
        st.message = ""
        if k in (curses.KEY_UP, "k"):
            st.move(-1)
        elif k in (curses.KEY_DOWN, "j"):
            st.move(1)
        elif k == curses.KEY_PPAGE:
            st.move(-10)
        elif k == curses.KEY_NPAGE:
            st.move(10)
        elif k == curses.KEY_HOME:
            st.move(-10_000)
        elif k == curses.KEY_END:
            st.move(10_000)
        elif k in (curses.KEY_LEFT, "\x1b", "h", curses.KEY_BACKSPACE, "\x7f", "\b"):
            st.back()
        elif k == " ":
            st.space()
        elif k in ("\n", "\r", curses.KEY_ENTER, curses.KEY_RIGHT, "l"):
            act = st.enter()
            if act == "prompt":
                oid, cur = st.prompt
                st.finish_prompt(_ask(curses, scr, pal, st.db.options[oid].title, cur))
            elif act == "layout":
                st.show_text("Flash layout", layout_lines(st.cfg))
            elif act == "build":
                _build(curses, scr, st, pal)
        elif k == "?":
            st.show_text("Help", [line for _, t in st.details()
                                  for line in (textwrap.wrap(t, max(20, scr.getmaxyx()[1] - 4)) or [""])] or ["(no help)"])
        elif k == "/" and st.cfg:
            st.search(_ask(curses, scr, pal, "search") or "")
        elif k in ("p", "P") and st.cfg:
            st.open(View("presets", title="Presets"))
        elif k in ("L",) and st.cfg:
            st.show_text("Flash layout", layout_lines(st.cfg))
        elif k in ("s", "S") and st.cfg:
            st.save()
        elif k in ("b", "B") and st.cfg:
            _build(curses, scr, st, pal)
        elif k in ("q", "Q"):
            if st.dirty and st.cfg:
                ans = _ask(curses, scr, pal, "save changes? (y/n)", "y")
                if ans is None:
                    continue
                if ans.lower().startswith("y"):
                    st.save()
            st.quit = True


def build_report(st: TuiState, info: dict, out: Path) -> list[str]:
    lines = [f"{G['ok']} built {st.cfg.board}", f"  -> {out}", ""]
    used, region = info.get("flash_used"), info.get("flash_region")
    if used and region:
        lines.append(f"  flash  [{bar(used, region)}] {used:>7} / {region} bytes  {100 * used // region}%")
    if "ram_used" in info:
        ram = info["ram_used"] + info["stack"]
        lines.append(f"  RAM    [{bar(ram, info['ram_region'])}] {ram:>7} / {info['ram_region']} bytes  "
                     f"({info['ram_used']} data + {info['stack']} stack)")
    lines += ["", "  files:"] + [f"    {f}" for f in info.get("files", [])]
    notes = info.get("notes", [])
    if notes:
        lines += [""] + [f"  note: {n}" for n in notes]
    return lines


def _build(curses, scr, st: TuiState, pal):
    from . import build as mubuild
    if any(lvl == "error" for lvl, _ in st.problems()):
        st.message = "fix the errors first (shown above)"
        return
    st.save()
    out = st.cfg.output_dir()
    h, w = scr.getmaxyx()
    _put(scr, h - 2, 1, f"building {st.cfg.board} into {out} ... (this can take a while)".ljust(w - 2), w - 2, pal["title"])
    scr.refresh()
    try:
        info = mubuild.build(st.cfg, out, log=lambda *a: None)
        lines = build_report(st, info, out)
        st.last_build = "\n".join(lines)
    except Exception as e:      # noqa: BLE001 - a build error is shown, never a traceback
        lines = ["build failed:", ""] + str(e).splitlines()[-30:]
    st.show_text("Build", lines)
