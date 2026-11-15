"""menuconfig for MimiBoot-Mu.

TuiState is the whole UI as plain data (testable without a terminal); run()
draws it with curses.

The screen, top to bottom: the board and the file; a gauge of how much of the
bootloader's flash the configuration takes (an estimate until it is built);
where you are; the list, with the details of the highlighted line beside it
(below it on narrow terminals); the last thing that happened; the keys that
do something here.

Home describes the configuration in words, one line per area, then what you
changed from the board's defaults and what is wrong (Enter on a problem goes
to the option that fixes it).

  up/down PgUp/PgDn Home/End  move         Enter / Right   open, toggle, edit
  Space   toggle / next choice             Esc / Left / Backspace   back
  /       find (as you type)               ?   all of the help for the line
  d       back to the default              u   undo
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
    kind: str           # section | maker | category | board | menu | option | preset | action | issue | info
    key: str
    label: str
    value: str = ""
    enabled: bool = True
    note: str = ""      # the right-hand column: what it costs, what it needs, why it's fixed
    style: str = ""     # a colour for the row (issues: bad / warn)


@dataclass
class View:
    kind: str           # makers | categories | boards | main | menu | presets | search | boardsearch | text
    arg: str = ""
    title: str = ""
    lines: list = field(default_factory=list)
    cursor: int = 0
    top: int = 0


# A few words for what an option does, for the home screen's summaries (the title otherwise)
SHORT = {
    "AB_TRIAL": "trial boots", "TRIAL_WATCHDOG": "trial watchdog", "CRASH_GUARD": "crash guard",
    "ANTI_ROLLBACK": "anti-rollback", "IMG_NATIVE": "MimiBoot", "IMG_MCUBOOT": "Zephyr/MCUboot", "IMG_RAW": "raw",
    "RAM_IMAGES": "RAM images", "SIGNATURES": "Ed25519", "ECDSA": "P-256", "LMS": "LMS",
    "REQUIRE_SIGNATURE": "signed only", "ENCRYPTED_IMAGES": "encrypted images", "BOOT_RECORD": "boot record",
    "CFG_SIGNED": "signed config", "FAULT_HARDENING": "glitch hardening", "CONSOLE_AUTH": "console lock",
    "BOOT_LOCK": "flash lock", "LOCK_GOLDEN": "golden locked", "PROTECTED_FLOOR": "protected floor",
    "DEBUG_LOCK": "debug locked", "CONSOLE": "menu", "SHELL": "command line", "SHELL_DIAG": "diagnostics",
    "RECV": "uploads", "CONSOLE_USB": "over USB", "SMP": "SMP", "CFG_FILE": "config file", "GRUB": "GRUB syntax",
    "HANDOFF": "handoff", "CONTROL": "control service", "OS_HOOKS": "OS hooks", "SCRUB_RAM": "RAM wiped",
    "BOARD_LED": "LED", "BOARD_BUTTON": "button", "TWO_STAGE": "two-stage", "STK500": "STK500 uploads",
    "EEPROM_RW": "EEPROM access", "NOAPP_STAY": "waits without an app", "APP_REQUEST": "app requests",
    "LITE_HANDOFF": "handoff", "LITE_TRIAL": "trial boots", "SPM_API": "flash service",
    "STAGED_UPDATE": "staged updates", "LED": "LED",
}
# how a value reads in a summary
VALUE_TEXT = {
    "LAYOUT": lambda v: {"single": "one slot", "ab": "A/B", "ab+golden": "A/B + golden"}.get(v, v),
    "AUX_SLOTS": lambda v: f"+{v} aux" if v else "",
    "TRIES": lambda v: f"{v} tries",
    "BOOT_VERIFY": lambda v: {"every-boot": "hash every boot", "once": "hash once", "never": "no hash"}.get(v, v),
    "MENU_SECS": lambda v: f"{v} s countdown",
    "BAUD": lambda v: f"{v} baud",
    "BOOT_SIZE": lambda v: "" if str(v).lower() in ("chip", "auto", "") else str(v),
    "ENTRY": lambda v: f"listens on {v}",
    "VERIFY": lambda v: "" if v == "none" else f"{v} check",
}
# options whose "needs" names the reason in fewer words
NEEDS_TEXT = {"SIGNATURES|LMS": "a signature scheme"}


def summary(cfg: Config, menu: str) -> str:
    """what a menu's options add up to, in a few words: what's on, and the values that say most"""
    parts = []
    if menu == "layout" and cfg.t.build == "mcu":
        from . import gen
        try:
            parts.append(f"{gen.mcu_layout(cfg).boot.size // 1024} KB for the bootloader")
        except Exception:           # noqa: BLE001 - the problems list says what is wrong
            parts.append("doesn't fit (see below)")
    for o in cfg.options(menu):
        v = cfg.effective(o.id)
        if o.id in VALUE_TEXT and v is not None and v is not False:
            if o.kind == "bool" or not cfg.enabled(o.id):
                continue
            t = VALUE_TEXT[o.id](v)
            if t:
                parts.append(t)
        elif o.kind == "bool" and v:
            parts.append(SHORT.get(o.id, o.title.split(" (")[0].split(":")[0]))
    return " · ".join(parts) if parts else "nothing on"


def _kb(n: float) -> str:
    return f"{n / 1024:.1f} KB" if abs(n) >= 1024 else f"{int(n)} B"


class TuiState:
    def __init__(self, db: Db, path: Path, cfg: Config | None = None):
        from . import sizes
        self.db, self.path = db, path
        self.cfg = cfg
        self.dirty = False
        self.message = ""
        self.last_build = None      # the report, printed after the UI closes
        self.last_info = None       # (board, values, info) of the last build: real sizes
        self.sizes = sizes.load()
        self.history: list[tuple[dict, str]] = []
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
            return [Item("board", name, name, db.target(name).status) for name in db.tree()[maker][cat]]
        if v.kind == "boardsearch":
            q = v.arg.lower()
            out = []
            for name in db.boards:
                t = db.target(name)
                if all(w in f"{name} {t.chip_name} {t.title} {db.maker_title(t.maker)}".lower() for w in q.split()):
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
                   Item("section", "", "What it does")]
            for mid, title in cfg.menus():
                if mid == "output":
                    continue
                out.append(Item("menu", mid, title, summary(cfg, mid)))
            ch = self.changes()
            if ch:
                out.append(Item("section", "", f"Changed from the board's defaults ({len(ch)})"))
                out += [self._opt_item(oid) for oid in ch]
            iss = self.issues()
            if iss:
                out.append(Item("section", "", "Needs attention"))
                for i, (lvl, msg, target) in enumerate(iss):
                    out.append(Item("issue", f"{i}", msg, target or "", style="bad" if lvl == "error" else "warn"))
            out.append(Item("section", "", "Build"))
            out.append(Item("action", "presets", "Start from a preset", "minimal / hobby / product / secure"))
            if t.build == "mcu":
                out.append(Item("action", "layout", "Show the flash map", "bootloader, log, config and slot addresses"))
            out.append(self._opt_item("OUTPUT_DIR"))
            out.append(self._opt_item("EXPORT_SOURCE"))
            out.append(Item("action", "build", "Build now", str(cfg.output_dir())))
            return out
        if v.kind == "search":
            words = v.arg.lower().split()
            ids = [o.id for o in cfg.options()
                   if all(w in (o.id + " " + o.title + " " + o.help + " " + SHORT.get(o.id, "")).lower() for w in words)]
            return [self._opt_item(oid) for oid in ids]
        return [self._opt_item(o.id) for o in cfg.options(v.arg)]

    def _opt_item(self, oid) -> Item:
        o = self.db.options[oid]
        cfg = self.cfg
        en = cfg.enabled(oid)
        v = cfg.values[oid]
        if o.kind == "bool":
            val = "[x]" if (v and en) else "[ ]"
        elif o.kind == "int":
            val = f"{v}"
        elif o.kind == "choice":
            val = f"<{v}>"
        else:
            val = f'"{v}"' if v else "(none)"
        if cfg.locked(oid) is not None:
            note = "fixed here"
        elif not en:
            note = "needs " + ", ".join(NEEDS_TEXT.get(d, d.replace("|", " or ")) for d in o.depends
                                        if not cfg.dep_ok(d))
        else:
            c = self.cost(oid)
            note = f"{'+' if c > 0 else '-'}{_kb(abs(c))}" if c is not None and abs(c) >= 64 else ""
        return Item("option", oid, o.title, val, en, note)

    def current(self) -> Item | None:
        its = self.items()
        return its[self.view.cursor] if its and self.view.cursor < len(its) else None

    # ---- what the configuration costs and changes -----------------------------------------
    def cost(self, oid: str) -> float | None:
        """bytes of flash the option adds while on (bools), as measured on the reference board"""
        ref = self.sizes.get(self.cfg.t.build) if self.cfg else None
        o = self.db.options[oid]
        if not ref or o.kind != "bool" or oid not in ref.get("options", {}):
            return None
        e = ref["options"][oid]
        return e["delta"] if e["value"] else -e["delta"]

    def _delta(self, oid: str, value) -> float | None:
        """flash difference of `value` against the reference build's default for this option"""
        ref = self.sizes.get(self.cfg.t.build, {})
        o = self.db.options[oid]
        if o.kind == "bool":
            c = self.cost(oid)
            return None if c is None else (c if value else 0.0)
        e = ref.get("options", {}).get(f"{oid}={value}")
        return float(e["delta"]) if e else 0.0

    def estimate(self) -> dict | None:
        """{used, region, exact, unmeasured}: flash of the bootloader as configured. Exact after a
        build of exactly this configuration; otherwise the board's measured default build plus
        what each changed option adds on the reference board (an estimate)."""
        cfg = self.cfg
        if not cfg:
            return None
        if self.last_info and self.last_info[0] == cfg.board and self.last_info[1] == cfg.values:
            info = self.last_info[2]
            if info.get("flash_used") and info.get("flash_region"):
                return {"used": info["flash_used"], "region": info["flash_region"], "exact": True, "unmeasured": [],
                        "ram": info.get("ram_used", 0) + info.get("stack", 0), "ram_region": info.get("ram_region")}
        base = self.sizes.get("boards", {}).get(cfg.board)
        if not base:
            return None
        default = Config(self.db, cfg.board)
        used, unmeasured = float(base["flash"]), []
        for o in cfg.options():
            if o.kind not in ("bool", "choice") or not o.macro:
                continue
            now, was = cfg.effective(o.id), default.effective(o.id)
            if now == was:
                continue
            a, b = self._delta(o.id, now), self._delta(o.id, was)
            if a is None or b is None:
                unmeasured.append(o.id)
                continue
            used += a - b
        return {"used": int(used), "region": self._region(base["region"]), "exact": False, "unmeasured": unmeasured}

    def _region(self, default: int) -> int | None:
        """the room the bootloader has as configured now (BOOT_SIZE moves it; two-stage: a stage-1
        copy, None when that is sized to fit)"""
        cfg = self.cfg
        if cfg.t.build != "mcu":
            return default
        from . import gen
        from .model import parse_size
        try:
            if cfg.effective("TWO_STAGE"):
                s1 = str(cfg.effective("STAGE1_SIZE") or "auto").strip().lower()
                return None if s1 in ("auto", "") else parse_size(s1.upper()) - gen.NATIVE_HDR
            return gen.code_room(cfg, gen.mcu_layout(cfg))
        except Exception:           # noqa: BLE001 - a layout that doesn't work is in the problems list
            return default

    def changes(self) -> list[str]:
        """options set differently from the board's defaults (what you did)"""
        cfg = self.cfg
        default = Config(self.db, cfg.board)
        return [o.id for o in cfg.options() if o.menu != "output" and cfg.values[o.id] != default.values[o.id]
                and cfg.locked(o.id) is None]

    def issues(self) -> list[tuple[str, str, str | None]]:
        """[(level, message, option id that fixes it or None)], errors first"""
        out = []
        ids = {o.id for o in self.cfg.options()}
        titles = {o.title.lower(): o.id for o in self.cfg.options()}
        for lvl, msg in sorted(self.cfg.problems(), key=lambda p: p[0] != "error"):
            target = None
            for word in msg.replace("(", " ").replace(")", " ").replace(",", " ").replace(":", " ").split():
                w = word.strip("'\".")
                if w in ids:
                    target = w
                    break
            if not target:
                for t, oid in titles.items():
                    if f"'{t}'" in msg.lower():
                        target = oid
                        break
            out.append((lvl, msg, target))
        return out

    def _effective(self) -> dict:
        return {o.id: self.cfg.effective(o.id) for o in self.cfg.options()}

    def knock_on(self, oid: str) -> tuple[list[str], list[str]]:
        """turning `oid` the other way would also switch these on / off (through dependencies)"""
        cfg = self.cfg
        trial = Config(self.db, cfg.board, dict(cfg.values))
        before = {o.id: trial.effective(o.id) for o in trial.options()}
        trial.toggle(oid)
        on, off = [], []
        for o in trial.options():
            if o.id == oid or o.kind != "bool":
                continue
            b, a = before[o.id], trial.effective(o.id)
            if bool(a) != bool(b):
                (on if a else off).append(o.id)
        return on, off

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
            out += [("text", ""), ("warn", "Enter applies it: every option back to its default first (u undoes it).")]
            return out
        if it.kind == "menu":
            m = db.menu_defs[it.key]
            out += [("title", m.title), ("text", m.help), ("text", "")]
            for o in self.cfg.options(it.key):
                val = self.cfg.effective(o.id)
                shown = ("on" if val else "off") if o.kind == "bool" else str(val)
                out.append(("dim" if not self.cfg.enabled(o.id) else "text", f"  {shown:>10}  {o.title}"))
            return out
        if it.kind == "issue":
            lvl, msg, target = self.issues()[int(it.key)]
            out += [("bad" if lvl == "error" else "warn", "Stops the build" if lvl == "error" else "Worth a look"),
                    ("text", msg), ("text", "")]
            if target:
                out.append(("dim", f"Enter goes to {self.db.options[target].title} ({target})."))
            return out
        if it.kind == "option":
            return self._option_details(it.key)
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
            if it.key == "build":
                est = self.estimate()
                if est:
                    out += [("text", ""), ("label", "flash: " + gauge_text(est, 0)[0].split("flash ", 1)[1].strip())]
            return out
        if v.kind == "text":
            return []
        return [("text", it.label)]

    def _option_details(self, oid: str) -> list[tuple[str, str]]:
        o = self.db.options[oid]
        cfg = self.cfg
        out = [("title", o.title), ("dim", f"MU_{o.id}" + (f"  ->  {o.macro}" if o.macro else ""))]

        def show(x):
            return ("on" if x else "off") if o.kind == "bool" else (str(x) if x != "" else "(none)")
        state = f"now {show(cfg.effective(o.id) if cfg.enabled(o.id) else cfg.values[o.id])}"
        state += f", default {show(cfg.default(o))}"
        c = self.cost(oid)
        if c is not None and abs(c) >= 16:
            state += f", about {_kb(abs(c))} of flash when on"
        out.append(("label", state))
        if cfg.locked(o.id) is not None:
            out.append(("warn", f"fixed to {show(cfg.locked(o.id))} on this board"))
        if not cfg.enabled(o.id):
            out.append(("warn", "can't be set now: needs " + ", ".join(d.replace("|", " or ") for d in o.depends
                                                                       if not cfg.dep_ok(d))))
        if o.kind == "choice":
            out.append(("label", "choices: " + " | ".join(o.choices)))
        if o.kind == "int" and o.range:
            out.append(("label", f"range: {o.range[0]} .. {o.range[1]}"))
        if o.kind == "bool" and cfg.enabled(o.id) and cfg.locked(o.id) is None:
            on, off = self.knock_on(oid)
            name = lambda i: SHORT.get(i, i)       # noqa: E731
            if off:
                out.append(("warn", f"turning it {'off' if cfg.values[oid] else 'on'} also turns off: "
                                    + ", ".join(name(i) for i in off)))
            if on:
                out.append(("good", f"turning it {'off' if cfg.values[oid] else 'on'} makes these available again: "
                                    + ", ".join(name(i) for i in on)))
        out.append(("text", ""))
        out += [("text", para) for para in (o.help or o.title).split("\n")]
        return out

    def help_text(self) -> str:
        return "\n".join(t for _, t in self.details())

    def header(self) -> str:
        if not self.cfg:
            return "MimiBoot-Mu  ·  pick a board" if UTF else "MimiBoot-Mu - pick a board"
        t = self.cfg.t
        cpu = t.get("cpu") or t.get("mcu") or t.get("platform") or ""
        flash = t.board.get("flash", t.get("flash"))
        parts = ["MimiBoot-Mu", t.name, f"{t.chip_name}" + (f" ({cpu}, {flash} flash)" if cpu and flash else "")]
        return f"  {G['dot']}  ".join(parts)

    def file_label(self) -> str:
        return f"{self.path.name}{' (not saved)' if self.dirty else ''}"

    def issue_counts(self) -> str:
        if not self.cfg:
            return ""
        probs = self.problems()
        e = sum(1 for lvl, _ in probs if lvl == "error")
        w = len(probs) - e
        out = []
        if e:
            out.append(f"{e} stop{'s' if e == 1 else ''} the build")
        if w:
            out.append(f"{w} warning{'' if w == 1 else 's'}")
        return ", ".join(out)

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
            elif v.kind in ("search", "boardsearch"):
                out.append(f"find '{v.arg}'")
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
            self.view.cursor = 0
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
            self._fix_cursor()
        elif self.view.kind == "makers" and not self.cfg:
            self.quit = True

    def open(self, view: View):
        self.views.append(view)
        self._fix_cursor()

    def goto_option(self, oid: str):
        """open the menu that holds the option, cursor on it"""
        o = self.db.options[oid]
        self.views = [self.views[0]]
        self.open(View("menu", o.menu, self.db.menu_defs[o.menu].title))
        self.select(oid)

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
        if it.kind == "issue":
            if it.value:
                self.goto_option(it.value)
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

    def _remember(self, label: str):
        if self.cfg:
            self.history.append((dict(self.cfg.values), label))
            del self.history[:-50]

    def undo(self):
        if not self.history:
            self.message = "nothing to undo"
            return
        values, label = self.history.pop()          # (the history is cleared when the board changes)
        self.cfg.values = dict(values)
        self.dirty = True
        self._fix_cursor()
        self.message = f"undone: {label}"

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
        self.history.clear()        # another board: its own defaults, nothing to undo into
        self.dirty = True
        self.views = [View("main", title="Home")]
        self._fix_cursor()
        self.message = f"board: {name}"

    def apply_preset(self, pid: str):
        self._remember(f"preset {pid}")
        done = self.cfg.apply_preset(pid)
        self.dirty = True
        self.views = [View("main", title="Home")]
        self._fix_cursor()
        kept = f"; kept off (too big for this chip): {', '.join(self.cfg.preset_kept)}" if self.cfg.preset_kept else ""
        self.message = f"preset {pid}: {len(done)} options set{kept} (u undoes it)"

    def _report(self, oid: str, before: dict):
        """the message after a change: what it is now, what else moved, what it costs"""
        o = self.db.options[oid]
        after = self._effective()
        now = after.get(oid)
        shown = ("on" if now else "off") if o.kind == "bool" else str(now)
        parts = [f"{SHORT.get(oid, o.title.split(' (')[0])}: {shown}"]
        moved_on = [k for k, v in after.items() if k != oid and self.db.options[k].kind == "bool" and v and not before.get(k)]
        moved_off = [k for k, v in after.items() if k != oid and self.db.options[k].kind == "bool" and before.get(k) and not v]
        if moved_off:
            parts.append("also off: " + ", ".join(SHORT.get(k, k) for k in moved_off))
        if moved_on:
            parts.append("also on: " + ", ".join(SHORT.get(k, k) for k in moved_on))
        est = self.estimate()
        if est:
            parts.append(f"flash {'' if est['exact'] else '~'}{_kb(est['used'])}"
                         + (f" of {_kb(est['region'])}" if est["region"] else ""))
        self.message = "  ·  ".join(parts)

    def activate(self, oid: str, space=False):
        o = self.db.options[oid]
        if not self.cfg.enabled(oid):
            needs = ", ".join(d.replace("|", " or ") for d in o.depends if not self.cfg.dep_ok(d))
            self.message = f"{oid} needs {needs}"
            return None
        if self.cfg.locked(oid) is not None:
            self.message = f"{oid} is fixed on this board"
            return None
        if o.kind in ("bool", "choice"):
            before = self._effective()
            self._remember(f"{oid}")
            self.cfg.toggle(oid)
            self.dirty = True
            self._report(oid, before)
            return None
        if space:
            return None
        self.prompt = (oid, str(self.cfg.values[oid]))
        return "prompt"

    def space(self):
        it = self.current()
        if it and it.kind == "option":
            self.activate(it.key, space=True)

    def reset_default(self):
        it = self.current()
        if not it or it.kind != "option":
            return
        o = self.db.options[it.key]
        d = self.cfg.default(o)
        if self.cfg.values[it.key] == d:
            self.message = f"{it.key} is already at its default"
            return
        before = self._effective()
        self._remember(f"{it.key} back to default")
        self.cfg.values[it.key] = d
        self.dirty = True
        self._fix_cursor()
        self._report(it.key, before)

    def finish_prompt(self, text: str | None):
        oid, _ = self.prompt
        self.prompt = None
        if text is None:
            return
        try:
            before = dict(self.cfg.values)
            self.cfg.set(oid, text)
            self.history.append((before, oid))
            del self.history[:-50]
            self.dirty = True
            self.message = f"{oid} = {self.cfg.values[oid]}"
        except (KeyError, ValueError) as e:
            self.message = str(e)

    def search(self, text: str):
        """find options (or boards, when none is picked yet) whose name, title or help hold every word"""
        if not text:
            return
        picking = not self.cfg or self.view.kind in ("makers", "categories", "boards", "boardsearch")
        kind = "boardsearch" if picking else "search"
        if self.view.kind == kind:
            self.view.arg = text
            self.view.cursor = 0
            self._fix_cursor()
        else:
            self.open(View(kind, text, f"find '{text}'"))

    def show_text(self, title: str, lines: list[str]):
        self.open(View("text", title=title, lines=lines))

    def save(self):
        self.cfg.save(self.path)
        self.dirty = False
        self.message = f"saved {self.path}"

    def keys_hint(self) -> list[tuple[str, str]]:
        """[(key, what it does here)]: only what applies to the highlighted line"""
        if not self.cfg or self.view.kind in ("makers", "categories", "boards", "boardsearch"):
            return [("Enter", "open"), ("/", "find a board"), ("Esc", "back"), ("Q", "quit")]
        it = self.current()
        out = []
        if it and it.kind == "option":
            o = self.db.options[it.key]
            if it.enabled and self.cfg.locked(it.key) is None:
                out.append(("Space", "toggle" if o.kind == "bool" else "next" if o.kind == "choice" else "edit"))
                if self.cfg.values[it.key] != self.cfg.default(o):
                    out.append(("d", "default"))
        elif it and it.kind in ("menu", "maker", "category"):
            out.append(("Enter", "open"))
        elif it and it.kind == "issue" and it.value:
            out.append(("Enter", "go to the fix"))
        elif it and it.kind in ("action", "preset", "board"):
            out.append(("Enter", "go"))
        if len(self.views) > 1:
            out.append(("Esc", "back"))
        out += [("/", "find"), ("?", "help")]
        if self.history:
            out.append(("u", "undo"))
        out += [("B", "build")] + ([("S", "save")] if self.dirty else []) + [("Q", "quit")]
        return out


# ---------------------------------------------------------------------------
# curses
# ---------------------------------------------------------------------------
UTF = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "").startswith("utf8")
G = {"sep": " › " if UTF else " > ", "full": "█" if UTF else "#", "empty": "░" if UTF else ".",
     "more": "›" if UTF else ">", "ok": "✓" if UTF else "OK", "vline": "│" if UTF else "|",
     "hline": "─" if UTF else "-", "dot": "·" if UTF else "-", "bad": "✗" if UTF else "x", "warn": "!",
     "on": "●" if UTF else "*", "off": "○" if UTF else "o"}


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
        bar_ = G["full"] * max(1, round(36 * r.size / total))
        out.append(f"  {r.name:6} 0x{fb + r.offset:08x} {r.size // 1024:6} KB  {bar_}")
    return out + [""] + [f"note: {n}" for n in lay.notes]


def bar(used: int, total: int, width: int = 30) -> str:
    n = max(0, min(width, round(width * used / total))) if total else 0
    return G["full"] * n + G["empty"] * (width - n)


def gauge_text(est: dict | None, width: int = 24) -> tuple[str, str]:
    """the size line under the title: (text, style)"""
    if not est:
        return "flash: build once to see what it takes", "dim"
    used, region = est["used"], est["region"]
    if not region:
        return f"flash ~{_kb(used)} for stage 1 (two-stage: each stage-1 copy is sized to fit it)", "good"
    pct = 100 * used / region
    style = "bad" if pct > 100 else "warn" if pct > 94 else "good"
    sure = "" if est["exact"] else "~"
    text = f"flash {bar(used, region, width)} {sure}{_kb(used)} of {_kb(region)}"
    if not est["exact"]:
        if pct > 94:
            text += "  (an estimate: close to the limit, build to check)"
        elif est["unmeasured"]:
            text += f"  (estimate; not measured: {', '.join(est['unmeasured'][:3])}{'...' if len(est['unmeasured']) > 3 else ''})"
        else:
            text += "  (estimate)"
    if est.get("ram_region"):
        text += f"   RAM {bar(est['ram'], est['ram_region'], 10)} {_kb(est['ram'])} of {_kb(est['ram_region'])}"
    return text, style


def run(db: Db, path: Path):
    try:
        import curses
    except ImportError:
        raise SystemExit("this Python has no curses (Windows: pip install windows-curses). "
                         "The CLI does everything too: python muconfigurator.py show / set / preset / build")
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
        keys = ("title", "text", "label", "dim", "good", "warn", "bad", "head", "sel", "section", "key", "keyname")
        self.attr = {k: 0 for k in keys}
        self.attr.update(title=curses.A_BOLD, dim=curses.A_DIM, head=curses.A_REVERSE, sel=curses.A_REVERSE,
                         section=curses.A_BOLD, bad=curses.A_BOLD, warn=curses.A_BOLD, keyname=curses.A_REVERSE)
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
                         "label": (curses.COLOR_CYAN, bg), "keyname": (curses.COLOR_BLACK, curses.COLOR_WHITE),
                         "key": (curses.COLOR_WHITE, bg)}
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


def _ask(curses, scr, pal, label: str, initial: str = "", live=None) -> str | None:
    """a line of input at the bottom; live(text) runs on every key (find as you type)"""
    h, w = scr.getmaxyx()
    curses.curs_set(1)
    buf = list(initial)
    while True:
        if live:
            live("".join(buf))
            h, w = scr.getmaxyx()
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


def _row(it: Item, width: int) -> str:
    if it.kind == "option":
        note = f" {it.note}" if it.note else ""
        left = f" {it.value:<12} {it.label}"
        room = width - len(note)
        if len(left) > room:
            left = left[:max(1, room - 1)] + ("…" if UTF else ".")
        return left.ljust(room) + note
    if it.kind in ("menu", "maker", "category"):
        if it.kind == "menu":
            left = f" {it.label:<26}  "
            room = width - len(left) - 2
            summary_ = it.value if len(it.value) <= room else it.value[:max(1, room - 1)] + ("…" if UTF else ".")
            return (left + summary_).ljust(width - 2) + G["more"] + " "
        right = f"{it.value}  {G['more']}" if it.value else G["more"]
        return f" {it.label}".ljust(max(1, width - len(right) - 1)) + right
    if it.kind == "board":
        return f" {it.label}".ljust(max(1, width - 11)) + f"{it.value:>9} "
    if it.kind == "issue":
        mark = G["bad"] if it.style == "bad" else G["warn"]
        return f" {mark} {it.label}"
    if it.kind == "action":
        return f" {it.label}" + (f"   {it.value}" if it.value else "")
    return f" {it.label}"


def _draw(curses, scr, st: TuiState, pal):
    scr.erase()
    h, w = scr.getmaxyx()
    v = st.view
    head = " " + st.header()
    if st.cfg:
        right = st.file_label() + " "
        head = head[:max(1, w - len(right) - 1)].ljust(w - len(right)) + right
    _put(scr, 0, 0, head.ljust(w), w, pal["head"])
    if st.cfg:
        text, style = gauge_text(st.estimate(), 24 if w >= 100 else 12)
        _put(scr, 1, 1, text, w - 2, pal[style])
        counts = st.issue_counts()
        if counts and len(text) + len(counts) + 6 < w:
            bad = any(lvl == "error" for lvl, _ in st.problems())
            _put(scr, 1, w - len(counts) - 2, counts, len(counts), pal["bad" if bad else "warn"])
    _put(scr, 2, 1, G["sep"].join(st.breadcrumb()), w - 2, pal["section"])
    msg_rows = 1 if st.message else 0
    body_top, body_bot = 4, h - 1 - msg_rows       # rows [body_top, body_bot)
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
    if not items and v.kind in ("search", "boardsearch"):
        _put(scr, body_top, 1, "nothing matches", list_w - 2, pal["dim"])
    for row, it in enumerate(items[v.top:v.top + body_h]):
        i = v.top + row
        y = body_top + row
        if it.kind == "section":
            _put(scr, y, 0, (" " + it.label.upper()).ljust(list_w - 1), list_w - 1, pal["section"])
            continue
        selected = i == v.cursor and v.kind != "text"
        attr = pal["sel"] if selected else 0
        if not selected:
            if not it.enabled:
                attr |= pal["dim"]
            elif it.kind == "board" and it.value in ("hardware", "emulator"):
                attr |= pal["good"]
            elif it.kind == "issue":
                attr |= pal[it.style or "warn"]
            elif it.kind == "menu":
                attr |= 0
        _put(scr, y, 0, _row(it, list_w - 1).ljust(list_w - 1), list_w - 1, attr)
        if it.kind == "option" and it.note and not selected:          # the note column, quieter
            nx = list_w - 1 - len(it.note)
            style = "warn" if it.note.startswith(("needs", "fixed")) else "dim"
            _put(scr, y, nx, it.note, len(it.note), pal[style])
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
    if st.message:
        _put(scr, h - 2, 1, st.message, w - 2, pal["title"])
    # the keys that do something here
    x = 0
    _put(scr, h - 1, 0, " " * w, w - 1, pal["key"])
    for key, what in st.keys_hint():
        chunk = f" {key} "
        if x + len(chunk) + len(what) + 2 >= w:
            break
        _put(scr, h - 1, x, chunk, len(chunk), pal["keyname"])
        _put(scr, h - 1, x + len(chunk), f" {what} ", len(what) + 2, pal["key"])
        x += len(chunk) + len(what) + 3
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
        elif k == "/":
            depth = len(st.views)

            def live(text, depth=depth):
                if text:
                    st.search(text)
                elif len(st.views) > depth:
                    st.views.pop()
                _draw(curses, scr, st, pal)
            if _ask(curses, scr, pal, "find", "", live) is None and len(st.views) > depth:
                st.views.pop()          # Esc: back to where you were
        elif k == "u" and st.cfg:
            st.undo()
        elif k == "d" and st.cfg:
            st.reset_default()
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
        st.message = "fix what stops the build first (Home, 'Needs attention')"
        return
    st.save()
    out = st.cfg.output_dir()
    h, w = scr.getmaxyx()
    _put(scr, h - 2, 1, f"building {st.cfg.board} into {out} ... (this can take a while)".ljust(w - 2), w - 2, pal["title"])
    scr.refresh()
    try:
        info = mubuild.build(st.cfg, out, log=lambda *a: None)
        st.last_info = (st.cfg.board, dict(st.cfg.values), info)
        lines = build_report(st, info, out)
        st.last_build = "\n".join(lines)
    except Exception as e:      # noqa: BLE001 - a build error is shown, never a traceback
        lines = ["build failed:", ""] + str(e).splitlines()[-30:]
    st.show_text("Build", lines)
