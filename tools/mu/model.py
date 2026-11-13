"""MimiBoot-Mu configuration model: targets, options, dependencies, .config files.

No UI here: the TUI (tui.py) and the CLI (mimiconf.py) both drive this.
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIZE_RE = re.compile(r"^\s*(\d+)\s*([KM]?)\s*$", re.I)


def parse_size(v) -> int:
    """'64K' -> 65536, '1M' -> 1048576, 4096 -> 4096"""
    if isinstance(v, int):
        return v
    m = SIZE_RE.match(str(v))
    if not m:
        raise ValueError(f"not a size: {v!r}")
    n, unit = int(m.group(1)), m.group(2).upper()
    return n * {"": 1, "K": 1024, "M": 1 << 20}[unit]


def parse_sectors(spec: str) -> list[tuple[int, int]]:
    """'4x16K,1x64K' -> [(offset, size), ...]"""
    out, off = [], 0
    for part in spec.split(","):
        count, size = part.lower().split("x")
        size = parse_size(size.upper())
        for _ in range(int(count)):
            out.append((off, size))
            off += size
    return out


def parse_pin(s: str) -> tuple[int, int]:
    """(port, pin): 'C13' / 'PC13' -> (2, 13) (STM32, AVR, SAMD); 'P1.11' -> (1, 11) (nRF)"""
    t = s.strip().upper()
    m = re.fullmatch(r"P(\d)\.(\d{1,2})", t)
    if m:
        port, pin = int(m.group(1)), int(m.group(2))
        if pin > 31:
            raise ValueError(f"nRF pins are P<port>.<0..31>, not {s!r}")
        return port, pin
    m = re.fullmatch(r"P?([A-K])(\d{1,2})", t)
    if not m:
        raise ValueError(f"pin must look like A9 / PC13 (or P0.06 on nRF), not {s!r}")
    return ord(m.group(1)) - ord("A"), int(m.group(2))


@dataclass
class Option:
    id: str
    kind: str
    default: object
    title: str
    menu: str
    macro: str = ""
    cores: list = field(default_factory=lambda: ["night", "lite"])
    builds: list | None = None
    default_for: dict = field(default_factory=dict)
    depends: list = field(default_factory=list)
    range: list | None = None
    choices: list | None = None
    help: str = ""


@dataclass
class Menu:
    id: str
    title: str
    help: str = ""


@dataclass
class Preset:
    id: str
    title: str
    help: str = ""
    cores: list = field(default_factory=lambda: ["night", "lite"])
    values: dict = field(default_factory=dict)


STATUS_TEXT = {"hardware": "ran on a real board", "emulator": "booted in an emulator (QEMU / simavr)",
               "built": "compiles and fits; never run", "host": "logic host-tested only"}


@dataclass
class Target:
    """A board, merged with its chip and family."""
    name: str
    board: dict
    chip_name: str
    chip: dict
    family_name: str
    family: dict

    def get(self, key, default=None):
        for d in (self.board, self.chip, self.family):
            if key in d:
                return d[key]
        return default

    @property
    def maker(self) -> str:
        return self.get("maker", "other")

    @property
    def category(self) -> str:
        return self.board.get("category", "Other boards")

    def facts(self) -> list[tuple[str, str]]:
        """(label, text) rows describing the board, for the picker's details pane"""
        rows = [("chip", f"{self.chip_name} ({self.get('cpu') or self.get('mcu') or self.get('platform') or '?'})")]
        if self.get("flash"):
            ram = self.get("ram")
            rows.append(("memory", f"{self.board.get('flash', self.get('flash'))} flash" + (f", {ram} RAM" if ram else "")))
        core = {"night": "full (slots, checks, console, OS hooks)", "lite": "Lite (small AVR core, STK500 uploads)"}
        rows.append(("core", core.get(self.core, self.core)))
        if self.build == "mcu":
            if self.get("vendor") == "samd":
                rows.append(("console", f"SERCOM{self.get('sercom')} UART, TX {self.get('tx')} RX {self.get('rx')}"))
            elif self.get("vendor") == "stm32":
                rows.append(("console", f"{self.get('uart', '').upper()}, TX {self.get('tx')} RX {self.get('rx')}"))
            else:
                rows.append(("console", f"UART, TX {self.get('tx')} RX {self.get('rx')}"))
        elif self.build == "pico":
            rows.append(("console", "USB (CDC serial)"))
        else:
            rows.append(("console", f"UART0 at {self.get('baud', 115200)} baud, {self.get('f_cpu', 16000000) // 1000000} MHz"))
        io = []
        if self.board.get("led"):
            io.append(f"LED {self.board['led']}")
        if self.board.get("button"):
            io.append(f"button {self.board['button']}")
        if io:
            rows.append(("pins", ", ".join(io)))
        rows.append(("tested", f"{self.status}: {STATUS_TEXT.get(self.status, '')}"))
        return rows

    @property
    def core(self) -> str:
        return self.get("core")

    @property
    def build(self) -> str:
        return self.get("build")

    @property
    def title(self) -> str:
        return self.board.get("title", self.name)

    @property
    def status(self) -> str:
        return self.board.get("status", "built")


class Db:
    def __init__(self, root: Path = ROOT):
        self.root = root
        t = tomllib.loads((root / "config/targets.toml").read_text(encoding="utf-8"))
        f = tomllib.loads((root / "config/features.toml").read_text(encoding="utf-8"))
        self.families, self.chips, self.boards = t.get("family", {}), t["chip"], t["board"]
        self.makers = t.get("maker", {})
        self.menu_defs = {m["id"]: Menu(**m) for m in f["menu"]}
        self.menus = [(m.id, m.title) for m in self.menu_defs.values()]
        self.options = {}
        for o in f["option"]:
            opt = Option(**o)
            if opt.id in self.options:
                raise ValueError(f"option {opt.id} defined twice")
            self.options[opt.id] = opt
        self.presets = {p["id"]: Preset(**p) for p in f.get("preset", [])}
        self._check()

    def _check(self):
        for o in self.options.values():
            for d in o.depends:
                if re.split(r"!?=", d)[0] not in self.options:
                    raise ValueError(f"{o.id} depends on unknown option {d}")
            if o.kind == "choice" and o.default not in o.choices:
                raise ValueError(f"{o.id}: default {o.default!r} isn't a choice")
            if o.menu not in self.menu_defs:
                raise ValueError(f"{o.id}: unknown menu {o.menu}")
        for p in self.presets.values():
            for k, v in p.values.items():
                o = self.options.get(k)
                if not o:
                    raise ValueError(f"preset {p.id}: unknown option {k}")
                Config.coerce(o, v)
        for name, b in self.boards.items():
            if b["chip"] not in self.chips:
                raise ValueError(f"board {name}: unknown chip {b['chip']}")

    def maker_title(self, mid: str) -> str:
        return self.makers.get(mid, {}).get("title", mid)

    def tree(self) -> dict:
        """{maker id: {category: [board, ...]}}, makers in targets.toml order, categories as first seen"""
        out = {m: {} for m in self.makers}
        for name in self.boards:
            t = self.target(name)
            out.setdefault(t.maker, {}).setdefault(t.category, []).append(name)
        def order(m, cats):
            pref = self.makers.get(m, {}).get("categories", [])
            return dict(sorted(cats.items(), key=lambda kv: pref.index(kv[0]) if kv[0] in pref else len(pref)))
        return {m: order(m, cats) for m, cats in out.items() if cats}

    def target(self, board: str) -> Target:
        if board not in self.boards:
            raise KeyError(f"unknown board {board!r} (mimiconf.py boards)")
        b = self.boards[board]
        c = self.chips[b["chip"]]
        fam = c.get("family", "")
        return Target(board, b, b["chip"], c, fam, self.families.get(fam, {}))


class Config:
    """Option values for one board. Values for options that don't apply to the
    board's core/build are never stored; unmet dependencies switch an option off."""

    def __init__(self, db: Db, board: str, values: dict | None = None):
        self.db, self.board = db, board
        self.t = db.target(board)
        self.values: dict[str, object] = {}
        self.preset_kept: list[str] = []        # what the last preset left off (too big for the chip)
        for o in self.options():
            self.values[o.id] = self.default(o)
        for k, v in (values or {}).items():
            if k in self.values:
                self.set(k, v)

    # ---- which options exist for this board ----
    def applies(self, o: Option) -> bool:
        return self.t.core in o.cores and (o.builds is None or self.t.build in o.builds)

    def options(self, menu: str | None = None) -> list[Option]:
        return [o for o in self.db.options.values() if self.applies(o) and (menu is None or o.menu == menu)]

    def menus(self) -> list[tuple[str, str]]:
        return [(m, title) for m, title in self.db.menus if self.options(m)]

    def locked(self, oid: str):
        """the value a board / chip / family fixes for this option, or None"""
        for d in (self.t.board, self.t.chip, self.t.family):
            if oid in d.get("locked", {}):
                return d["locked"][oid]
        return None

    def default(self, o: Option):
        if self.locked(o.id) is not None:
            return self.locked(o.id)
        # board, then chip, then family "defaults" tables (small chips trim features to fit)
        for d in (self.t.board, self.t.chip, self.t.family):
            if o.id in d.get("defaults", {}):
                return d["defaults"][o.id]
        if self.t.build in o.default_for:
            return o.default_for[self.t.build]
        if o.id == "BAUD" and self.t.get("baud"):
            return self.t.get("baud")
        return o.default

    # ---- dependencies ----
    def dep_ok(self, dep: str) -> bool:
        if "!=" in dep:
            k, v = dep.split("!=", 1)
            o = self.db.options.get(k)
            if not o or not self.applies(o):
                return True                 # nothing to differ from (e.g. LAYOUT on RP boards)
            return str(self.effective(k)) != v
        if "=" in dep:
            k, v = dep.split("=", 1)
            return self.enabled(k) and str(self.values.get(k)) == v
        return self.enabled(dep) and bool(self.values.get(dep))

    def enabled(self, oid: str) -> bool:
        """selectable: applies to this board and every dependency holds"""
        o = self.db.options.get(oid)
        if not o or not self.applies(o):
            return False
        return all(self.dep_ok(d) for d in o.depends)

    def effective(self, oid: str):
        """what the build sees: an option whose dependencies fail is off (bool) / its default"""
        o = self.db.options[oid]
        if not self.applies(o):
            return None
        if not self.enabled(oid):
            return False if o.kind == "bool" else self.default(o)
        return self.values[oid]

    # ---- editing ----
    def set(self, oid: str, value):
        o = self.db.options.get(oid)
        if o is None or not self.applies(o):
            raise KeyError(f"{oid} is not an option for {self.board} ({self.t.core}/{self.t.build})")
        v = self.coerce(o, value)
        fixed = self.locked(oid)
        if fixed is not None and v != fixed:
            raise ValueError(f"{oid} is fixed to {fixed} on {self.board}")
        self.values[oid] = v

    def apply_preset(self, pid: str) -> list[str]:
        """every option back to its default, then the preset's values; returns what was set"""
        p = self.db.presets[pid]
        if self.t.core not in p.cores:
            raise KeyError(f"preset {pid} isn't for the {self.t.core} core")
        for o in self.options():
            self.values[o.id] = self.default(o)
        done, self.preset_kept = [], []
        for k, v in p.values.items():
            if k not in self.values or self.locked(k) is not None:
                continue
            if v is True and self.trimmed(k):
                self.preset_kept.append(k)          # the chip turns it off to fit: a preset doesn't override that
                continue
            self.set(k, v)
            done.append(k)
        return done

    def trimmed(self, oid: str) -> bool:
        """switched off by the board / chip / family `defaults` table (small parts, to fit)"""
        return any(d.get("defaults", {}).get(oid) is False for d in (self.t.board, self.t.chip, self.t.family))

    def presets(self) -> list[Preset]:
        return [p for p in self.db.presets.values() if self.t.core in p.cores]

    def output_dir(self) -> Path:
        """where `build` writes: OUTPUT_DIR/<board> (default ~/MimiBoot/<board>)"""
        raw = str(self.effective("OUTPUT_DIR") or "").strip().strip('"').strip("'").strip() or "~/MimiBoot"
        return Path(os.path.expandvars(os.path.expanduser(raw))) / self.board

    @staticmethod
    def coerce(o: Option, value):
        if o.kind == "bool":
            if isinstance(value, bool):
                return value
            s = str(value).strip().lower()
            if s in ("y", "yes", "1", "true", "on"):
                return True
            if s in ("n", "no", "0", "false", "off", ""):
                return False
            raise ValueError(f"{o.id}: expected y/n, got {value!r}")
        if o.kind == "int":
            v = int(str(value), 0)
            lo, hi = o.range or (-(1 << 31), 1 << 31)
            if not lo <= v <= hi:
                raise ValueError(f"{o.id}: {v} is outside {lo}..{hi}")
            return v
        if o.kind == "choice":
            v = str(value)
            if v not in o.choices:
                raise ValueError(f"{o.id}: one of {', '.join(o.choices)}")
            return v
        s = str(value).strip()
        if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
            s = s[1:-1]                     # paths may be typed in quotes
        return s

    def toggle(self, oid: str):
        o = self.db.options[oid]
        if o.kind == "bool":
            self.values[oid] = not self.values[oid]
        elif o.kind == "choice":
            i = o.choices.index(self.values[oid])
            self.values[oid] = o.choices[(i + 1) % len(o.choices)]

    # ---- checks ----
    def problems(self) -> list[tuple[str, str]]:
        """[(level, message)]: 'error' stops a build, 'warn' doesn't"""
        out = []
        e = self.effective
        if self.t.core == "night":
            if not any(e(k) for k in ("IMG_NATIVE", "IMG_MCUBOOT", "IMG_RAW") if e(k) is not None):
                out.append(("error", "enable at least one image format"))
            if e("REQUIRE_SIGNATURE") and e("BOOT_VERIFY") != "every-boot":
                out.append(("error", "'Refuse unsigned images' needs the image hash on every boot (BOOT_VERIFY=every-boot)"))
            if e("REQUIRE_SIGNATURE") and not e("KEYS"):
                out.append(("error", "'Refuse unsigned images' needs a KEYS file"))
            if e("KEYS"):
                p = Path(str(e("KEYS")))
                if not p.is_absolute():
                    p = Path.cwd() / p
                if not p.exists():
                    out.append(("error", f"KEYS file not found: {p}"))
            if e("LAYOUT") == "single" and e("AB_TRIAL"):
                out.append(("warn", "one slot + 'Updates must confirm': an app that never confirms stops booting after "
                                    f"{e('TRIES')} tries (nothing to roll back to)"))
            if e("AB_TRIAL") and (e("IMG_MCUBOOT") or e("IMG_RAW")):
                out.append(("warn", "'Updates must confirm' with Zephyr/raw images: firmware that doesn't call "
                                    "mb_client_confirm() is rolled back after " + str(e("TRIES")) + " boots"))
            if e("IMG_RAW") and e("REQUIRE_SIGNATURE"):
                out.append(("warn", "raw images carry no signature: with 'Refuse unsigned images' they never boot"))
            vendor = self.t.get("vendor")
            mh = self.t.get("mcuboot_hdr", 0x200)
            if self.t.build == "mcu" and e("IMG_MCUBOOT") and mh != 0x200:
                out.append(("warn", f"Zephyr images for this chip need imgtool --header-size 0x{mh:x} and "
                                    f"CONFIG_ROM_START_OFFSET=0x{mh:x} (its vector table needs {mh}-byte alignment)"))
            if vendor in ("stm32", "nrf") and e("TRIAL_WATCHDOG"):
                out.append(("warn", f"the {vendor.upper()} watchdog can't be stopped once started: trial-booted apps must "
                                    "refresh it for as long as they run"))
            if self.t.build == "pico" and e("IMG_RAW") is not None and e("IMG_RAW"):
                out.append(("error", "raw images are for bare Cortex-M MCUs"))
            if self.t.chip_name == "rp2040" and not e("RAM_IMAGES"):
                out.append(("error", "RP2040 can only start RAM images: keep 'RAM images' on"))
        if self.t.core == "lite":
            if e("SPM_API") and parse_size(self.t.get("flash")) > 128 * 1024:
                out.append(("error", "the flash service isn't supported on >128 KB AVRs yet (the call needs EIND)"))
            if not e("STK500") and e("VERIFY") == "none":
                out.append(("warn", "no upload and no check: the bootloader only starts the app (Optiboot without the boot)"))
        return out

    # ---- .config ----
    def dump(self) -> str:
        lines = ["# MimiBoot-Mu configuration (python mimiconf.py)", f'MU_BOARD="{self.board}"']
        for o in self.options():
            v = self.values[o.id]
            if o.kind == "bool":
                lines.append(f"MU_{o.id}=y" if v else f"# MU_{o.id} is not set")
            elif o.kind == "int":
                lines.append(f"MU_{o.id}={v}")
            else:
                lines.append(f'MU_{o.id}="{v}"')
        return "\n".join(lines) + "\n"

    @classmethod
    def parse(cls, db: Db, text: str, board: str | None = None) -> "Config":
        vals, b = {}, board
        for line in text.splitlines():
            line = line.strip()
            m = re.fullmatch(r"# MU_(\w+) is not set", line)
            if m:
                vals[m.group(1)] = False
                continue
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip().strip('"')
            if k == "MU_BOARD":
                b = b or v
            elif k.startswith("MU_"):
                vals[k[3:]] = v
        if not b:
            raise ValueError("no MU_BOARD in the config")
        cfg = cls(db, b)
        for k, v in vals.items():
            if k in cfg.values and cfg.locked(k) is None:
                cfg.set(k, v)
        return cfg

    def save(self, path: Path):
        path.write_text(self.dump(), encoding="utf-8")

    @classmethod
    def load(cls, db: Db, path: Path) -> "Config":
        return cls.parse(db, path.read_text(encoding="utf-8"))
