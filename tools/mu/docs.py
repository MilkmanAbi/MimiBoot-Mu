"""docs/OPTIONS.md from config/features.toml (+ measured sizes): every menu, every
option with what it does, its default, what it needs and what it costs, and the
presets. `python mimiconf.py docs` regenerates it."""
from __future__ import annotations

from .model import ROOT, Db
from .sizes import load

OUT = ROOT / "docs/OPTIONS.md"


def _kb(n: int) -> str:
    return f"{n / 1024:.1f} KB" if abs(n) >= 1024 else f"{n} B"


def render(db: Db) -> str:
    sizes = load()
    lines = ["# MimiBoot-Mu options", "",
             "Generated from `config/features.toml` by `python mimiconf.py docs`; don't edit by hand.",
             "Set options in the TUI (`python mimiconf.py`) or with `python mimiconf.py set ID=value`.", ""]
    if sizes:
        lines += ["**Cost** is the flash a feature adds when it is on, measured by building a reference board "
                  "with its defaults and again with that one option flipped: " +
                  ", ".join(f"{v['board']} ({k}, default build {_kb(v['base'])})" for k, v in sizes.items()) +
                  ". Other chips differ a little (Cortex-M0 code is larger).", ""]
    lines += ["## Presets", "", "| preset | what you get |", "|---|---|"]
    for p in db.presets.values():
        lines.append(f"| `{p.id}` | **{p.title}**. {p.help} |")
    lines += ["", "`python mimiconf.py preset <name>` (or Presets in the TUI): every option back to its default, "
              "then the preset's values. On small chips a preset doesn't turn back on what the chip's defaults "
              "trim to fit.", ""]
    for m in db.menu_defs.values():
        opts = [o for o in db.options.values() if o.menu == m.id]
        if not opts:
            continue
        lines += [f"## {m.title}", "", m.help, ""]
        for o in opts:
            where = []
            if o.cores != ["night", "lite"]:
                where.append(" / ".join({"night": "full core", "lite": "AVR Lite"}[c] for c in o.cores))
            if o.builds:
                where.append("builds: " + ", ".join({"mcu": "STM32/nRF/SAMD", "pico": "RP2040/RP2350",
                                                     "avr": "AVR"}[b] for b in o.builds))
            default = o.default
            if o.kind == "bool":
                default = "on" if o.default else "off"
            extra = [f"default **{default}**"]
            for b, v in o.default_for.items():
                extra.append(f"{'on' if v is True else 'off' if v is False else v} on "
                             + {"mcu": "STM32/nRF/SAMD", "pico": "RP", "avr": "AVR"}[b])
            if o.choices:
                extra.append("one of " + ", ".join(f"`{c}`" for c in o.choices))
            if o.range:
                extra.append(f"{o.range[0]}..{o.range[1]}")
            if o.depends:
                extra.append("needs " + ", ".join(f"`{d}`" for d in o.depends))
            for kind, s in sizes.items():
                opt = s["options"].get(o.id)
                if opt and o.kind == "bool" and abs(opt["delta"]) >= 16:
                    cost = -opt["delta"] if not opt["value"] else opt["delta"]
                    extra.append(f"cost ~{_kb(cost)} on {s['board']}")
                for key, e in s["options"].items():
                    if key.startswith(o.id + "=") and abs(e["delta"]) >= 16:
                        extra.append(f"`{e['value']}` {'+' if e['delta'] > 0 else '-'}{_kb(abs(e['delta']))} on {s['board']}")
            head = f"### `{o.id}`: {o.title}"
            lines += [head, "", "; ".join(extra) + "." + (f" ({'; '.join(where)})" if where else ""), ""]
            if o.help:
                lines += [o.help.replace("\n", "\n\n"), ""]
            if o.macro:
                lines += [f"C macro: `{o.macro}`", ""]
    return "\n".join(lines).rstrip() + "\n"


def write(db: Db):
    OUT.write_text(render(db), encoding="utf-8", newline="\n")
    return OUT
