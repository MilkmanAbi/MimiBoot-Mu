#!/usr/bin/env python3
"""MimiBoot-Mu configurator and builder - like the kernel's menuconfig, for a bootloader.

  python mimiconf.py                      menuconfig (TUI) on ./.config
  python mimiconf.py boards               every board, by maker and category, with test status
  python mimiconf.py defconfig uno        start a .config for a board
  python mimiconf.py set VERIFY=none LED=n
  python mimiconf.py show                 the effective configuration + warnings
  python mimiconf.py layout               flash layout (bare-metal MCUs) without building
  python mimiconf.py build                build into OUTPUT_DIR/<board>/ (default ~/MimiBoot/<board>)
  python mimiconf.py preset [minimal|hobby|product|secure]   start from a preset (no name: list them)
  python mimiconf.py toolchains           what was found where
  python mimiconf.py sizes                re-measure what each feature costs (for the TUI)
  python mimiconf.py docs                 regenerate docs/OPTIONS.md

Options are the ids from config/features.toml (`show` lists them).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from mu import build as mubuild  # noqa: E402
from mu import gen  # noqa: E402
from mu.model import Config, Db  # noqa: E402


def load(a, db):
    p = Path(a.config)
    if not p.exists():
        raise SystemExit(f"no {p}: start one with `python mimiconf.py defconfig <board>` (see `boards`)")
    return Config.load(db, p)


def cmd_boards(a, db):
    for maker, cats in db.tree().items():
        print(db.maker_title(maker))
        for cat, names in cats.items():
            print(f"  {cat}")
            for name in names:
                t = db.target(name)
                print(f"    {t.name:22} {t.status:9} {t.title}")
        print()
    print("status: hardware = ran on a board, emulator = booted in QEMU/simavr, built = compiles only")


def cmd_preset(a, db):
    cfg = load(a, db) if Path(a.config).exists() else None
    if not a.preset:
        for p in db.presets.values():
            print(f"  {p.id:9} {p.title}\n            {p.help}")
        return
    if not cfg:
        raise SystemExit(f"no {a.config}: pick a board first (defconfig)")
    try:
        done = cfg.apply_preset(a.preset)
    except KeyError as e:
        raise SystemExit(str(e))
    cfg.save(Path(a.config))
    print(f"{a.config}: preset {a.preset} on {cfg.board} ({len(done)} options set, the rest at their defaults)")
    if cfg.preset_kept:
        print(f"kept off because this chip is too small for them: {', '.join(cfg.preset_kept)} (set them by hand to try)")
    for lvl, m in cfg.problems():
        print(f"{lvl}: {m}")


def cmd_docs(a, db):
    from mu import docs
    print(f"wrote {docs.write(db)}")


def cmd_sizes(a, db):
    from mu import sizes
    print("building each reference board once per option (a few minutes)...")
    sizes.measure_all(db)
    print(f"wrote {sizes.SIZES_FILE}")


def cmd_defconfig(a, db):
    cfg = Config(db, a.board)
    Path(a.config).write_text(cfg.dump(), encoding="utf-8")
    print(f"{a.config}: defaults for {a.board} ({cfg.t.title})")
    for lvl, m in cfg.problems():
        print(f"  {lvl}: {m}")


def cmd_set(a, db):
    cfg = load(a, db)
    for kv in a.assignments:
        if "=" not in kv:
            raise SystemExit(f"expected ID=value, got {kv!r}")
        k, v = kv.split("=", 1)
        k = k.upper().removeprefix("MU_")
        try:
            cfg.set(k, v)
        except (KeyError, ValueError) as e:
            raise SystemExit(f"{e}")
        if not cfg.enabled(k):
            o = db.options[k]
            print(f"note: {k} has no effect until {', '.join(o.depends)}")
    cfg.save(Path(a.config))
    for lvl, m in cfg.problems():
        print(f"{lvl}: {m}")


def cmd_show(a, db):
    cfg = load(a, db)
    print(f"board {cfg.board}: {cfg.t.title}  [{cfg.t.core} core, {cfg.t.build} build, {cfg.t.status}]")
    for mid, title in cfg.menus():
        print(f"\n{title}")
        for o in cfg.options(mid):
            v = cfg.effective(o.id)
            shown = ("y" if v else "n") if o.kind == "bool" else str(v)
            dim = "" if cfg.enabled(o.id) else f"   (off: needs {', '.join(o.depends)})"
            print(f"  {o.id:18} {shown:10} {o.title}{dim}")
    probs = cfg.problems()
    if probs:
        print()
        for lvl, m in probs:
            print(f"{lvl}: {m}")


def cmd_layout(a, db):
    cfg = load(a, db)
    if cfg.t.build != "mcu":
        raise SystemExit("layouts are planned for bare-metal MCU boards; RP boards use fixed presets, AVR has one app area")
    lay = gen.mcu_layout(cfg)
    fb = gen.flash_base(cfg)
    for r in lay.regions():
        print(f"  {r.name:6} 0x{fb + r.offset:08x} {r.size // 1024:6} KB")
    for n in lay.notes:
        print("note:", n)


def cmd_build(a, db):
    cfg = load(a, db)
    out = Path(a.out) if a.out else cfg.output_dir()
    try:
        info = mubuild.build(cfg, out)
    except mubuild.BuildError as e:
        raise SystemExit(f"build failed: {e}")
    used, region = info.get("flash_used"), info.get("flash_region")
    print(f"built {cfg.board} -> {out}")
    if used and region:
        print(f"  flash {used} of {region} bytes ({100 * used // region}%)" +
              (f", RAM {info['ram_used']} + stack {info['stack']} of {info['ram_region']}" if "ram_used" in info else ""))
    for f in info.get("files", []):
        print("  ", f)
    for n in info.get("notes", []):
        print("note:", n)
    for lvl, m in cfg.problems():
        print(f"{lvl}: {m}")


def cmd_toolchains(a, db):
    for k, v in mubuild.toolchains().items():
        print(f"  {k:18} {v or '(not found)'}")


def cmd_menuconfig(a, db):
    from mu import tui
    tui.run(db, Path(a.config))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", default=".config", help="config file (default .config)")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("boards").set_defaults(fn=cmd_boards)
    s = sub.add_parser("defconfig"); s.add_argument("board"); s.set_defaults(fn=cmd_defconfig)
    s = sub.add_parser("set"); s.add_argument("assignments", nargs="+"); s.set_defaults(fn=cmd_set)
    sub.add_parser("show").set_defaults(fn=cmd_show)
    sub.add_parser("layout").set_defaults(fn=cmd_layout)
    s = sub.add_parser("build"); s.add_argument("-o", "--out"); s.set_defaults(fn=cmd_build)
    sub.add_parser("toolchains").set_defaults(fn=cmd_toolchains)
    s = sub.add_parser("preset"); s.add_argument("preset", nargs="?"); s.set_defaults(fn=cmd_preset)
    sub.add_parser("sizes").set_defaults(fn=cmd_sizes)
    sub.add_parser("docs").set_defaults(fn=cmd_docs)
    sub.add_parser("menuconfig").set_defaults(fn=cmd_menuconfig)
    a = p.parse_args()
    db = Db()
    (a.fn if a.cmd else cmd_menuconfig)(a, db)


if __name__ == "__main__":
    main()
