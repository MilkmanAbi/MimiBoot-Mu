"""What each feature costs in flash: build a reference board with its defaults,
then once with each on/off option flipped (choices: each value), and record
the difference. `python mimiconf.py sizes` regenerates config/feature-sizes.json;
the TUI shows the numbers next to the options."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .model import ROOT, Config, Db

REFERENCE = {"mcu": "nucleo-f411re", "avr": "uno"}      # pico builds take minutes each: not measured
SIZES_FILE = ROOT / "config/feature-sizes.json"
SKIP = {"KEYS", "OUTPUT_DIR", "EXPORT_SOURCE", "BAUD", "BOOT_SIZE", "LAYOUT", "AUX_SLOTS", "REQUIRE_SIGNATURE"}


def _size(cfg: Config, work: Path) -> int | None:
    from .build import BuildError, build
    try:
        return build(cfg, work, log=lambda *a: None)["flash_used"]
    except BuildError:
        return None


def measure(db: Db, board: str, log=print) -> dict:
    base_cfg = Config(db, board)
    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "b"
        base = _size(base_cfg, work)
        out = {"board": board, "base": base, "options": {}}
        for o in base_cfg.options():
            if o.id in SKIP or not o.macro or o.kind not in ("bool", "choice"):
                continue
            values = [not base_cfg.values[o.id]] if o.kind == "bool" else [c for c in o.choices
                                                                             if c != base_cfg.values[o.id]]
            for v in values:
                cfg = Config(db, board, dict(base_cfg.values))
                cfg.set(o.id, v)                            # options that depend on it switch off with it
                if cfg.effective(o.id) == base_cfg.effective(o.id):
                    continue                                # not selectable here
                s = _size(cfg, work)
                if s is None or base is None:
                    continue
                key = o.id if o.kind == "bool" else f"{o.id}={v}"
                out["options"][key] = {"value": v, "delta": s - base}
                log(f"  {board}: {key:28} {s - base:+7d} bytes")
    return out


def measure_all(db: Db, log=print) -> dict:
    res = {kind: measure(db, board, log) for kind, board in REFERENCE.items()}
    SIZES_FILE.write_text(json.dumps(res, indent=1) + "\n")
    return res


def load() -> dict:
    try:
        return json.loads(SIZES_FILE.read_text())
    except (OSError, ValueError):
        return {}


def cost_text(sizes: dict, cfg: Config, oid: str) -> str:
    """'turning this off saves ~6.9 KB (measured on nucleo-f411re)' style hint, or ''"""
    ref = sizes.get(cfg.t.build)
    if not ref:
        return ""
    o = cfg.db.options[oid]
    rows = []
    if o.kind == "bool" and oid in ref["options"]:
        e = ref["options"][oid]
        d = -e["delta"] if not e["value"] else e["delta"]       # cost of having it on
        if abs(d) >= 16:
            rows.append(f"costs ~{_kb(d)} when on")
    elif o.kind == "choice":
        for key, e in ref["options"].items():
            if key.startswith(oid + "=") and abs(e["delta"]) >= 16:
                rows.append(f"{e['value']}: {'+' if e['delta'] > 0 else '-'}{_kb(abs(e['delta']))}")
    if not rows:
        return ""
    return "; ".join(rows) + f" (measured on {ref['board']}, default build {_kb(ref['base'])})"


def _kb(n: int) -> str:
    return f"{n / 1024:.1f} KB" if abs(n) >= 1024 else f"{n} B"
