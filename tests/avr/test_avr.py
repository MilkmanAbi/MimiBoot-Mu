#!/usr/bin/env python3
"""Build MimiBoot-Mu Lite variants + test sketches here, run them in simavr with
avrdude (tests/avr/run_sim.py, in WSL on Windows)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from mu import build as mubuild  # noqa: E402
from mu.build import _tool  # noqa: E402
from mu.model import Config, Db  # noqa: E402

PARTS = {"atmega328p": "m328p", "atmega168": "m168", "atmega644p": "m644p", "atmega1284p": "m1284p",
         "atmega2560": "m2560"}


def to_linux(p):
    p = Path(p).resolve()
    if os.name != "nt":
        return str(p)
    return "/mnt/" + p.drive[0].lower() + p.as_posix()[2:]


def build_boot(db, board, sets, out):
    cfg = Config(db, board)
    for k, v in sets.items():
        cfg.set(k, v)
    info = mubuild.build(cfg, out, log=lambda *a: None)
    return cfg, info


def build_app(gcc, mcu, hz, name, boot_size, out, stage=False, fmt="ihex"):
    elf = out / f"{name}.elf"
    cmd = [gcc, f"-mmcu={mcu}", f"-DF_CPU={hz}UL", "-Os", f'-DNAME="{name}"', f"-DMU_BOOT_SIZE={boot_size}UL",
           f"-I{ROOT / 'client'}", f"-I{ROOT / 'lite'}", str(ROOT / "tests/avr/app.c"), "-o", str(elf)]
    if stage:
        cmd.insert(1, "-DSTAGE_TEST")
    subprocess.run(cmd, check=True)
    hexf = out / f"{name}.hex"
    subprocess.run([_tool(gcc, "objcopy"), "-O", fmt, "-R", ".eeprom", str(elf), str(hexf)], check=True)
    return hexf


def main():
    gcc = mubuild.avr_gcc()
    if not gcc:
        raise SystemExit("avr-gcc not found")
    db = Db()
    work = Path(tempfile.mkdtemp(prefix="mu-avr-"))
    board = os.environ.get("MU_AVR_BOARD", "uno")
    t = db.target(board)
    mcu, hz = t.get("mcu"), t.board.get("f_cpu", 16000000)
    base = {"ENTRY": "every-reset", "TIMEOUT_MS": "2000"}
    spec = {"work": to_linux(work)}
    variants = {
        "default": {},
        "trial": {"LITE_TRIAL": True, "LITE_TRIES": 2},
        "stage": {"SPM_API": True, "STAGED_UPDATE": True},
    }
    if os.environ.get("MU_AVR_ONLY"):
        variants = {k: v for k, v in variants.items() if k in os.environ["MU_AVR_ONLY"].split(",")}
    for name, extra in variants.items():
        out = work / name
        cfg, info = build_boot(db, board, {**base, **extra}, out)
        boot = info["flash_region"]
        print(f"{name}: {info['flash_used']} bytes in a {boot}-byte boot section")
        v1 = build_app(gcc, mcu, hz, "v1", boot, out, stage=name == "stage")
        entry = {"board": board, "mcu": mcu, "part": PARTS[mcu], "hz": hz, "boot_elf": to_linux(out / "mimiboot-lite.hex"),
                 "boot_start": info["boot_start"], "app_v1": to_linux(v1), "page": t.get("page")}
        if name == "stage":
            v2 = build_app(gcc, mcu, hz, "v2", boot, out, stage=True, fmt="binary")
            entry["app_v2_bin"] = to_linux(v2)
        spec[name] = entry
    (work / "spec.json").write_text(json.dumps(spec, indent=2))
    runner = ROOT / "tests/avr/run_sim.py"
    if os.name == "nt":
        cmd = ["wsl", "-d", os.environ.get("MU_WSL_DISTRO", "Ubuntu-24.04"), "--", "python3", to_linux(runner),
               to_linux(work / "spec.json")]
    else:
        cmd = [sys.executable, str(runner), str(work / "spec.json")]
    rc = subprocess.run(cmd).returncode
    if not os.environ.get("MU_KEEP"):
        shutil.rmtree(work, ignore_errors=True)
    sys.exit(rc)


if __name__ == "__main__":
    main()
