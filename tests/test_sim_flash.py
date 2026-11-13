#!/usr/bin/env python3
"""Build and run the flash-driver model tests on the host (no hardware, no emulator):
port/samd/samd_flash.c against tests/sim_samd.c, once as SAM D21 and once as D51.
Needs a host C compiler (gcc / clang; HOST_CC overrides)."""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "samd21": ["-DMB_SAMD_SERIES=21", "-DMB_SAMD_ERASE=256u"],
    "samd51": ["-DMB_SAMD_SERIES=51", "-DMB_SAMD_ERASE=8192u"],
}


def main():
    cc = os.environ.get("HOST_CC") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise SystemExit("no host C compiler (set HOST_CC)")
    bad = 0
    with tempfile.TemporaryDirectory() as td:
        for name, defs in CASES.items():
            exe = Path(td) / (name + (".exe" if os.name == "nt" else ""))
            cmd = [cc, "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-DMB_HOST_SIM", "-DMB_FLASH_BASE=0u",
                   "-DMB_FLASH_SIZE=0x10000u", *defs, "-I.", "-Iinclude", "tests/sim_samd.c", "port/samd/samd_flash.c",
                   "-o", str(exe)]
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
            if r.returncode:
                print(f"[{name}] build failed:\n{r.stdout}{r.stderr}")
                bad += 1
                continue
            r = subprocess.run([str(exe)], capture_output=True, text=True)
            print(r.stdout.strip() + ("\n" + r.stderr.strip() if r.stderr.strip() else ""))
            bad += r.returncode != 0
    print("flash models:", "PASS" if not bad else "FAIL")
    return bad


if __name__ == "__main__":
    sys.exit(main())
