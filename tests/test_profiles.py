#!/usr/bin/env python3
"""Build the Night core under named feature profiles (-Werror) and smoke-boot each
in the simulator; check that invalid combinations refuse to compile."""
import os, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ["mb_hash", "mb_ed25519", "mb_image", "mb_bcl", "mb_config", "mb_policy", "mb_recv", "mb_console",
        "mb_control", "mb_grub", "mb_formats"]
OFF_ALL = dict(CONSOLE=0, SHELL=0, SHELL_DIAG=0, RECV=0, CFG_FILE=0, GRUB=0, CONTROL=0, SIGNATURES=0, ANTI_ROLLBACK=0,
               RAM_IMAGES=0, HANDOFF=0, CRASH_GUARD=0, TRIAL_WATCHDOG=0)
NO_TRIAL = dict(AB_TRIAL=0, TRIAL_WATCHDOG=0)
PROFILES = {
    "full": {},
    "full+formats": dict(IMG_MCUBOOT=1, IMG_RAW=1),
    "minimal": OFF_ALL,
    "minimal+sig": {**OFF_ALL, "SIGNATURES": 1},
    "no-console": dict(CONSOLE=0, SHELL=0, SHELL_DIAG=0, RECV=0),
    "menu-only": dict(SHELL=0, SHELL_DIAG=0, RECV=0),
    "no-diagnostics": dict(SHELL_DIAG=0),
    "zephyr-only": {**OFF_ALL, "IMG_NATIVE": 0, "IMG_MCUBOOT": 1},
    "freertos-raw": {**OFF_ALL, "IMG_NATIVE": 0, "IMG_RAW": 1},
    "no-ab-trial": dict(**NO_TRIAL, IMG_MCUBOOT=1),
    "verify-once": dict(**NO_TRIAL, MB_BOOT_VERIFY=1, MB_MENU_SECS=3),
    "verify-never": dict(**NO_TRIAL, MB_BOOT_VERIFY=2),
    "verify-once+mcuboot": dict(**NO_TRIAL, MB_BOOT_VERIFY=1, IMG_MCUBOOT=1),
}
INVALID = {
    "recv-without-console": dict(CONSOLE=0, SHELL=0, SHELL_DIAG=0, RECV=1),
    "shell-without-console": dict(CONSOLE=0, RECV=0, SHELL_DIAG=0, SHELL=1),
    "recv-without-shell": dict(SHELL=0, SHELL_DIAG=0, RECV=1),
    "grub-without-cfg": dict(CFG_FILE=0, GRUB=1),
    "no-image-format": dict(IMG_NATIVE=0),
    "required-signature-hash-once": dict(MB_REQUIRE_SIGNATURE=1, MB_BOOT_VERIFY=1),
    "verify-out-of-range": dict(MB_BOOT_VERIFY=7),
}


def compiler():
    return os.environ.get("HOST_CC") or shutil.which("gcc") or shutil.which("clang") or "gcc"


def build(name, feats, out, expect_ok=True):
    hdr = out / f"cfg_{name}.h"
    hdr.write_text("".join(f"#define {k if k.startswith('MB_') else 'MB_FEAT_' + k} {v}\n" for k, v in feats.items()))
    exe = out / (f"profile_{name}" + (".exe" if os.name == "nt" else ""))
    src = [f"core/{n}.c" for n in CORE] + ["tests/sim_port.c", "tests/test_profile.c"]
    cmd = [compiler(), "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
           "-D_CRT_SECURE_NO_WARNINGS", f'-DMB_CONFIG_HEADER="{hdr.as_posix()}"', "-I.", "-Iinclude", *src, "-o", str(exe)]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if not expect_ok:
        msg = r.stderr + r.stdout
        return r.returncode != 0 and ("MB_" in msg or "image format" in msg)
    if r.returncode:
        print(r.stdout + r.stderr)
        return None
    return exe


def main():
    out = Path(tempfile.mkdtemp(prefix="mu-profiles-"))
    bad = 0
    for name, feats in PROFILES.items():
        exe = build(name, feats, out)
        if not exe:
            print(f"[{name}] BUILD FAILED"); bad += 1; continue
        r = subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True)
        last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "(no output)"
        print(f"[{name}] {last}")
        if r.returncode:
            print(r.stdout); bad += 1
    for name, feats in INVALID.items():
        refused = build(name, feats, out, expect_ok=False)
        print(f"[invalid {name}] {'refused (good)' if refused else 'COMPILED - consistency check missing'}")
        bad += 0 if refused else 1
    shutil.rmtree(out, ignore_errors=True)
    print("profiles: " + ("PASS" if not bad else f"{bad} FAILED"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
