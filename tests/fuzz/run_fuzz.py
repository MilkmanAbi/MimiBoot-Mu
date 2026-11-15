#!/usr/bin/env python3
"""Fuzz the parsers that take untrusted input, with libFuzzer + AddressSanitizer +
UndefinedBehaviorSanitizer (Linux / WSL, clang).

    python3 tests/fuzz/run_fuzz.py [seconds per target] [target ...]

Targets: smp (mcumgr frames, CBOR, uploads), recv (console uploads), config (the
boot config parser and the decision over it), flash (whatever is in the log,
config, slot headers, MCUboot TLVs and the protected store, then a boot decision).
A crash leaves its input in tests/fuzz/crashes/ and the run fails.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORE = ["mb_hash", "mb_ed25519", "mb_image", "mb_bcl", "mb_config", "mb_policy", "mb_recv", "mb_console",
        "mb_control", "mb_grub", "mb_formats", "mb_floor", "mb_ecdsa", "mb_stage0", "mb_smp", "mb_enc", "mb_lms", "mb_mailbox"]
TARGETS = ["smp", "recv", "config", "flash"]
FEATURES = ["-DMB_FEAT_SMP=1", "-DMB_FEAT_ENC=1", "-DMB_FEAT_REVOKE=1", "-DMB_FEAT_ECDSA=1", "-DMB_FEAT_IMG_MCUBOOT=1", "-DMB_FEAT_IMG_RAW=1", "-DMB_FEAT_LMS=1"]


def c_arrays(path):
    """name -> bytes, from a generated header of `static const uint8_t name[n] = { ... };`"""
    out = {}
    for m in re.finditer(r"uint8_t (\w+)\[\d+\] = \{([^}]*)\}", path.read_text()):
        out[m.group(1)] = bytes(int(x, 16) for x in m.group(2).replace(",", " ").split())
    return out


def seeds(target, d):
    d.mkdir(parents=True, exist_ok=True)
    if target == "smp":
        for name, data in c_arrays(ROOT / "tests/gen_smp.h").items():
            if name.startswith("smp_") and data[:2] == b"\x06\x09":
                # raw mode: the frames as a client sends them (encrypted uploads: with the board's key)
                (d / name).write_bytes((b"\x09" if "_enc" in name else b"\x11" if "_lms" in name else b"\x01") + data)
    elif target == "config":
        (d / "basic").write_bytes(b"default os\ntimeout 3\nentry os\n title A/B\n slot ab\n args quiet=1\n"
                                  b"entry rescue\n slot g\n arch arm\n")
    elif target == "flash":
        hdr = c_arrays(ROOT / "tests/gen_signed.h")["signed_good_hdr"]
        (d / "image-in-a").write_bytes(b"\x01" + b"\xff" * 0x4000 + hdr)
        # a RAM mailbox asking for the menu (bit 5), then a log and an image like the one above
        import struct
        mbox = bytearray(216)
        mbox[16] = 2                                    # end.reason: reboot
        struct.pack_into("<HHI", mbox, 80, 1, 128, 1)  # next: version 1, size 128, MB_CONTROL_MENU
        (d / "mailbox-menu").write_bytes(b"\x21" + bytes(mbox) + b"\xff" * 0x4000 + hdr)
    else:
        (d / "empty").write_bytes(b"\x00" * 300)


def main():
    secs = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 60
    targets = [t for t in sys.argv[1:] if t in TARGETS] or TARGETS
    cc = os.environ.get("FUZZ_CC") or shutil.which("clang") or "clang"
    work = Path(tempfile.mkdtemp(prefix="mu-fuzz-"))
    crashes = ROOT / "tests/fuzz/crashes"
    bad = []
    for t in targets:
        exe = work / f"fuzz_{t}"
        src = [f"core/{n}.c" for n in CORE] + ["tests/sim_port.c", f"tests/fuzz/fuzz_{t}.c"]
        r = subprocess.run([cc, "-g", "-O1", "-std=c11", "-fsanitize=fuzzer,address,undefined",
                            "-fno-sanitize-recover=undefined", "-D_GNU_SOURCE", *FEATURES, "-I.", "-Iinclude",
                            *src, "-o", str(exe)], cwd=ROOT, capture_output=True, text=True)
        if r.returncode:
            print(f"[{t}] build failed\n{r.stdout}{r.stderr}")
            bad.append(t)
            continue
        corpus, seed = work / f"corpus_{t}", work / f"seed_{t}"
        corpus.mkdir()
        seeds(t, seed)
        art = work / f"art_{t}"
        art.mkdir()
        r = subprocess.run([str(exe), f"-max_total_time={secs}", "-timeout=10", "-rss_limit_mb=2048",
                            "-print_final_stats=1", f"-artifact_prefix={art}/", str(corpus), str(seed)],
                           cwd=ROOT, capture_output=True, text=True)
        found = list(art.iterdir())
        stats = [ln for ln in r.stderr.splitlines() if ln.startswith(("stat::number_of_executed_units", "#")) and
                 ("DONE" in ln or "number_of" in ln)]
        print(f"[{t}] {'CRASH' if found or r.returncode else 'ok'}  " + "  ".join(s.strip() for s in stats[-2:]))
        if found or r.returncode:
            crashes.mkdir(exist_ok=True)
            for f in found:
                shutil.copy(f, crashes / f"{t}-{f.name}")
            print("\n".join(r.stderr.splitlines()[-40:]))
            bad.append(t)
    print(f"fuzz: {len(targets) - len(bad)}/{len(targets)} clean ({secs} s each)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
