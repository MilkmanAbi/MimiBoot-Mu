#!/usr/bin/env python3
"""Boot MimiBoot-Mu (bare-metal STM32 port) in QEMU and check what it starts.

Needs: arm-none-eabi-gcc (Windows or Linux), qemu-system-arm (here, or in WSL),
imgtool + cryptography for the MCUboot case (IMGTOOL=path/to/imgtool).

QEMU has no STM32 flash controller, so every flash write fails (the port reads
back and reports MB_E_IO). That is fine for what this tests: golden images need
no log write to boot. Trial boots (which must record the attempt first) are
covered by the host tests, not here.
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from mu import build as mubuild  # noqa: E402
from mu.model import Config, Db  # noqa: E402

GCC = mubuild.arm_gcc()
OBJCOPY = mubuild._tool(GCC, "objcopy") if GCC else None
MACHINES = {"netduinoplus2": ("netduinoplus2", 0x40011000), "stm32vldiscovery": ("stm32vldiscovery", 0x40013800)}


def qemu_cmd():
    """-> (command prefix, path converter, wrap with GNU timeout?)
    Windows: WSL's QEMU unless MU_QEMU names a native binary (a Windows qemu on
    PATH - MSYS2 has one - is never picked by accident: Windows' timeout.exe is
    a different program)."""
    if os.environ.get("MU_QEMU"):
        return [os.environ["MU_QEMU"]], lambda p: str(p), False
    if os.name == "nt":
        if not shutil.which("wsl"):
            raise SystemExit("qemu: set MU_QEMU to a qemu-system-arm binary, or install it in WSL")

        def wslpath(p):
            p = Path(p).resolve()
            return "/mnt/" + p.drive[0].lower() + p.as_posix()[2:]
        return ["wsl", "-d", os.environ.get("MU_WSL_DISTRO", "Ubuntu-24.04"), "--", "qemu-system-arm"], wslpath, True
    if shutil.which("qemu-system-arm"):
        return ["qemu-system-arm"], lambda p: str(p), True
    raise SystemExit("qemu-system-arm not found")

def run(cmd, **kw):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    if r.returncode:
        raise RuntimeError(f"{cmd[0]} failed:\n{r.stdout}{r.stderr}")
    return r.stdout


def build_app(work: Path, name: str, origin: int, uart: int, ram_kb: int) -> Path:
    ld = work / f"{name}.ld"
    ld.write_text(f"""MEMORY {{ FLASH (rx) : ORIGIN = 0x{origin:08x}, LENGTH = 64K
         RAM (rwx) : ORIGIN = 0x20000000, LENGTH = {ram_kb}K }}
_estack = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS {{ .isr_vector : {{ KEEP(*(.isr_vector)) }} > FLASH
  .text : {{ *(.text*) *(.rodata*) }} > FLASH
  .noinit (NOLOAD) : {{ *(.noinit*) }} > RAM }}
""")
    elf = work / f"{name}.elf"
    run([GCC, "-mcpu=cortex-m3", "-mthumb", "-Os", "-nostdlib", "-ffreestanding", f'-DNAME="{name}"',
         f"-DUART=0x{uart:08x}u", f"-I{ROOT / 'include'}", ROOT / "tests/qemu/app.c", f"-T{ld}", "-o", elf])
    return elf


def build_client_app(work: Path, cfg, origin: int, uart: int, cfg_header: Path) -> Path:
    """an app linked against the MimiBoot client (client.txt recipe)"""
    from mu.gen import client_sources
    ld = work / "client.ld"
    ld.write_text(f"""MEMORY {{ FLASH (rx) : ORIGIN = 0x{origin:08x}, LENGTH = 96K
         RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K }}
_estack = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS {{ .isr_vector : {{ KEEP(*(.isr_vector)) }} > FLASH
  .text : {{ *(.text*) *(.rodata*) . = ALIGN(4); }} > FLASH
  .ARM.exidx : {{ *(.ARM.exidx*) }} > FLASH
  _sidata = LOADADDR(.data);
  .data : {{ _sdata = .; *(.data*) . = ALIGN(4); _edata = .; }} > RAM AT > FLASH
  .bss (NOLOAD) : {{ _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; }} > RAM
  .noinit (NOLOAD) : {{ *(.noinit*) }} > RAM
  end = .; _end = end; }}
""")
    elf = work / "client.elf"
    run([GCC, "-mcpu=cortex-m4", "-mthumb", "-Os", "-ffunction-sections", "-fdata-sections", "-DMB_CM_CLIENT",
         f'-DMB_CONFIG_HEADER="{cfg_header.as_posix()}"', f"-DUART=0x{uart:08x}u", f"-I{ROOT}", f"-I{ROOT / 'include'}",
         ROOT / "tests/qemu/client_app.c", *[ROOT / s for s in client_sources(cfg)], "-nostartfiles", "--specs=nano.specs",
         "--specs=nosys.specs", "-Wl,--gc-sections", f"-T{ld}", "-o", elf])
    return elf


def mbtool(*args):
    return run([sys.executable, ROOT / "tools/mbtool.py", *args])


def flash_image(work: Path, name: str, flash_size: int, boot_bin: Path, slot_off: int, payload: bytes) -> Path:
    img = bytearray(b"\xff" * flash_size)
    b = boot_bin.read_bytes()
    img[:len(b)] = b
    img[slot_off:slot_off + len(payload)] = payload
    p = work / f"{name}.flash.bin"
    p.write_bytes(img)
    return p


def boot(machine: str, flash: Path, seconds=3.0, keys: bytes | None = None) -> str:
    """Run QEMU for `seconds`, return everything the console printed. QEMU is
    stopped by `timeout` on its own side so its output is flushed (killing
    wsl.exe from Windows loses whatever the relay still holds)."""
    q, conv, wrap = qemu_cmd()
    if wrap:
        i = len(q) - 1
        q = q[:i] + ["timeout", str(seconds)] + q[i:]
    cmd = q + ["-M", machine, "-display", "none", "-monitor", "none", "-serial", "stdio", "-kernel", conv(flash)]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if keys:
        time.sleep(0.3)                      # spam a key through the 300 ms break-in window
        for _ in range(30):
            try:
                p.stdin.write(keys)
                p.stdin.flush()
            except OSError:
                break
            time.sleep(0.03)
    if not wrap:                         # a native process: stop it ourselves
        time.sleep(seconds)
        p.kill()
    out, _ = p.communicate(timeout=seconds + 30)
    return out.decode(errors="replace")


class QemuSerial:
    """A running QEMU whose console is driven like a serial port, so mbtool's own
    upload code (to_shell / send_image) talks to the emulated bootloader."""

    def __init__(self, machine: str, flash: Path, seconds: float):
        import queue
        import threading
        q, conv, wrap = qemu_cmd()
        if wrap:
            i = len(q) - 1
            q = q[:i] + ["timeout", str(seconds)] + q[i:]
        cmd = q + ["-M", machine, "-display", "none", "-monitor", "none", "-serial", "stdio", "-kernel", conv(flash)]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.q = queue.Queue()
        self.log = b""

        def pump():
            while True:
                b = self.p.stdout.read1(4096)
                if not b:
                    break
                self.q.put(b)
        threading.Thread(target=pump, daemon=True).start()

    def read(self, n):
        import queue
        try:
            b = self.q.get(timeout=0.1)
        except queue.Empty:
            return b""
        self.log += b
        return b

    def write(self, b):
        self.p.stdin.write(b)
        self.p.stdin.flush()

    def close(self):
        try:
            self.p.kill()
        except OSError:
            pass
        while True:                          # whatever is still queued goes into the log
            b = self.read(4096)
            if not b:
                break
        return self.log.decode(errors="replace")


def build_nrf_app(work: Path, name: str, origin: int, ram_base: int, ram_end: int, probe: int,
                  check: tuple | None = None) -> Path:
    ld = work / f"{name}.ld"
    ld.write_text(f"""MEMORY {{ FLASH (rx) : ORIGIN = 0x{origin:08x}, LENGTH = 32K
         RAM (rwx) : ORIGIN = 0x{ram_base:08x}, LENGTH = 0x{ram_end - ram_base:x} }}
_estack = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS {{ .isr_vector : {{ KEEP(*(.isr_vector)) }} > FLASH
  .text : {{ *(.text*) *(.rodata*) }} > FLASH
  .bss (NOLOAD) : {{ *(.bss*) *(COMMON) }} > RAM
  .noinit (NOLOAD) : {{ *(.noinit*) }} > RAM }}
""")
    elf = work / f"{name}.elf"
    run([GCC, "-mcpu=cortex-m0", "-mthumb", "-Os", "-nostdlib", "-ffreestanding", f'-DNAME="{name}"',
         f"-DPROBE=0x{probe:08x}u", f"-I{ROOT / 'include'}", ROOT / "tests/qemu/nrf_app.c", f"-T{ld}", "-o", elf,
         *([f"-DCHECK_LO=0x{check[0]:08x}u", f"-DCHECK_HI=0x{check[1]:08x}u"] if check else [])])
    return elf


def nrf51_tests(work: Path, db, check):
    """micro:bit (nRF51822) in QEMU: the nRF port's NVMC, UART, TIMER and the
    vector relay all run for real (QEMU models the nRF51 NVMC)."""
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool as mbt
    board, machine = "microbit", "microbit"
    cfg = Config(db, board)
    cfg.set("LAYOUT", "ab+golden")
    out = work / board
    info = mubuild.build(cfg, out, log=lambda *a: None)
    lay = json.loads((out / "layout.json").read_text())
    print(f"\n{board}: bootloader {info['flash_used']} B flash, {info['ram_used']} B RAM (+{info['stack']} stack)")
    boot_bin = out / "mimiboot.bin"
    flash = lay["flash_size"]
    ram_lo = lay["ram_base"] + lay["ram_reserved"]
    ram_hi = lay["ram_base"] + 16 * 1024
    g = next(s for s in lay["slots"] if s["name"] == "g")
    a = next(s for s in lay["slots"] if s["name"] == "a")
    probe = flash - 4                        # the last word: in no region the tests write

    # 1. nothing installed: the console comes up on the UART (TIMER-driven break-in, then the menu)
    o = boot(machine, flash_image(work, "nrf-empty", flash, boot_bin, g["offset"], b""), seconds=3.0)
    check(f"{board}: empty board: console reports nothing bootable", "nothing bootable" in o, o)

    # 2. a MimiBoot image in golden: started, exceptions and IRQs relayed to its table
    elf = build_nrf_app(work, "nrf-golden", g["link_native"], ram_lo, ram_hi, probe)
    mimg = work / "nrf-golden.mimg"
    mbtool("pack", str(elf), "--target", lay["target"], "-o", str(mimg), "--golden", "--version", "1.0.0")
    o = boot(machine, flash_image(work, "nrf-golden", flash, boot_bin, g["offset"], mimg.read_bytes()))
    check(f"{board}: golden image boots", "MU-APP nrf-golden" in o and "slot=g" in o, o)
    check(f"{board}: relay word points at the image's vector table", f"relay={g['link_native']:08x}" in o, o)
    check(f"{board}: SVC and NVIC interrupt reach the image's handlers through the relay",
          "svc=00000001" in o and "irq=00000001" in o, o)
    check(f"{board}: interrupts enabled at entry (PRIMASK=0)", "primask=00000000" in o, o)
    check(f"{board}: emulator NVMC ignores a write without WEN (so flash checks mean something)",
          "nowen=ffffffff" in o, o)

    # 3. upload over the console (mbtool's own protocol code) into slot a: NVMC erase +
    #    program + read-back + boot-log writes, then boot what was written
    elf = build_nrf_app(work, "nrf-uploaded", a["link_native"], ram_lo, ram_hi, probe)
    img_path = work / "nrf-uploaded.mimg"
    mbtool("pack", str(elf), "--target", lay["target"], "-o", str(img_path), "--version", "2.0.0")
    img, h, payload = mbt.checked_image(str(img_path))
    s = QemuSerial(machine, flash_image(work, "nrf-upload", flash, boot_bin, g["offset"], b""), seconds=40)
    ok, note = False, ""
    try:
        mbt.read_until(s, r"up/down \+ enter", 10)     # the menu is up and reading keys
        # 'c' opens the command line. Retry rather than mbtool's Enter fallback (which
        # would boot the selection): the first key through WSL's stdin relay can be slow.
        for _ in range(3):
            s.write(b"c")
            if mbt.read_until(s, r"mimiboot(?:\x1b\[0m)?> $", 6)[1]:
                break
        s.write(b"\x15recv a\r")                    # Ctrl-U first: drop a 'c' that arrived late
        mbt.send_image(s, img, payload)
        ok = True
        s.write(b"verify a\r")
        mbt.read_until(s, r"mimiboot(?:\x1b\[0m)?> $", 5)
        s.write(b"boot a\r")
        mbt.read_until(s, r"MU-APP-DONE", 10)
    except SystemExit as e:                  # mbtool's die()
        note = f"mbtool: {e}"
    o = s.close()
    check(f"{board}: image uploaded over the UART (flash erase/program verified)", ok and "MB DONE" in o, note + "\n" + o[-1500:])
    check(f"{board}: the uploaded image verifies and boots from slot a",
          "MU-APP nrf-uploaded" in o and "slot=a" in o and f"relay={a['link_native']:08x}" in o, o[-1500:])

    # 4. 'wipe the bootloader's RAM' + a menu-only console (no command line): the app finds
    #    the loader's RAM region zeroed (the default build above leaves it dirty), its
    #    handoff intact, and the menu offers no command line
    def loader_range(inf):
        lo = lay["ram_base"] + 16 * 1024 - inf["ram_region"]
        return lo, ram_hi - 512                  # the app's own stack is in the top 512 bytes
    cfg2 = Config(db, board)
    cfg2.set("LAYOUT", "ab+golden")
    for k, v in (("SCRUB_RAM", True), ("SHELL", False)):
        cfg2.set(k, v)
    out2 = work / f"{board}-scrub"
    info2 = mubuild.build(cfg2, out2, log=lambda *a: None)
    print(f"{board} (scrub, menu only): bootloader {info2['flash_used']} B flash")
    rng = loader_range(info2)
    elf = build_nrf_app(work, "nrf-scrub", g["link_native"], ram_lo, ram_hi, probe, check=rng)
    simg = work / "nrf-scrub.mimg"
    mbtool("pack", str(elf), "--target", lay["target"], "-o", str(simg), "--golden", "--version", "1.0.0")
    o = boot(machine, flash_image(work, "nrf-scrub-def", flash, boot_bin, g["offset"], simg.read_bytes()))
    check(f"{board}: without the wipe the loader's RAM is left dirty (so the check means something)",
          "MU-APP nrf-scrub" in o and "loaderram-dirty=00000000" not in o, o)
    o = boot(machine, flash_image(work, "nrf-scrub", flash, out2 / "mimiboot.bin", g["offset"], simg.read_bytes()))
    check(f"{board}: SCRUB_RAM: the loader's RAM region is all zero when the image starts",
          "loaderram-dirty=00000000" in o, o)
    check(f"{board}: SCRUB_RAM: the handoff survives the wipe", "slot=g" in o and "svc=00000001" in o, o)
    s = QemuSerial(machine, flash_image(work, "nrf-menuonly", flash, out2 / "mimiboot.bin", g["offset"], b""), seconds=12)
    mbt.read_until(s, r"up/down \+ enter", 10)
    s.write(b"c")
    mbt.read_until(s, r"mimiboot(?:\x1b\[0m)?> $", 4)
    o = s.close()
    check(f"{board}: menu-only console: no command line offered or opened",
          "up/down + enter" in o and "c  command line" not in o and "command line. 'help'" not in o, o[-1500:])

def main():
    if not GCC:
        raise SystemExit("arm-none-eabi-gcc not found")
    only = sys.argv[1:]                      # e.g. "microbit" or "netduinoplus2"
    imgtool = os.environ.get("IMGTOOL") or shutil.which("imgtool")
    work = Path(tempfile.mkdtemp(prefix="mu-qemu-"))
    db = Db()
    results = []

    def check(name, ok, out=""):
        results.append((name, ok))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            print("   output: " + out.strip().replace("\n", "\n           ")[:1500])

    # keys: one trusted, one not
    mbtool("keygen", "--out", str(work / "trusted"))
    mbtool("keygen", "--out", str(work / "stranger"))

    if not only or "microbit" in only:
        nrf51_tests(work, db, check)

    for board in ("netduinoplus2", "stm32vldiscovery"):
        if only and board not in only:
            continue
        machine, uart = MACHINES[board]
        cfg = Config(db, board)
        cfg.set("LAYOUT", "ab+golden")
        if board == "netduinoplus2":
            cfg.set("IMG_MCUBOOT", True)
            cfg.set("IMG_RAW", True)
            cfg.set("KEYS", str(work / "trusted.pub"))
        else:   # 8 KB of RAM: the lean profile
            for k in ("SIGNATURES", "RECV", "CONTROL", "RAM_IMAGES"):
                cfg.set(k, False)
        out = work / board
        info = mubuild.build(cfg, out, log=lambda *a: None)
        lay = json.loads((out / "layout.json").read_text())
        print(f"\n{board}: bootloader {info['flash_used']} B flash, {info['ram_used']} B RAM (+{info['stack']} stack)")
        g = next(s for s in lay["slots"] if s["name"] == "g")
        boot_bin = out / "mimiboot.bin"
        ram_kb = 4

        # 1. MimiBoot image in golden (signed with the trusted key on the F405)
        elf = build_app(work, f"{board}-native", g["link_native"], uart, ram_kb)
        mimg = work / f"{board}-native.mimg"
        args = ["pack", str(elf), "--target", lay["target"], "-o", str(mimg), "--golden", "--version", "1.0.0"]
        if board == "netduinoplus2":
            args += ["--key", str(work / "trusted.key")]
        mbtool(*args)
        o = boot(machine, flash_image(work, f"{board}-native", lay["flash_size"], boot_bin, g["offset"], mimg.read_bytes()))
        check(f"{board}: MimiBoot image in golden boots", f"MU-APP {board}-native" in o and "slot=g" in o, o)
        check(f"{board}: VTOR points at the image", f"vtor={g['link_native']:08x}" in o, o)
        check(f"{board}: interrupts enabled at entry (PRIMASK=0)", "primask=00000000" in o, o)

        # 2. the same image with one payload byte flipped: refused, console says nothing bootable
        bad = bytearray(mimg.read_bytes())
        bad[0x1000 + 40] ^= 0x01
        o = boot(machine, flash_image(work, f"{board}-corrupt", lay["flash_size"], boot_bin, g["offset"], bytes(bad)))
        check(f"{board}: corrupted image is not started", "MU-APP" not in o and "nothing bootable" in o, o)

        # 3. break-in: a key right after reset opens the menu instead of booting
        o = boot(machine, flash_image(work, f"{board}-native", lay["flash_size"], boot_bin, g["offset"], mimg.read_bytes()),
                 seconds=3.0, keys=b" ")
        check(f"{board}: UART break-in opens the menu", "MimiBoot" in o and "MU-APP" not in o, o)

        if board != "netduinoplus2":
            continue

        # 4. signed by a key the bootloader doesn't trust: refused
        mbtool("pack", str(elf), "--target", lay["target"], "-o", str(work / "stranger.mimg"), "--golden",
               "--key", str(work / "stranger.key"))
        o = boot(machine, flash_image(work, "stranger", lay["flash_size"], boot_bin, g["offset"],
                                      (work / "stranger.mimg").read_bytes()))
        check(f"{board}: image signed by an untrusted key is refused", "MU-APP" not in o and "nothing bootable" in o, o)

        # 5. raw firmware (FreeRTOS-style: vector table at the slot start)
        raw_elf = build_app(work, "raw", g["link_raw"], uart, ram_kb)
        raw_bin = work / "raw.bin"
        run([OBJCOPY, "-O", "binary", raw_elf, raw_bin])
        o = boot(machine, flash_image(work, "raw", lay["flash_size"], boot_bin, g["offset"], raw_bin.read_bytes()))
        check(f"{board}: raw firmware at the slot start boots", "MU-APP raw" in o and f"vtor={g['link_raw']:08x}" in o, o)

        # 6. an app using the client library: knows its slot, takes the handoff
        celf = build_client_app(work, cfg, g["link_native"], uart, out / "mimiboot_config.h")
        cimg = work / "client.mimg"
        mbtool("pack", str(celf), "--target", lay["target"], "-o", str(cimg), "--golden", "--key", str(work / "trusted.key"))
        o = boot(machine, flash_image(work, "client", lay["flash_size"], boot_bin, g["offset"], cimg.read_bytes()))
        check(f"{board}: client library: slot from VTOR, validated handoff", "MU-CLIENT slot=2" in o and "handoff=1" in o, o)

        # 7. Zephyr/MCUboot image signed by imgtool with an Ed25519 key
        if not imgtool:
            print("[SKIP] MCUboot cases: set IMGTOOL")
            continue
        mc_elf = build_app(work, "mcuboot", g["link_mcuboot"], uart, ram_kb)
        mc_bin = work / "mcuboot.bin"
        run([OBJCOPY, "-O", "binary", mc_elf, mc_bin])
        key = work / "ed.pem"
        run([imgtool, "keygen", "-k", key, "-t", "ed25519"])
        pub = subprocess.run([str(Path(imgtool).with_name("python")), "-c",
                              "import sys;from cryptography.hazmat.primitives import serialization as s;"
                              "k=s.load_pem_private_key(open(sys.argv[1],'rb').read(),None);"
                              "print(k.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw).hex())", str(key)],
                             capture_output=True, text=True, check=True).stdout.strip()
        signed = work / "mcuboot.signed.bin"
        run([imgtool, "sign", "--header-size", "0x200", "--pad-header", "--align", "8", "--version", "1.2.3",
             "--slot-size", hex(g["size"]), "--key", key, mc_bin, signed])
        # the bootloader built above trusts only trusted.pub: rebuild trusting the imgtool key
        (work / "ed.pub").write_text(pub + "\n")
        cfg.set("KEYS", str(work / "ed.pub"))
        cfg.set("REQUIRE_SIGNATURE", True)
        out2 = work / f"{board}-mcuboot-build"
        mubuild.build(cfg, out2, log=lambda *a: None)
        o = boot(machine, flash_image(work, "mcuboot", lay["flash_size"], out2 / "mimiboot.bin", g["offset"],
                                      signed.read_bytes()))
        check(f"{board}: imgtool-signed Zephyr/MCUboot image boots (signature required)",
              "MU-APP mcuboot" in o and f"vtor={g['link_mcuboot']:08x}" in o, o)
        tampered = bytearray(signed.read_bytes())
        tampered[0x200 + 64] ^= 0x01
        o = boot(machine, flash_image(work, "mcuboot-bad", lay["flash_size"], out2 / "mimiboot.bin", g["offset"],
                                      bytes(tampered)))
        check(f"{board}: tampered MCUboot image is refused", "MU-APP" not in o and "nothing bootable" in o, o)
        unsigned = work / "mcuboot.unsigned.bin"
        run([imgtool, "sign", "--header-size", "0x200", "--pad-header", "--align", "8", "--version", "1.2.3",
             "--slot-size", hex(g["size"]), mc_bin, unsigned])
        o = boot(machine, flash_image(work, "mcuboot-unsigned", lay["flash_size"], out2 / "mimiboot.bin", g["offset"],
                                      unsigned.read_bytes()))
        check(f"{board}: unsigned MCUboot image refused when signatures are required", "MU-APP" not in o and "nothing bootable" in o, o)

    if not os.environ.get("MU_QEMU_KEEP"):
        shutil.rmtree(work, ignore_errors=True)
    else:
        print("kept", work)
    bad = [n for n, ok in results if not ok]
    print(f"\nqemu: {len(results) - len(bad)}/{len(results)} passed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
