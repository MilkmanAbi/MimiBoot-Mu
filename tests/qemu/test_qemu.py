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
        # Spam a key from the start through the 300 ms break-in window. No delay
        # first: QEMU holds serial input until the UART reads it, and on a fast
        # host the window can be over before a fixed delay ends (seen on CI).
        for _ in range(50):
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

    def __init__(self, machine: str, flash: Path, seconds: float, keep: bool = False):
        """keep: a monitor is listening, and keep_flash() saves flash over `flash` (see boot_keep)"""
        import queue
        import random
        import threading
        q, conv, wrap = qemu_cmd()
        self.flash, self.conv = flash, conv
        self.port = random.randint(20000, 40000) if keep else None
        if wrap:
            i = len(q) - 1
            q = q[:i] + ["timeout", str(seconds)] + q[i:]
        mon = f"tcp:127.0.0.1:{self.port},server,nowait" if keep else "none"
        cmd = q + ["-M", machine, "-display", "none", "-monitor", mon, "-serial", "stdio", "-kernel", conv(flash)]
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

    def keep_flash(self, size: int):
        """power off: flash as it is now goes back into the image file"""
        dump = self.flash.with_suffix(".dump")
        dump.unlink(missing_ok=True)
        said = monitor_send(self.port, [f'memsave 0 {size} "{self.conv(dump)}"', "quit"])
        self.p.wait(timeout=60)
        data = dump.read_bytes() if dump.exists() else b""
        if len(data) != size:
            raise RuntimeError(f"memsave gave {len(data)} bytes, wanted {size}; monitor: {said}")
        if data[:8] != self.flash.read_bytes()[:8]:
            raise RuntimeError("the flash dump doesn't start with the image's vector table: not saving it")
        self.flash.write_bytes(data)

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
                  check: tuple | None = None, floor_at: int | None = None, store_at: int | None = None,
                  record: bool = False) -> Path:
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
         *([f"-DCHECK_LO=0x{check[0]:08x}u", f"-DCHECK_HI=0x{check[1]:08x}u"] if check else []),
         *([f"-DFLOOR_AT=0x{floor_at:08x}u"] if floor_at is not None else []),
         *([f"-DSTORE_AT=0x{store_at:08x}u"] if store_at is not None else []),
         *(["-DRECORD=1"] if record else [])])
    return elf


def monitor_send(port: int, cmds: list[str]) -> str:
    """Commands to a QEMU monitor listening on 127.0.0.1:port (in WSL when QEMU is).
    -> what the monitor said (its line editor echoes; the last lines are the answers)."""
    script = ("import socket,time,sys\n"
              "s=None\n"
              "for _ in range(50):\n"
              "    try:\n"
              f"        s=socket.create_connection(('127.0.0.1',{port}),5); break\n"
              "    except OSError: time.sleep(0.2)\n"
              "if s is None: print('no monitor'); sys.exit(0)\n"
              "s.settimeout(2)\n"
              "def rx():\n"
              "    out=b''\n"
              "    try:\n"
              "        while True:\n"
              "            b=s.recv(65536)\n"
              "            if not b: break\n"
              "            out+=b\n"
              "            if out.endswith(b'(qemu) '): break\n"
              "    except OSError: pass\n"
              "    return out\n"
              "rx()\n"
              + "".join(f"s.sendall({(c + chr(10)).encode()!r}); print(rx()[-300:])\n" for c in cmds))
    q, _, _ = qemu_cmd()
    if q[0] == "wsl":
        return run(q[:-1] + ["python3", "-c", script])
    return run([sys.executable, "-c", script])


def boot_keep(machine: str, flash: Path, size: int, seconds=6.0) -> str:
    """One power cycle whose flash writes are kept. QEMU writes the -kernel image
    back into flash on every reset (the nRF51's flash is a ROM *device*, so QEMU
    doesn't treat the image as written-once ROM), so writes made before a reset
    are lost. Here a boot runs for `seconds`, then the monitor saves flash over
    `flash` and quits: the next call starts where this one left off. (memsave,
    through the CPU: pmemsave reads QEMU's global address space, where the
    nRF51 SoC's flash isn't mapped, and gives zeros.)"""
    import random
    port = random.randint(20000, 40000)
    q, conv, _ = qemu_cmd()
    dump = flash.with_suffix(".dump")
    dump.unlink(missing_ok=True)
    cmd = q + ["-M", machine, "-display", "none", "-serial", "stdio",
               "-monitor", f"tcp:127.0.0.1:{port},server,nowait", "-kernel", conv(flash)]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(seconds)
    said = monitor_send(port, [f'memsave 0 {size} "{conv(dump)}"', "quit"])
    out, _ = p.communicate(timeout=60)
    data = dump.read_bytes() if dump.exists() else b""
    if len(data) != size:
        raise RuntimeError(f"memsave gave {len(data)} bytes, wanted {size}; monitor: {said}")
    if data[:8] != flash.read_bytes()[:8]:
        raise RuntimeError("the flash dump doesn't start with the image's vector table: not saving it")
    flash.write_bytes(data)
    return out.decode(errors="replace")


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

    # 5. BOOT_LOCK + PROTECTED_FLOOR: booting a golden image records its version in the
    #    floor store at the end of the bootloader region, through the real NVMC driver.
    #    (QEMU doesn't model the MPU block protection, so the lock itself isn't tested here.)
    cfg3 = Config(db, board)
    cfg3.set("LAYOUT", "ab+golden")
    for k in ("BOOT_LOCK", "PROTECTED_FLOOR"):
        cfg3.set(k, True)
    out3 = work / f"{board}-floor"
    info3 = mubuild.build(cfg3, out3, log=lambda *a: None)
    lay3 = json.loads((out3 / "layout.json").read_text())
    fl = lay3["floor"]
    print(f"{board} (lock + floor): bootloader {info3['flash_used']} B of {info3['flash_region']} B, floors at 0x{fl['offset']:x}")
    g3 = next(s for s in lay3["slots"] if s["name"] == "g")
    elf = build_nrf_app(work, "nrf-floor", g3["link_native"], ram_lo, ram_hi, probe, floor_at=fl["offset"])
    fimg = work / "nrf-floor.mimg"
    mbtool("pack", str(elf), "--target", lay3["target"], "-o", str(fimg), "--golden", "--version", "1.2.3")
    o = boot(machine, flash_image(work, "nrf-floor", flash, out3 / "mimiboot.bin", g3["offset"], fimg.read_bytes()))
    ver = (1 << 24) | (2 << 16) | 3
    want = f"floor=3146424d,{ver:08x},{(~ver) & 0xFFFFFFFF:08x},{(~0x3146424d) & 0xFFFFFFFF:08x}"
    check(f"{board}: PROTECTED_FLOOR: golden 1.2.3 recorded in the floor store ({want})",
          "MU-APP nrf-floor" in o and want in o, o)

    # 6. CONSOLE_AUTH: a locked console refuses changes; mbtool answers the challenge
    #    (nonce from the emulated nRF RNG) with the unlock key; a stranger's key is refused
    mbtool("keygen", "--out", str(work / "unlock"))
    cfg4 = Config(db, board)
    cfg4.set("LAYOUT", "ab+golden")
    cfg4.set("KEYS", str(work / "trusted.pub"))
    cfg4.set("CONSOLE_AUTH", True)
    cfg4.set("UNLOCK_KEYS", str(work / "unlock.pub"))
    out4 = work / f"{board}-auth"
    info4 = mubuild.build(cfg4, out4, log=lambda *a: None)
    print(f"{board} (console lock): bootloader {info4['flash_used']} B flash")
    gimg = flash_image(work, "nrf-auth", flash, out4 / "mimiboot.bin", g["offset"], b"")    # empty: the menu stays up
    prompt = r"mimiboot(?:\x1b\[0m)?> $"

    def session(steps):
        s = QemuSerial(machine, gimg, seconds=40)
        note = ""
        try:
            mbt.read_until(s, r"up/down \+ enter|booting \S+ in", 10)
            for _ in range(3):
                s.write(b"c")
                if mbt.read_until(s, prompt, 6)[1]:
                    break
            s.write(b"\x15\r")
            mbt.read_until(s, prompt, 3)
            steps(s)
        except SystemExit as e:
            note = f"mbtool: {e}"
        return s.close(), note

    def locked_then_unlocked(s):
        s.write(b"reject g\r")
        mbt.read_until(s, prompt, 5)
        mbt.unlock(s, str(work / "unlock.key"))
        s.write(b"reject g\r")
        mbt.read_until(s, r"g -> BAD", 5)

    o, note = session(locked_then_unlocked)
    check(f"{board}: CONSOLE_AUTH: 'reject' refused while locked", "locked: 'unlock' first" in o, note + o[-1500:])
    check(f"{board}: CONSOLE_AUTH: mbtool answers the challenge, the console unlocks", "MB UNLOCKED" in o, note + o[-1500:])
    check(f"{board}: CONSOLE_AUTH: after the unlock 'reject' runs", "g -> BAD" in o, note + o[-1500:])

    def wrong_key(s):
        mbt.unlock(s, str(work / "stranger.key"))

    o, note = session(wrong_key)
    check(f"{board}: CONSOLE_AUTH: a key not in UNLOCK_KEYS is refused",
          "MB ERR bad response (1 of 5)" in o and "MB UNLOCKED" not in o, note + o[-1500:])

    two_stage_tests(work, db, check, board, machine, ram_lo, ram_hi, probe)
    smp_tests(work, db, check, board, machine, ram_lo, ram_hi, probe, os.environ.get("IMGTOOL") or shutil.which("imgtool"))
    revoke_tests(work, db, check, board, machine, ram_lo, ram_hi, probe)
    enc_tests(work, db, check, board, machine, ram_lo, ram_hi, probe)
    record_tests(work, db, check, board, machine, ram_lo, ram_hi, probe)
    lms_tests(work, db, check, board, machine, ram_lo, ram_hi, probe)


def smp_request(s, req, timeout=15.0):
    """Send one SMP request (the smp package's message) over a QemuSerial and return
    (header, body dict) of the reply, parsed by the smp package's framing and cbor2."""
    import cbor2
    from smp import header as smphdr
    from smp import packet
    for line in packet.encode(req.BYTES, line_length=127):
        s.write(line)
    dec = packet.decode()
    next(dec)
    buf, end = b"", time.time() + timeout
    while time.time() < end:
        buf += s.read(4096)
        while True:
            starts = [i for i in (buf.find(b"\x06\x09"), buf.find(b"\x04\x14")) if i >= 0]
            if not starts or buf.find(b"\n", min(starts)) < 0:
                break
            i = min(starts)
            j = buf.find(b"\n", i)
            line, buf = buf[i:j + 1], buf[j + 1:]
            try:
                dec.send(line)
            except StopIteration as e:
                frame = e.value
                return smphdr.Header.loads(frame[:8]), cbor2.loads(frame[8:])
    raise TimeoutError(f"no SMP reply to {type(req).__name__}")


def smp_tests(work: Path, db, check, board, machine, ram_lo, ram_hi, probe, imgtool):
    """8. SMP (mcumgr) on the nRF51: requests and replies by the smp package, uploads
    written through the real NVMC, then booted after a power cycle."""
    try:
        from smp import image_management as img
        from smp import os_management as osm
    except ImportError:
        print("[SKIP] SMP cases: pip install smp (the independent client the test talks through)")
        return
    import hashlib
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool as mbt
    cfg = Config(db, board)
    cfg.set("LAYOUT", "ab+golden")
    cfg.set("SMP", True)
    cfg.set("IMG_MCUBOOT", True)
    out = work / f"{board}-smp"
    info = mubuild.build(cfg, out, log=lambda *a: None)
    lay = json.loads((out / "layout.json").read_text())
    slot = {s["name"]: s for s in lay["slots"]}
    fsize = lay["flash_size"]
    print(f"{board} (SMP): bootloader {info['flash_used']} B flash, {info['ram_used']} B RAM (+{info['stack']} stack)")
    elf = build_nrf_app(work, "smp-app", slot["a"]["link_native"], ram_lo, ram_hi, probe)   # a fresh board: "image 0" is a
    app = work / "smp-app.mimg"
    mbtool("pack", str(elf), "--target", lay["target"], "-o", str(app), "--version", "2.0.0")
    image = app.read_bytes()

    def upload(s, data, image_no=0, chunk=600):
        sha, last = hashlib.sha256(data).digest(), None
        for off in range(0, len(data), chunk):
            extra = {"image": image_no, "len": len(data), "sha": sha} if off == 0 else {}
            h, d = smp_request(s, img.ImageUploadWriteRequest(off=off, data=data[off:off + chunk], **extra))
            if "err" in d or d.get("rc", 0) or d.get("off") != min(off + chunk, len(data)):
                return d
            last = d
        return last

    flash = flash_image(work, "smp", fsize, out / "mimiboot.bin", slot["g"]["offset"], b"")   # nothing: the menu stays up
    s = QemuSerial(machine, flash, seconds=120, keep=True)
    notes, got = [], {}
    try:
        if not mbt.read_until(s, r"up/down \+ enter", 30)[1]:
            raise RuntimeError("the menu never came up")    # sent earlier, a request would be the break-in key
        h, got["params"] = smp_request(s, osm.MCUMgrParametersReadRequest())
        h, got["echo"] = smp_request(s, osm.EchoWriteRequest(d="mimiboot smp"))
        h, got["boot"] = smp_request(s, osm.BootloaderInformationReadRequest())
        h, got["list0"] = smp_request(s, img.ImageStatesReadRequest())
        got["up"] = upload(s, image)
        h, got["list1"] = smp_request(s, img.ImageStatesReadRequest())
        got["golden"] = upload(s, image, image_no=3)
        s.keep_flash(fsize)
    except (SystemExit, TimeoutError, RuntimeError) as e:
        notes.append(str(e))
    o = s.close()
    note = "\n".join(notes) + f"\n{got}\n"
    check(f"{board}: SMP: MCUmgr parameters (buf_size 1024)", got.get("params", {}).get("buf_size") == 1024, note + o[-1500:])
    check(f"{board}: SMP: echo", got.get("echo", {}).get("r") == "mimiboot smp", note)
    check(f"{board}: SMP: bootloader info", got.get("boot", {}).get("bootloader") == "MimiBoot", note)
    check(f"{board}: SMP: image list of an empty board", got.get("list0", {}).get("images") == [], note)
    check(f"{board}: SMP: a MimiBoot image uploaded through the NVMC driver, sha matched",
          (got.get("up") or {}).get("off") == len(image) and (got.get("up") or {}).get("match") is True, note)
    lst = (got.get("list1") or {}).get("images") or []
    check(f"{board}: SMP: the list shows it in slot a (no active slot yet), 2.0.0, pending",
          any(i.get("slot") == 0 and i.get("version") == "2.0.0" and i.get("pending") is True and
              i.get("hash") == hashlib.sha256(image[0x1000:]).digest() for i in lst), note)
    check(f"{board}: SMP: golden (image 3) refused", "err" in (got.get("golden") or {}), note)
    o = boot_keep(machine, flash, fsize)                   # power on with what SMP wrote
    check(f"{board}: SMP: after a power cycle the uploaded image boots from a",
          "MU-APP smp-app" in o and "slot=a" in o, o[-1500:])

    # signatures required: Ed25519 runs inside menu -> SMP -> upload on the M0 and its 6 KB stack.
    # An unsigned image is refused at its first page; a signed one goes in and boots.
    cfg_s = Config(db, board)
    cfg_s.set("LAYOUT", "ab+golden")
    cfg_s.set("SMP", True)
    cfg_s.set("KEYS", str(work / "trusted.pub"))
    cfg_s.set("REQUIRE_SIGNATURE", True)
    out_s = work / f"{board}-smp-signed"
    info_s = mubuild.build(cfg_s, out_s, log=lambda *a: None)
    lay_s = json.loads((out_s / "layout.json").read_text())
    sa = next(x for x in lay_s["slots"] if x["name"] == "a")
    print(f"{board} (SMP, signatures required): bootloader {info_s['flash_used']} B flash")
    elf = build_nrf_app(work, "smp-signed", sa["link_native"], ram_lo, ram_hi, probe)
    simg = work / "smp-signed.mimg"
    mbtool("pack", str(elf), "--target", lay_s["target"], "-o", str(simg), "--version", "2.1.0", "--key", str(work / "trusted.key"))
    uimg = work / "smp-unsigned.mimg"
    mbtool("pack", str(elf), "--target", lay_s["target"], "-o", str(uimg), "--version", "2.1.0")
    flash3 = flash_image(work, "smp-signed", fsize, out_s / "mimiboot.bin", slot["g"]["offset"], b"")
    s = QemuSerial(machine, flash3, seconds=120, keep=True)
    res_u = res_s = None
    notes = []
    try:
        if not mbt.read_until(s, r"up/down \+ enter", 30)[1]:
            raise RuntimeError("the menu never came up")
        res_u = upload(s, uimg.read_bytes())
        res_s = upload(s, simg.read_bytes())
        s.keep_flash(fsize)
    except (SystemExit, TimeoutError, RuntimeError) as e:
        notes.append(str(e))
    o = s.close()
    check(f"{board}: SMP signed: an unsigned image is refused at the first chunk", "err" in (res_u or {}),
          f"{notes} {res_u}\n{o[-800:]}")
    check(f"{board}: SMP signed: a signed image goes in (Ed25519 on the M0, inside the console)",
          (res_s or {}).get("off") == len(simg.read_bytes()) and (res_s or {}).get("match") is True, f"{notes} {res_s}\n{o[-800:]}")
    o = boot_keep(machine, flash3, fsize)
    check(f"{board}: SMP signed: ... and boots after a power cycle", "MU-APP smp-signed" in o and "slot=a" in o, o[-1500:])

    if not imgtool:
        print("[SKIP] SMP + imgtool image: set IMGTOOL")
        return
    # an imgtool-signed Zephyr/MCUboot image, uploaded with mcumgr's own image numbering (2 = slot b)
    mc = build_nrf_app(work, "smp-mcuboot", slot["b"]["link_mcuboot"], ram_lo, ram_hi, probe)
    mc_bin = work / "smp-mcuboot.bin"
    run([OBJCOPY, "-O", "binary", mc, mc_bin])
    signed = work / "smp-mcuboot.signed.bin"
    run([imgtool, "sign", "--header-size", "0x200", "--pad-header", "--align", "4", "--version", "3.1.0",
         "--slot-size", hex(slot["b"]["size"]), mc_bin, signed])
    data = signed.read_bytes()
    flash2 = flash_image(work, "smp-mc", fsize, out / "mimiboot.bin", slot["g"]["offset"], b"")
    s = QemuSerial(machine, flash2, seconds=120, keep=True)
    res, notes = None, []
    try:
        if not mbt.read_until(s, r"up/down \+ enter", 30)[1]:
            raise RuntimeError("the menu never came up")
        res = upload(s, data, image_no=2, chunk=480)
        s.keep_flash(fsize)
    except (SystemExit, TimeoutError, RuntimeError) as e:
        notes.append(str(e))
    o = s.close()
    check(f"{board}: SMP: an imgtool (MCUboot) image uploaded as image 2",
          (res or {}).get("off") == len(data) and (res or {}).get("match") is True, f"{notes} {res}\n{o[-800:]}")
    o = boot_keep(machine, flash2, fsize)
    check(f"{board}: SMP: ... and it boots after a power cycle (vector table at b + 0x200)",
          "MU-APP smp-mcuboot" in o and f"relay={slot['b']['link_mcuboot']:08x}" in o, o[-1500:])


def enc_tests(work: Path, db, check, board, machine, ram_lo, ram_hi, probe):
    """10. Encrypted images on the nRF51, signed and encrypted (signatures required):
    X25519, HKDF and AES-CTR on the M0 inside the console. One goes in with
    mbtool over the console, one over SMP (the smp package as the client);
    one made for another board is refused. Each boots after a power cycle."""
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool as mbt
    for k in ("board", "otherboard"):
        mbtool("keygen", "--type", "x25519", "--out", str(work / f"enc-{k}"), "--force")
    try:
        from smp import image_management as img
    except ImportError:
        img = None
        print("[SKIP] the SMP half of the encrypted-image cases: pip install smp")
    cfg = Config(db, board)
    cfg.set("LAYOUT", "ab+golden")
    for k, v in (("ENCRYPTED_IMAGES", True), ("ENC_KEY", str(work / "enc-board.key")), ("SHELL_DIAG", False),
                 ("KEYS", str(work / "trusted.pub")), ("REQUIRE_SIGNATURE", True), ("SMP", img is not None)):
        cfg.set(k, v)
    out = work / f"{board}-enc"
    info = mubuild.build(cfg, out, log=lambda *a: None)
    lay = json.loads((out / "layout.json").read_text())
    slot = {s["name"]: s for s in lay["slots"]}
    fsize = lay["flash_size"]
    print(f"{board} (encrypted images): bootloader {info['flash_used']} B flash, {info['ram_used']} B RAM")
    if img is not None:     # (with SMP: the loader takes all 16 KB of RAM)
        check(f"{board}: ENC: the builder says this build leaves no RAM for a handoff",
              any("no room for the boot handoff" in n for n in info["notes"]), str(info["notes"]))

    def packed(name, at, version, pub, bits=128):
        elf = build_nrf_app(work, name, slot[at]["link_native"], ram_lo, ram_hi, probe)
        p = work / f"{name}.mimg"
        mbtool("pack", str(elf), "--target", lay["target"], "-o", str(p), "--version", version, "--key",
               str(work / "trusted.key"), "--encrypt", str(work / f"enc-{pub}.pub"), "--encrypt-keylen", str(bits))
        return p.read_bytes()

    prompt = r"mimiboot(?:\x1b\[0m)?> $"

    def shell(s):
        if not mbt.read_until(s, r"up/down \+ enter", 30)[1]:
            raise RuntimeError("the menu never came up")
        for _ in range(3):
            s.write(b"c")
            if mbt.read_until(s, prompt, 6)[1]:
                return
        raise RuntimeError("no prompt")

    def payload(image):
        return image[mbt.PAYLOAD_OFF:]

    con = packed("enc-con", "a", "3.0.0", "board")
    stranger = packed("enc-other", "b", "3.0.1", "otherboard")
    flash = flash_image(work, "enc", fsize, out / "mimiboot.bin", slot["g"]["offset"], b"")
    s = QemuSerial(machine, flash, seconds=180, keep=True)
    notes, done = [], []
    try:
        shell(s)
        s.write(b"recv a\r")
        mbt.send_image(s, con, payload(con))
        done.append("a")
        mbt.read_until(s, prompt, 5)
        s.write(b"recv b\r")
        try:
            mbt.send_image(s, stranger, payload(stranger))
            done.append("b")
        except SystemExit as e:
            notes.append(f"b: {e}")
        mbt.read_until(s, prompt, 5)
        s.keep_flash(fsize)
    except (SystemExit, TimeoutError, RuntimeError) as e:
        notes.append(str(e))
    o = s.close()
    note = f"{notes} {done}\n{o[-1500:]}"
    check(f"{board}: ENC: a signed + encrypted image goes in over the console (mbtool install)", "a" in done, note)
    check(f"{board}: ENC: one encrypted for another board is refused before the erase",
          "b" not in done and "not encrypted for this device" in o, note)
    o = boot_keep(machine, flash, fsize)
    # (this build needs all 16 KB of RAM, so there is no handoff: where it runs from is the relay address)
    check(f"{board}: ENC: ... and after a power cycle the decrypted image boots from a",
          "MU-APP enc-con" in o and f"relay={slot['a']['link_native']:08x}" in o, o[-1500:])

    if img is None:
        return
    import hashlib
    smp_img = packed("enc-smp", "a", "3.1.0", "board", bits=256)
    flash2 = flash_image(work, "enc-smp", fsize, out / "mimiboot.bin", slot["g"]["offset"], b"")
    s = QemuSerial(machine, flash2, seconds=180, keep=True)
    res, notes = None, []
    try:
        if not mbt.read_until(s, r"up/down \+ enter", 30)[1]:
            raise RuntimeError("the menu never came up")
        sha, chunk = hashlib.sha256(smp_img).digest(), 600
        for off in range(0, len(smp_img), chunk):
            extra = {"image": 0, "len": len(smp_img), "sha": sha} if off == 0 else {}
            _, res = smp_request(s, img.ImageUploadWriteRequest(off=off, data=smp_img[off:off + chunk], **extra))
            if "err" in res or res.get("rc", 0):
                break
        s.keep_flash(fsize)
    except (SystemExit, TimeoutError, RuntimeError) as e:
        notes.append(str(e))
    o = s.close()
    check(f"{board}: ENC: an AES-256 one goes in over SMP (sha of the encrypted file matched)",
          (res or {}).get("off") == len(smp_img) and (res or {}).get("match") is True, f"{notes} {res}\n{o[-800:]}")
    o = boot_keep(machine, flash2, fsize)
    check(f"{board}: ENC: ... and boots after a power cycle",
          "MU-APP enc-smp" in o and f"relay={slot['a']['link_native']:08x}" in o, o[-1500:])


def record_tests(work: Path, db, check, board, machine, ram_lo, ram_hi, probe):
    """11. Measured boot on the nRF51: a signed image asks for a boot record; the
    app prints it and the test recomputes the bootloader hash from mimiboot.bin and
    the measurement from that and the image header, as a verifier would."""
    import hashlib
    import re
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool as mbt
    cfg = Config(db, board)
    cfg.set("LAYOUT", "ab+golden")
    for k, v in (("KEYS", str(work / "trusted.pub")), ("REQUIRE_SIGNATURE", True), ("BOOT_RECORD", True)):
        cfg.set(k, v)
    out = work / f"{board}-record"
    info = mubuild.build(cfg, out, log=lambda *a: None)
    lay = json.loads((out / "layout.json").read_text())
    slot = {s["name"]: s for s in lay["slots"]}
    print(f"{board} (boot record): bootloader {info['flash_used']} B flash, {info['ram_used']} B RAM")
    elf = build_nrf_app(work, "rec-app", slot["a"]["link_native"], ram_lo, ram_hi, probe, record=True)
    p = work / "rec-app.mimg"
    mbtool("pack", str(elf), "--target", lay["target"], "-o", str(p), "--version", "5.0.0", "--key", str(work / "trusted.key"))
    img = p.read_bytes()
    flash = flash_image(work, "record", lay["flash_size"], out / "mimiboot.bin", slot["a"]["offset"], img)
    o = boot(machine, flash, seconds=5)
    m = re.search(r"rec=([0-9a-f]{8})/([0-9a-f]{8}) loader=([0-9a-f]{64}) meas=([0-9a-f]{64})", o)
    loader = hashlib.sha256((out / "mimiboot.bin").read_bytes()).digest()
    meas = hashlib.sha256(b"MimiBoot measure v1\0" + loader + img[:mbt.SIGNED_BYTES]).hexdigest()
    key_id = int.from_bytes(bytes.fromhex((work / "trusted.pub").read_text().split()[0])[:4], "little")
    flags = int(m.group(1), 16) if m else 0
    check(f"{board}: RECORD: the image gets a boot record: signed, hashed, loader measured",
          bool(m) and flags & 0x0B == 0x0B and int(m.group(2), 16) == key_id, o[-1500:])
    check(f"{board}: RECORD: the loader hash is SHA-256 of mimiboot.bin", bool(m) and m.group(3) == loader.hex(),
          f"{m.group(3) if m else None} vs {loader.hex()}")
    check(f"{board}: RECORD: the measurement recomputes from mimiboot.bin and the image header",
          bool(m) and m.group(4) == meas, f"{m.group(4) if m else None} vs {meas}")


def lms_tests(work: Path, db, check, board, machine, ram_lo, ram_hi, probe):
    """12. LMS on the nRF51, a post-quantum-only build (no Ed25519 in it, signatures
    required): an image written straight into flash with its signature in the header
    sector boots (checked as it streams from flash on the M0); one with a flipped bit
    in its signature doesn't; one uploaded with mbtool over the console ('S' frame)
    goes in and boots after a power cycle."""
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool as mbt
    for k, w in (("lms4", "4"), ("lms8", "8")):
        mbtool("keygen", "--type", "lms", "--lms-height", "5", "--lms-w", w, "--out", str(work / k), "--force")
    keys = work / "lms-keys.pub"
    keys.write_text((work / "lms4.pub").read_text() + (work / "lms8.pub").read_text())
    cfg = Config(db, board)
    cfg.set("LAYOUT", "ab+golden")
    for k, v in (("SIGNATURES", False), ("LMS", True), ("KEYS", str(keys)), ("REQUIRE_SIGNATURE", True)):
        cfg.set(k, v)
    out = work / f"{board}-lms"
    info = mubuild.build(cfg, out, log=lambda *a: None)
    lay = json.loads((out / "layout.json").read_text())
    slot = {s["name"]: s for s in lay["slots"]}
    fsize = lay["flash_size"]
    print(f"{board} (LMS only): bootloader {info['flash_used']} B flash, {info['ram_used']} B RAM")

    def packed(name, at, version, key):
        elf = build_nrf_app(work, name, slot[at]["link_native"], ram_lo, ram_hi, probe)
        p = work / f"{name}.mimg"
        mbtool("pack", str(elf), "--target", lay["target"], "-o", str(p), "--version", version, "--key", str(work / f"{key}.key"))
        return p.read_bytes()

    a = packed("lms-a", "a", "6.0.0", "lms8")           # W8: the slow kind, checked on the M0
    bad = bytearray(packed("lms-b", "b", "6.0.1", "lms4"))
    bad[mbt.HDR_SIZE + 4 + 400] ^= 0x20
    flash = flash_image(work, "lms", fsize, out / "mimiboot.bin", slot["a"]["offset"], a)
    img = bytearray(flash.read_bytes())
    img[slot["b"]["offset"]:slot["b"]["offset"] + len(bad)] = bad
    flash.write_bytes(bytes(img))
    o = boot(machine, flash, seconds=8)
    check(f"{board}: LMS: a W8-signed image in a boots (no Ed25519 in this bootloader)", "MU-APP lms-a" in o, o[-1500:])
    check(f"{board}: LMS: the newer one in b, a bit flipped in its signature, is refused", "MU-APP lms-b" not in o, o[-1500:])

    up = packed("lms-up", "a", "6.1.0", "lms4")
    prompt = r"mimiboot(?:\x1b\[0m)?> $"
    flash2 = flash_image(work, "lms-up", fsize, out / "mimiboot.bin", slot["g"]["offset"], b"")   # empty: the menu
    s = QemuSerial(machine, flash2, seconds=120, keep=True)
    notes, done = [], False
    try:
        if not mbt.read_until(s, r"up/down \+ enter", 30)[1]:
            raise RuntimeError("the menu never came up")
        for _ in range(3):
            s.write(b"c")
            if mbt.read_until(s, prompt, 6)[1]:
                break
        s.write(b"recv a\r")
        mbt.send_image(s, up, up[mbt.PAYLOAD_OFF:])
        done = True
        mbt.read_until(s, prompt, 5)
        s.keep_flash(fsize)
    except (SystemExit, TimeoutError, RuntimeError) as e:
        notes.append(str(e))
    o = s.close()
    check(f"{board}: LMS: an LMS-signed image goes in over the console (MB SIG, 'S' frame)", done, f"{notes}\n{o[-1500:]}")
    o = boot_keep(machine, flash2, fsize, seconds=8)
    check(f"{board}: LMS: ... and boots after a power cycle", "MU-APP lms-up" in o, o[-1500:])


def revoke_tests(work: Path, db, check, board, machine, ram_lo, ram_hi, probe):
    """9. Key revocation on the nRF51: a statement from the revocation key, sent with
    mbtool's code, goes into the protected store; after a power cycle an image
    signed with the revoked key is refused and one signed with the other key boots."""
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool as mbt
    for k in ("img1", "img2", "revoker"):
        mbtool("keygen", "--out", str(work / k), "--force")
    (work / "img12.pub").write_text((work / "img1.pub").read_text() + (work / "img2.pub").read_text())
    cfg = Config(db, board)
    cfg.set("LAYOUT", "ab+golden")
    for k, v in (("BOOT_LOCK", True), ("PROTECTED_FLOOR", True), ("KEYS", str(work / "img12.pub")),
                 ("REQUIRE_SIGNATURE", True), ("REVOKE_KEYS", str(work / "revoker.pub"))):
        cfg.set(k, v)
    out = work / f"{board}-revoke"
    info = mubuild.build(cfg, out, log=lambda *a: None)
    lay = json.loads((out / "layout.json").read_text())
    g = next(s for s in lay["slots"] if s["name"] == "g")
    fsize = lay["flash_size"]
    print(f"{board} (key revocation): bootloader {info['flash_used']} B flash")
    elf = build_nrf_app(work, "rev-app", g["link_native"], ram_lo, ram_hi, probe)
    images = {}
    for k in ("img1", "img2"):
        p = work / f"rev-{k}.mimg"
        mbtool("pack", str(elf), "--target", lay["target"], "-o", str(p), "--golden", "--version", "1.0.0",
               "--key", str(work / f"{k}.key"))
        images[k] = p.read_bytes()
    id1 = int.from_bytes(bytes.fromhex((work / "img1.pub").read_text().split()[0])[:4], "little")
    flash = flash_image(work, "revoke", fsize, out / "mimiboot.bin", g["offset"], b"")
    prompt = r"mimiboot(?:\x1b\[0m)?> $"
    s = QemuSerial(machine, flash, seconds=60, keep=True)
    answers, notes = [], []
    try:
        if not mbt.read_until(s, r"up/down \+ enter", 30)[1]:
            raise RuntimeError("the menu never came up")
        for _ in range(3):
            s.write(b"c")
            if mbt.read_until(s, prompt, 6)[1]:
                break
        s.write(b"\x15\r")
        mbt.read_until(s, prompt, 3)
        answers.append(mbt.revoke_on(s, mbt.read_key(str(work / "img1.key")), lay["target"].encode(), id1))
        mbt.read_until(s, prompt, 3)
        answers.append(mbt.revoke_on(s, mbt.read_key(str(work / "revoker.key")), lay["target"].encode(), id1))
        mbt.read_until(s, prompt, 3)
        s.keep_flash(fsize)
    except (SystemExit, TimeoutError, RuntimeError) as e:
        notes.append(str(e))
    o = s.close()
    note = f"{notes} {answers}\n{o[-1200:]}"
    check(f"{board}: REVOKE: a statement signed by an image key is refused",
          len(answers) > 0 and "not signed by a revocation key" in answers[0], note)
    check(f"{board}: REVOKE: the revocation key's statement is taken", len(answers) > 1 and answers[1] == "MB REVOKED", note)
    for k, want in (("img1", False), ("img2", True)):
        f = work / f"revoke-{k}.flash.bin"
        img = bytearray(flash.read_bytes())
        img[g["offset"]:g["offset"] + len(images[k])] = images[k]
        f.write_bytes(bytes(img))
        o = boot(machine, f, seconds=5)
        if want:
            check(f"{board}: REVOKE: an image signed with the other key boots", "MU-APP rev-app" in o, o[-1200:])
        else:
            check(f"{board}: REVOKE: after a power cycle, an image signed with the revoked key is refused",
                  "MU-APP" not in o and "nothing bootable" in o, o[-1200:])


def two_stage_tests(work: Path, db, check, board, machine, ram_lo, ram_hi, probe):
    """7. TWO_STAGE on the nRF51: stage 0 at 0 picks a stage-1 copy and starts it
    through the vector relay; stage 1 records itself as working once it starts an
    app; a new stage 1 goes in over the console; one that never starts an app is
    counted and passed over. Store entries print as tag:value ('>' = stage 1
    worked, '?' = a boot of an unconfirmed one)."""
    import hashlib
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool as mbt
    cfg = Config(db, board)
    cfg.set("LAYOUT", "ab+golden")
    cfg.set("TWO_STAGE", True)
    out = work / f"{board}-2stage"
    info = mubuild.build(cfg, out, log=lambda *a: None)
    lay = json.loads((out / "layout.json").read_text())
    slot = {s["name"]: s for s in lay["slots"]}
    store = lay["floor"]["offset"]
    fsize = lay["flash_size"]
    print(f"{board} (two-stage): stage 0 {info['stage0_used']} B of {info['stage0_region']} B, "
          f"stage 1 {info['flash_used']} B in {slot['s1a']['size'] // 1024} KB copies, store at 0x{store:x}")

    def id32(payload):
        return int.from_bytes(hashlib.sha256(payload).digest()[4:8], "big")

    def stage1_image(name, payload, at, version, secret=None):
        hdr = mbt.build_header(payload, name, mbt.parse_version(version), target=lay["target"], arch=mbt.ARCH_ARM,
                               entry=slot[at]["offset"] + 0x1000, stage1=True, secret=secret)
        return hdr + b"\xff" * (0x1000 - len(hdr)) + payload

    def put(img, at, data):
        img[slot[at]["offset"]:slot[at]["offset"] + len(data)] = data

    factory = (out / "mimiboot.bin").read_bytes()
    s1a_payload = (out / "stage1-s1a.bin").read_bytes()
    s1b_payload = (out / "stage1-s1b.bin").read_bytes()
    elf = build_nrf_app(work, "nrf-2s", slot["g"]["link_native"], ram_lo, ram_hi, probe, store_at=store)
    gimg = work / "nrf-2s.mimg"
    mbtool("pack", str(elf), "--target", lay["target"], "-o", str(gimg), "--golden", "--version", "1.0.0")
    golden = gimg.read_bytes()

    def flash_with(name, extra=()):
        img = bytearray(b"\xff" * fsize)
        img[:len(factory)] = factory
        for at, data in extra:
            put(img, at, data)
        p = work / f"{name}.flash.bin"
        p.write_bytes(bytes(img))
        return p

    # a. a new board (stage 0 + stage 1 in s1a) with an app: the chain runs, stage 1 confirms itself
    o = boot(machine, flash_with("nrf-2s-factory", [("g", golden)]), seconds=7)
    ia = id32(s1a_payload)
    check(f"{board}: TWO_STAGE: stage 0 -> stage 1 (s1a) -> app, through two vector relays",
          "MU-APP nrf-2s" in o and f"relay={slot['g']['link_native']:08x}" in o and "svc=00000001" in o, o)
    check(f"{board}: TWO_STAGE: stage 1 recorded itself as working (>{ia:08x}), nothing counted with one copy",
          f">:{ia:08x}," in o and "?:" not in o, o)

    # b. over the console: the running copy and a copy linked for the other slot are refused;
    #    a newer stage 1 goes into s1b; after a reboot stage 0 tries it (counted), it starts
    #    the app and records itself
    newer = stage1_image("mimiboot-stage1", s1b_payload, "s1b", "1.1.0")
    wrong = stage1_image("mimiboot-stage1", s1a_payload, "s1b", "1.1.0")        # s1a's build, s1b's header
    ib = id32(s1b_payload)
    prompt = r"mimiboot(?:\x1b\[0m)?> $"
    upd = flash_with("nrf-2s-update")
    s = QemuSerial(machine, upd, seconds=90, keep=True)
    notes = []
    try:
        mbt.read_until(s, r"up/down \+ enter", 10)
        for _ in range(3):
            s.write(b"c")
            if mbt.read_until(s, prompt, 6)[1]:
                break
        s.write(b"\x15version\r")
        mbt.read_until(s, prompt, 5)
        s.write(b"recv s1a\r")
        mbt.read_until(s, prompt, 5)
        s.write(b"recv s1b\r")
        try:
            mbt.send_image(s, wrong, wrong[0x1000:])
        except SystemExit as e:
            notes.append(str(e))
        mbt.read_until(s, prompt, 5)
        # `mbtool loader`'s own code: asks which copy runs, sends the build's image for the other
        bdir = work / "nrf-2s-release"
        bdir.mkdir(exist_ok=True)
        shutil.copy(out / "layout.json", bdir / "layout.json")
        (bdir / "stage1-s1b.img").write_bytes(newer)
        (bdir / "stage1-s1a.img").write_bytes(b"not this one")
        went, _ = mbt.loader_upload(s, str(bdir))
        notes.append(f"loader wrote {went}")
        mbt.read_until(s, prompt, 5)
        s.write(b"recv g force\r")
        mbt.send_image(s, golden, golden[0x1000:])
        mbt.read_until(s, prompt, 5)
        s.keep_flash(fsize)                          # power off with the uploads in flash
    except SystemExit as e:
        notes.append(f"mbtool: {e}")
    o = s.close()
    o += boot_keep(machine, upd, fsize)              # power on: stage 0 sees the new copy
    note = "\n".join(notes) + "\n"
    check(f"{board}: TWO_STAGE: the console says which stage 1 runs", "stage 1 from s1a, v1.0.0" in o, note + o[-2500:])
    check(f"{board}: TWO_STAGE: 'recv' into the running copy is refused",
          "s1a is the stage 1 running now" in o, note + o[-2500:])
    check(f"{board}: TWO_STAGE: a stage 1 linked for the other copy is refused", "MB ERR refused" in o, note + o[-2500:])
    tail = o[o.rfind("MU-APP nrf-2s"):] if "MU-APP nrf-2s" in o else ""
    check(f"{board}: TWO_STAGE: mbtool loader put the new stage 1 into the copy that isn't running (s1b)",
          "loader wrote s1b" in note, note + o[-2500:])
    check(f"{board}: TWO_STAGE: after a power cycle stage 0 tries it (counted) and it starts the app",
          f"?:{ib:08x}," in tail and "MU-APP nrf-2s" in tail, note + o[-2500:])
    check(f"{board}: TWO_STAGE: ... and records itself as working", f">:{ib:08x}," in tail, note + o[-2500:])

    # c. a stage 1 in s1b that hangs before starting any app (this test app, flagged as a
    #    stage 1, just stops): each power cycle is counted; after 3 stage 0 passes it over
    #    and s1a starts the app
    elf = build_nrf_app(work, "s1-hang", slot["s1b"]["offset"] + 0x1000, ram_lo, ram_hi, probe)
    hang = stage1_image("hang", mbt.read_input(str(elf), None, lay["target"])[0], "s1b", "2.0.0")
    ih = id32(hang[0x1000:])
    hf = flash_with("nrf-2s-hang", [("g", golden), ("s1b", hang)])
    runs = [boot_keep(machine, hf, fsize, seconds=5.0) for _ in range(4)]
    o = "".join(runs)
    check(f"{board}: TWO_STAGE: a stage 1 that hangs is started on 3 power cycles",
          all("MU-APP s1-hang" in r for r in runs[:3]), o[-2500:])
    check(f"{board}: TWO_STAGE: ... then stage 0 goes back to s1a, which starts the app",
          "MU-APP nrf-2s" in runs[3] and "s1-hang" not in runs[3], runs[3][-1500:])
    check(f"{board}: TWO_STAGE: ... the 3 boots are on record, and s1a's own",
          runs[3].count(f"?:{ih:08x},") == 3 and f">:{ia:08x}," in runs[3], runs[3][-1500:])

    # d. damaged copies are ignored: a payload that doesn't match its hash, a header for the wrong slot
    bad = bytearray(newer)
    bad[0x1000 + 100] ^= 0x01
    o = boot(machine, flash_with("nrf-2s-badhash", [("g", golden), ("s1b", bytes(bad))]), seconds=7)
    check(f"{board}: TWO_STAGE: a stage 1 whose hash fails is ignored (s1a runs, nothing counted)",
          "MU-APP nrf-2s" in o and "?:" not in o and f">:{ia:08x}," in o, o)
    o = boot(machine, flash_with("nrf-2s-wrongslot", [("g", golden), ("s1b", wrong)]), seconds=7)
    check(f"{board}: TWO_STAGE: a stage 1 linked for the other copy is ignored", "MU-APP nrf-2s" in o and "?:" not in o, o)

    # e. signed: stage 0 takes S1_KEYS only. A stage 1 signed with the app key is ignored,
    #    one signed with the stage-1 key is started
    mbtool("keygen", "--out", str(work / "s1"))
    mbtool("keygen", "--out", str(work / "app2"))
    cfg2 = Config(db, board)
    cfg2.set("LAYOUT", "ab+golden")
    for k, v in (("TWO_STAGE", True), ("KEYS", str(work / "app2.pub")), ("REQUIRE_SIGNATURE", True),
                 ("S1_KEYS", str(work / "s1.pub")), ("STAGE1_SIGN_KEY", str(work / "s1.key"))):
        cfg2.set(k, v)
    out2 = work / f"{board}-2stage-signed"
    info2 = mubuild.build(cfg2, out2, log=lambda *a: None)
    lay2 = json.loads((out2 / "layout.json").read_text())
    if lay2 != lay:
        slot.update({s["name"]: s for s in lay2["slots"]})
    factory = (out2 / "mimiboot.bin").read_bytes()
    elf = build_nrf_app(work, "nrf-2s-signed", slot["g"]["link_native"], ram_lo, ram_hi, probe, store_at=lay2["floor"]["offset"])
    sg = work / "nrf-2s-signed.mimg"
    mbtool("pack", str(elf), "--target", lay["target"], "-o", str(sg), "--golden", "--version", "1.0.0",
           "--key", str(work / "app2.key"))
    app_key = mbt.read_secret(str(work / "app2.key"))
    s1_key = mbt.read_secret(str(work / "s1.key"))
    pay_b = (out2 / "stage1-s1b.bin").read_bytes()
    print(f"{board} (two-stage, signed): stage 0 {info2['stage0_used']} B, stage-1 images signed: {info2['stage1_signed']}")
    o = boot(machine, flash_with("nrf-2s-signed", [("g", sg.read_bytes())]), seconds=9)
    check(f"{board}: TWO_STAGE signed: stage 0 starts the build's signed stage 1, which starts a signed app",
          info2["stage1_signed"] and "MU-APP nrf-2s-signed" in o, o)
    o = boot(machine, flash_with("nrf-2s-appkey", [("g", sg.read_bytes()),
                                                   ("s1b", stage1_image("x", pay_b, "s1b", "5.0.0", app_key))]), seconds=9)
    check(f"{board}: TWO_STAGE signed: a newer stage 1 signed with the app key is ignored",
          "MU-APP nrf-2s-signed" in o and "?:" not in o, o)
    o = boot(machine, flash_with("nrf-2s-s1key", [("g", sg.read_bytes()),
                                                  ("s1b", stage1_image("x", pay_b, "s1b", "5.0.0", s1_key))]), seconds=9)
    check(f"{board}: TWO_STAGE signed: the same stage 1 signed with the stage-1 key is tried",
          "MU-APP nrf-2s-signed" in o and f"?:{id32(pay_b):08x}," in o, o)

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
    elif any(k in only for k in ("two-stage", "smp", "revoke", "enc", "record", "lms")):     # just cases 7-12 (nRF51)
        flash = 256 * 1024
        args = (work, db, check, "microbit", "microbit", 0x20000008, 0x20004000, flash - 4)
        if "two-stage" in only:
            two_stage_tests(*args)
        if "smp" in only:
            smp_tests(*args, imgtool)
        if "revoke" in only:
            revoke_tests(*args)
        if "enc" in only:
            enc_tests(*args)
        if "record" in only:
            record_tests(*args)
        if "lms" in only:
            lms_tests(*args)

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
        # OS hooks: the app asks (through the RAM mailbox) for a restart with new args and says why;
        # after a real reset the bootloader hands both to the next run, with no flash write
        check(f"{board}: OS hooks: a v2 handoff; the app's request and reason go through RAM",
              "prev=1 msg=[] via=2" in o and "MU-HOOK next=2" in o, o[-1500:])
        check(f"{board}: OS hooks: ... and after the reset the next run gets them (args hop=2, 'qemu-hop')",
              "args=[hop=2]" in o and "prev=3 msg=[qemu-hop]" in o, o[-1500:])

        # 6b. ECDSA P-256 (micro-ecc, as Thumb-2 code): a mbtool P-256 image with signatures
        #     required boots; one signed by a stranger's P-256 key doesn't
        mbtool("keygen", "--type", "p256", "--out", str(work / "p256"))
        mbtool("keygen", "--type", "p256", "--out", str(work / "p256-stranger"))
        (work / "mixed.pub").write_text((work / "trusted.pub").read_text() + (work / "p256.pub").read_text())
        cfg_ec = Config(db, board)
        cfg_ec.set("LAYOUT", "ab+golden")
        cfg_ec.set("KEYS", str(work / "mixed.pub"))
        cfg_ec.set("ECDSA", True)
        cfg_ec.set("REQUIRE_SIGNATURE", True)
        out_ec = work / f"{board}-ecdsa"
        info_ec = mubuild.build(cfg_ec, out_ec, log=lambda *a: None)
        print(f"{board} (ECDSA): bootloader {info_ec['flash_used']} B flash")
        for keyname, want in (("p256", True), ("p256-stranger", False)):
            eimg = work / f"{keyname}.mimg"
            mbtool("pack", str(elf), "--target", lay["target"], "-o", str(eimg), "--golden", "--key", str(work / f"{keyname}.key"))
            o = boot(machine, flash_image(work, f"ecdsa-{keyname}", lay["flash_size"], out_ec / "mimiboot.bin", g["offset"],
                                          eimg.read_bytes()))
            if want:
                check(f"{board}: ECDSA P-256 signed image boots (signatures required)", f"MU-APP {board}-native" in o, o)
            else:
                check(f"{board}: image signed by an untrusted P-256 key is refused", "MU-APP" not in o and "nothing bootable" in o, o)

        # 6c. TWO_STAGE on the F405: stage 0 hands over to stage 1 through VTOR (the
        #     relay case is the nRF51's), stage 1 boots the app. QEMU has no STM32 flash
        #     controller, so stage 1's "it works" record can't be written: one copy,
        #     nothing counted, the boot goes on regardless.
        cfg_2s = Config(db, board)
        cfg_2s.set("LAYOUT", "ab+golden")
        cfg_2s.set("TWO_STAGE", True)
        out_2s = work / f"{board}-2stage"
        info_2s = mubuild.build(cfg_2s, out_2s, log=lambda *a: None)
        lay_2s = json.loads((out_2s / "layout.json").read_text())
        g2 = next(s for s in lay_2s["slots"] if s["name"] == "g")
        s1a = next(s for s in lay_2s["slots"] if s["name"] == "s1a")
        print(f"{board} (two-stage): stage 0 {info_2s['stage0_used']} B, stage 1 {info_2s['flash_used']} B, "
              f"s1a at 0x{s1a['offset']:x}")
        e2 = build_app(work, "two-stage", g2["link_native"], uart, ram_kb)
        i2 = work / "two-stage.mimg"
        mbtool("pack", str(e2), "--target", lay_2s["target"], "-o", str(i2), "--golden")
        o = boot(machine, flash_image(work, "two-stage", lay_2s["flash_size"], out_2s / "mimiboot.bin", g2["offset"],
                                      i2.read_bytes()))
        check(f"{board}: TWO_STAGE: stage 0 -> stage 1 (VTOR) -> app", "MU-APP two-stage" in o and
              f"vtor={0x08000000 + g2['offset'] + 0x1000:08x}" in o, o)
        o = boot(machine, flash_image(work, "two-stage-menu", lay_2s["flash_size"], out_2s / "mimiboot.bin", g2["offset"],
                                      i2.read_bytes()), seconds=3.0, keys=b" ")
        check(f"{board}: TWO_STAGE: stage 1's console runs (break-in, 'stage 1 from s1a')",
              "stage 1 from s1a" in o and "MU-APP" not in o, o)

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

        # 8. imgtool with an ECDSA P-256 key (MCUboot's ECDSA_SIG TLV, DER)
        eckey = work / "ec.pem"
        run([imgtool, "keygen", "-k", eckey, "-t", "ecdsa-p256"])
        ecpub = subprocess.run([str(Path(imgtool).with_name("python")), "-c",
                                "import sys;from cryptography.hazmat.primitives import serialization as s;"
                                "k=s.load_pem_private_key(open(sys.argv[1],'rb').read(),None);"
                                "print(k.public_key().public_bytes(s.Encoding.X962,s.PublicFormat.UncompressedPoint)[1:].hex())",
                                str(eckey)], capture_output=True, text=True, check=True).stdout.strip()
        (work / "ec.pub").write_text(ecpub + "\n")
        ecsigned = work / "mcuboot.ecdsa.bin"
        run([imgtool, "sign", "--header-size", "0x200", "--pad-header", "--align", "8", "--version", "1.2.3",
             "--slot-size", hex(g["size"]), "--key", eckey, mc_bin, ecsigned])
        cfg.set("KEYS", str(work / "ec.pub"))
        cfg.set("ECDSA", True)
        out3 = work / f"{board}-mcuboot-ecdsa-build"
        mubuild.build(cfg, out3, log=lambda *a: None)
        o = boot(machine, flash_image(work, "mcuboot-ecdsa", lay["flash_size"], out3 / "mimiboot.bin", g["offset"],
                                      ecsigned.read_bytes()))
        check(f"{board}: imgtool ECDSA P-256 Zephyr/MCUboot image boots (signature required)", "MU-APP mcuboot" in o, o)

    if not os.environ.get("MU_QEMU_KEEP"):
        shutil.rmtree(work, ignore_errors=True)
    else:
        print("kept", work)
    bad = [n for n, ok in results if not ok]
    print(f"\nqemu: {len(results) - len(bad)}/{len(results)} passed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
