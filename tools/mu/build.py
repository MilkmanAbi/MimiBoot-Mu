"""Toolchain discovery and builds for every target kind.

mcu    arm-none-eabi-gcc, no SDK: core + port/cortexm + port/<vendor>, generated header + linker script
pico   the Pico SDK through CMake (tools/build.py), generated feature header
avr    avr-gcc: the Lite core (lite/avr)
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from . import gen
from .model import ROOT, Config, parse_sectors, parse_size

KOMOREBI_CORE = ["mb_hash", "mb_ed25519", "mb_image", "mb_bcl", "mb_config", "mb_policy", "mb_recv", "mb_console",
              "mb_control", "mb_grub", "mb_formats", "mb_floor", "mb_ecdsa", "mb_stage0", "mb_smp", "mb_enc", "mb_lms", "mb_mailbox"]
# a two-stage build's stage 0: check MimiBoot images, keep its records, start one
STAGE0_CORE = ["mb_hash", "mb_ed25519", "mb_image", "mb_floor", "mb_ecdsa", "mb_stage0", "mb_lms"]
VENDOR_SOURCES = {"stm32": ["port/stm32/stm32_flash.c", "port/stm32/stm32_periph.c"],
                  "nrf": ["port/nrf/nrf_flash.c", "port/nrf/nrf_periph.c"],
                  "samd": ["port/samd/samd_flash.c", "port/samd/samd_periph.c"]}


class BuildError(Exception):
    pass


# ---------------------------------------------------------------------------
# toolchains
# ---------------------------------------------------------------------------
def _expand(pattern: str) -> list[str]:
    pattern = os.path.expandvars(os.path.expanduser(pattern))
    return sorted(glob.glob(pattern), reverse=True)


def find_tool(exe: str, env: str, dirs: list[str]) -> str | None:
    if os.environ.get(env):
        p = Path(os.environ[env])
        return str(p if p.is_file() else p / exe)
    found = shutil.which(exe)
    if found:
        return found
    for d in dirs:
        for hit in _expand(d):
            for name in (exe, exe + ".exe"):
                if (Path(hit) / name).is_file():
                    return str(Path(hit) / name)
    return None


def arm_gcc():
    return find_tool("arm-none-eabi-gcc", "MU_ARM_GCC", [
        "C:/Program Files (x86)/Arm/GNU Toolchain*/bin", "C:/Program Files/Arm/GNU Toolchain*/bin",
        "C:/Program Files (x86)/GNU Arm Embedded Toolchain/*/bin", "~/.local/arm-gnu-toolchain*/bin",
        "/opt/arm-gnu-toolchain*/bin", "/Applications/ArmGNUToolchain/*/arm-none-eabi/bin"])


def avr_gcc():
    return find_tool("avr-gcc", "MU_AVR_GCC", [
        "%LOCALAPPDATA%/Arduino15/packages/arduino/tools/avr-gcc/*/bin", "~/.arduino15/packages/arduino/tools/avr-gcc/*/bin",
        "~/Library/Arduino15/packages/arduino/tools/avr-gcc/*/bin", "C:/Program Files*/Arduino*/hardware/tools/avr/bin"])


def pico_sdk():
    p = os.environ.get("PICO_SDK_PATH") or str(Path.home() / "pico/pico-sdk")
    return p if Path(p, "pico_sdk_init.cmake").exists() else None


def picotool():
    if os.environ.get("PICOTOOL"):
        return os.environ["PICOTOOL"]
    w = shutil.which("picotool")
    if w:
        return w
    hits = _expand("~/pico/picotool*/**/picotool.exe") + _expand("~/pico/picotool*/picotool/picotool*")
    hits = [h for h in hits if Path(h).is_file()] or [h for h in glob.glob(str(Path.home() / "pico/**/picotool.exe"), recursive=True)]
    return hits[0] if hits else None


def riscv_toolchain():
    if os.environ.get("RISCV_TOOLCHAIN"):
        return os.environ["RISCV_TOOLCHAIN"]
    hits = _expand("~/pico/riscv-toolchain*")
    return hits[0] if hits else None


def toolchains() -> dict:
    return {"arm-none-eabi-gcc": arm_gcc(), "avr-gcc": avr_gcc(), "pico-sdk": pico_sdk(),
            "picotool": picotool(), "riscv-toolchain": riscv_toolchain()}


def _run(cmd, cwd=ROOT, quiet=False):
    r = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        raise BuildError(f"command failed: {' '.join(map(str, cmd[:3]))} ...\n{r.stdout}{r.stderr}")
    if not quiet and (r.stderr.strip()):
        sys.stderr.write(r.stderr)
    return r.stdout


def _tool(gcc: str, name: str) -> str:
    """arm-none-eabi-gcc -> arm-none-eabi-objcopy next to it"""
    p = Path(gcc)
    stem = p.name.replace("gcc", name)
    cand = p.with_name(stem)
    return str(cand) if cand.exists() or cand.with_suffix(".exe").exists() else stem


def _sizes(gcc: str, elf: Path) -> dict:
    out = _run([_tool(gcc, "size"), "-A", elf], quiet=True)
    s = {}
    for line in out.splitlines():
        m = re.match(r"^(\.\S+)\s+(\d+)\s+(\d+)", line)
        if m:
            s[m.group(1)] = int(m.group(2))
    flash = sum(v for k, v in s.items() if k in (".isr_vector", ".text", ".ARM.exidx", ".data", ".rodata", ".text.progmem"))
    ram = s.get(".data", 0) + s.get(".bss", 0) + s.get(".noinit", 0)
    return {"flash": flash, "ram": ram, "sections": s}


# ---------------------------------------------------------------------------
# bare-metal Cortex-M: STM32, nRF, SAMD
# ---------------------------------------------------------------------------
def build_mcu(cfg: Config, out: Path, log=print) -> dict:
    cfg.store_one_unit = False      # set below when two store units don't fit beside the code
    gcc = arm_gcc()
    if not gcc:
        raise BuildError("arm-none-eabi-gcc not found: install the Arm GNU Toolchain or set MU_ARM_GCC")
    problems = [m for lvl, m in cfg.problems() if lvl == "error"]
    if problems:
        raise BuildError("; ".join(problems))
    t = cfg.t
    cpu = t.get("cpu")
    ram, _ = gen.mcu_ram(cfg)
    stack = 0x1800 if cfg.effective("SIGNATURES") else 0x1000 if cfg.effective("LMS") else 0xC00
    flash = parse_size(t.get("flash"))
    auto = str(cfg.effective("BOOT_SIZE")).lower() == "auto"
    out.mkdir(parents=True, exist_ok=True)

    def one_pass(lay, loader_ram, tag, flash_len=None):
        hdr = out / "mimiboot_config.h"
        hdr.write_text(gen.mcu_header(cfg, lay, loader_ram))
        ld = out / "link.ld"
        ld.write_text(gen.mcu_linker(cfg, flash_len or lay.boot.size, ram, loader_ram, 0 if tag == "measure" else stack))
        elf = out / "mimiboot.elf"
        _run([gcc, *recipe["cflags"], f'-DMB_CONFIG_HEADER="{hdr.as_posix()}"', "-I.", "-Iinclude", *recipe["sources"],
              *recipe["ldflags"], f"-T{ld.as_posix()}", f"-Wl,-Map={(out / 'mimiboot.map').as_posix()}", "-o", elf])
        return elf

    # what gets compiled, and how (the source export writes a Makefile from this)
    recipe = {
        "cc": "arm-none-eabi-gcc",
        "sources": [f"core/{n}.c" for n in KOMOREBI_CORE] + ["port/cortexm/cm_port.c"] + VENDOR_SOURCES[t.get("vendor")],
        "headers": ["core/*.h", "include/mimiboot/*.h", "port/cortexm/*.h", f"port/{t.get('vendor')}/*.h",
                    "third_party/micro-ecc/*"],
        "usb": bool(cfg.effective("CONSOLE_USB")),
        "cflags": [f"-mcpu={cpu}", "-mthumb", "-std=c11", "-Os", "-g", "-Wall", "-Wextra", "-Wno-unused-parameter",
                   "-ffunction-sections", "-fdata-sections", "-fno-common", "-ffreestanding"]
                  # flash at address 0 (nRF, SAMD): reading it is not a null dereference
                  + (["-fno-delete-null-pointer-checks"] if gen.flash_base(cfg) == 0 else []),
        "ldflags": ["-nostartfiles", "--specs=nano.specs", "--specs=nosys.specs", "-Wl,--gc-sections"],
        "config": "mimiboot_config.h", "linker": "link.ld", "target": "mimiboot",
    }
    if recipe["usb"]:
        recipe["sources"] += gen.USB_SOURCES
        recipe["cflags"] += gen.usb_includes(cfg)
        recipe["headers"] += ["third_party/tinyusb/src/**/*.h", "port/samd/usb/*.h", "third_party/cmsis/Include/**/*.h",
                              f"third_party/microchip/samd{t.get('series')}/include/**/*.h"]

    if cfg.effective("TWO_STAGE"):
        return _build_two_stage(cfg, out, gcc, recipe, ram, stack, flash)

    # pass 1: measure (linked against all of flash and RAM, so a build that is too big
    # still links and the error below can say by how much)
    lay0 = gen.mcu_layout(cfg, boot_bytes=flash // 2 if auto else None)
    elf = one_pass(lay0, ram, "measure", flash_len=flash)
    sz = _sizes(gcc, elf)
    need_flash = sz["flash"]
    need_ram = sz["ram"] + stack
    if need_ram > ram:
        raise BuildError(f"needs {sz['ram']} bytes of RAM + {stack} of stack, the chip has {ram}: "
                         "turn off SIGNATURES (smaller stack), CONSOLE/RECV or CFG_FILE")
    loader_ram = min(ram, ((need_ram + 1023) // 1024) * 1024)
    # pass 2: final layout
    floor = 0
    if cfg.effective("PROTECTED_FLOOR"):
        # the floor store takes the region's last erase unit: in auto mode, size for code + that unit
        lay = gen.mcu_layout(cfg, boot_bytes=need_flash if auto else None)
        floor = gen.floor_region(cfg, lay)[1]
    lay = gen.mcu_layout(cfg, boot_bytes=need_flash + floor if auto else None)
    room = gen.code_room(cfg, lay)
    if need_flash > room and gen.floor_unit(cfg, lay):
        # a fixed region with no room for a second store unit: one unit, append-only, as before
        cfg.store_one_unit = True
        if need_flash <= gen.code_room(cfg, lay):
            room = gen.code_room(cfg, lay)
            lay.notes.append("the protected store is one erase unit (append-only, it fills up): two, which compact, "
                             "don't fit beside this much code; a larger BOOT_SIZE gives it room")
        else:
            cfg.store_one_unit = False
    if need_flash > room:
        extra = f" (the last {lay.boot.size - room} bytes of it hold the rollback floors)" if room < lay.boot.size else ""
        raise BuildError(f"the bootloader is {need_flash} bytes but its region has room for {room}{extra}: "
                         "turn features off (SIGNATURES ~7 KB, CONSOLE ~9 KB, RECV, CONTROL) or set BOOT_SIZE")
    if loader_ram >= ram and cfg.effective("HANDOFF"):
        # the port writes a handoff only outside the loader's RAM (it may still be in use when it's written)
        lay.notes.append(f"the bootloader needs all {ram // 1024} KB of RAM ({sz['ram']} B + {stack} B of stack), "
                         "so there is no room for the boot handoff: apps get none and read their slot from flash. "
                         "SMP, ENCRYPTED_IMAGES or SIGNATURES off frees RAM")
    elf = one_pass(lay, loader_ram, "final", flash_len=room)
    sz = _sizes(gcc, elf)
    objcopy = _tool(gcc, "objcopy")
    _run([objcopy, "-O", "binary", elf, out / "mimiboot.bin"])
    _run([objcopy, "-O", "ihex", elf, out / "mimiboot.hex"])
    gen.mcu_outputs(cfg, lay, out, loader_ram)
    info = {"board": t.name, "core": "komorebi", "build": "mcu", "vendor": t.get("vendor"), "flash_used": sz["flash"], "flash_region": room,
            "ram_used": sz["ram"], "ram_region": loader_ram, "stack": stack,
            "features": {o.id: cfg.effective(o.id) for o in cfg.options()},
            "files": ["mimiboot.elf", "mimiboot.bin", "mimiboot.hex", "layout.txt", "layout.json",
                      "zephyr-partitions.overlay"] + [f"app-slot-{s.name}.ld" for s in lay.slots],
            "notes": lay.notes, "recipe": recipe}
    (out / "build-info.json").write_text(json.dumps(info, indent=2, default=str) + "\n")
    return info


def _build_two_stage(cfg: Config, out: Path, gcc: str, recipe: dict, ram: int, stack: int, flash: int) -> dict:
    """Stage 0 at the start of flash, stage 1 linked once per copy (s1a, s1b) and
    packed as signed MimiBoot images, mimiboot.bin = what a new board gets."""
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool  # noqa: E402  (the same header code `mbtool pack` uses)
    from .layout import ROLE_STAGE1
    from .model import parse_version_text
    t = cfg.t
    vendor_src = VENDOR_SOURCES[t.get("vendor")]
    fb = gen.flash_base(cfg)

    def link(lay, loader_ram, length, name, defines, *, origin=0, stage0=False, measure=False):
        hdr = out / f"{name}_config.h"
        hdr.write_text(gen.mcu_header(cfg, lay, loader_ram, gen.STAGE0_OFF if stage0 else None))
        ld = out / f"{name}.ld"
        ld.write_text(gen.mcu_linker(cfg, length, ram, loader_ram, 0 if measure else stack, origin))
        srcs = ([f"core/{n}.c" for n in STAGE0_CORE] + ["port/cortexm/cm_port.c"] + vendor_src) if stage0 else recipe["sources"]
        elf = out / f"{name}.elf"
        _run([gcc, *recipe["cflags"], *defines, f'-DMB_CONFIG_HEADER="{hdr.as_posix()}"', "-I.", "-Iinclude", *srcs,
              *recipe["ldflags"], f"-T{ld.as_posix()}", f"-Wl,-Map={(out / (name + '.map')).as_posix()}", "-o", elf])
        return elf

    def s1_defines(i):
        return ["-DMB_CM_STAGE1", f"-DMB_STAGE1_SLOT={i}"]

    # measure both stages against all of flash and RAM (this layout only has to place
    # the slots: one smallest sector per copy, so small parts get measured too)
    lay0 = gen.mcu_layout(cfg, s1_bytes=min(s for _, s in parse_sectors(t.get("sectors"))))
    first = next(i for i, s in enumerate(lay0.slots) if s.role == ROLE_STAGE1)
    s1 = _sizes(gcc, link(lay0, ram, flash, "stage1-measure", s1_defines(first), measure=True))
    s0 = _sizes(gcc, link(lay0, ram, flash, "stage0-measure", ["-DMB_CM_STAGE0"], stage0=True, measure=True))
    # one RAM size for both: their .noinit (the fault notes) then sits at the same address
    need_ram = max(s0["ram"], s1["ram"]) + stack
    if need_ram > ram:
        raise BuildError(f"needs {need_ram - stack} bytes of RAM + {stack} of stack, the chip has {ram}")
    loader_ram = min(ram, ((need_ram + 1023) // 1024) * 1024)

    # the layout: stage 0 + its store (the last erase unit of the boot region), then the copies
    s1_bytes = gen.stage1_bytes(cfg, s1["flash"])
    bs = str(cfg.effective("BOOT_SIZE") or "chip").strip().lower()
    if bs in ("chip", "auto"):
        lay = gen.mcu_layout(cfg, boot_bytes=s0["flash"], s1_bytes=s1_bytes)
        lay = gen.mcu_layout(cfg, boot_bytes=s0["flash"] + gen.floor_region(cfg, lay)[1], s1_bytes=s1_bytes)
    else:
        lay = gen.mcu_layout(cfg, s1_bytes=s1_bytes)
    room0 = gen.code_room(cfg, lay)
    if s0["flash"] > room0:
        raise BuildError(f"stage 0 is {s0['flash']} bytes, its region has room for {room0} (the store takes the "
                         f"last {lay.boot.size - room0}): set BOOT_SIZE bigger")
    copies = [(i, s) for i, s in enumerate(lay.slots) if s.role == ROLE_STAGE1]
    room1 = min(s.size for _, s in copies) - gen.NATIVE_HDR
    if s1["flash"] > room1:
        raise BuildError(f"stage 1 is {s1['flash']} bytes, a stage-1 copy has room for {room1}: set STAGE1_SIZE bigger")

    objcopy = _tool(gcc, "objcopy")
    elf0 = link(lay, loader_ram, room0, "stage0", ["-DMB_CM_STAGE0"], stage0=True)
    _run([objcopy, "-O", "binary", elf0, out / "stage0.bin"])
    sz0 = _sizes(gcc, elf0)
    version = parse_version_text(str(cfg.effective("STAGE1_VERSION")))
    secver = int(cfg.effective("STAGE1_SECURITY") or 0)
    key = cfg.effective("STAGE1_SIGN_KEY")
    signing = cfg.effective("SIGNATURES") or cfg.effective("LMS")
    secret = mbtool.read_secret(str(key)) if key and signing else None     # (an LMS key: two signatures per build)
    images, sz1 = {}, None
    for i, s in copies:
        name = f"stage1-{s.name}"
        elf = link(lay, loader_ram, s.size - gen.NATIVE_HDR, name, s1_defines(i), origin=s.offset + gen.NATIVE_HDR)
        sz1 = sz1 or _sizes(gcc, elf)
        _run([objcopy, "-O", "binary", elf, out / f"{name}.bin"])
        payload = (out / f"{name}.bin").read_bytes()
        hdr = mbtool.build_header(payload, "mimiboot-stage1", version, secver, target=t.chip_name[:15],
                                  arch=mbtool.ARCH_ARM, secret=secret, entry=s.offset + gen.NATIVE_HDR, stage1=True)
        img = mbtool.header_sector(hdr, secret.pending_tlv if secret else b"") + payload
        (out / f"{name}.img").write_bytes(img)
        images[s.name] = img
    # what a new board gets: stage 0, a blank store, stage 1 in the first copy
    a = copies[0][1]
    factory = bytearray(b"\xff" * (a.offset + len(images[a.name])))
    b0 = (out / "stage0.bin").read_bytes()
    factory[:len(b0)] = b0
    factory[a.offset:] = images[a.name]
    (out / "mimiboot.bin").write_bytes(bytes(factory))
    _run([objcopy, "-I", "binary", "-O", "ihex", f"--change-addresses=0x{fb:x}", out / "mimiboot.bin", out / "mimiboot.hex"])
    for n in ("stage1-measure", "stage0-measure"):
        for ext in (".elf", ".map", ".ld", "_config.h"):
            (out / (n + ext)).unlink(missing_ok=True)
    gen.mcu_outputs(cfg, lay, out, loader_ram)
    info = {"board": t.name, "core": "komorebi", "build": "mcu", "vendor": t.get("vendor"), "two_stage": True,
            "flash_used": sz1["flash"], "flash_region": room1, "stage0_used": sz0["flash"], "stage0_region": room0,
            "ram_used": max(sz0["ram"], sz1["ram"]), "ram_region": loader_ram, "stack": stack,
            "stage1_signed": bool(secret),
            "features": {o.id: cfg.effective(o.id) for o in cfg.options()},
            "files": ["mimiboot.bin", "mimiboot.hex", "stage0.elf", "stage0.bin"] +
                     [f"stage1-{s.name}{e}" for _, s in copies for e in (".elf", ".img")] +
                     ["layout.txt", "layout.json", "zephyr-partitions.overlay"] +
                     [f"app-slot-{s.name}.ld" for s in lay.slots if s.role != ROLE_STAGE1],
            "notes": lay.notes, "recipe": recipe}
    (out / "build-info.json").write_text(json.dumps(info, indent=2, default=str) + "\n")
    return info


# ---------------------------------------------------------------------------
# Pico SDK
# ---------------------------------------------------------------------------
def build_pico(cfg: Config, out: Path, log=print) -> dict:
    sdk = pico_sdk()
    if not sdk:
        raise BuildError("Pico SDK not found: set PICO_SDK_PATH")
    problems = [m for lvl, m in cfg.problems() if lvl == "error"]
    if problems:
        raise BuildError("; ".join(problems))
    t = cfg.t
    out.mkdir(parents=True, exist_ok=True)
    hdr = out / "mimiboot_config.h"
    hdr.write_text(gen.pico_header(cfg))
    platform = t.get("platform")
    plat_arg = "rp2040" if platform == "rp2040" else "rp2350-universal"
    cmd = [sys.executable, ROOT / "tools/build.py", "--out", out / "work", "--platform", plat_arg,
           "--config-header", hdr, "--sdk", sdk, "--jobs", str(os.cpu_count() or 4)]
    if t.board.get("pico_board"):
        cmd += ["--board2040" if platform == "rp2040" else "--board2350", t.board["pico_board"]]
    if t.board.get("flash"):
        cmd += ["--flash-size", str(parse_size(t.board["flash"]))]
    keys = gen.pico_keys_header(cfg)
    if keys:
        (out / "keys.h").write_text(keys)
        cmd += ["--keys", out / "keys.h"]
        if cfg.effective("REQUIRE_SIGNATURE"):
            cmd += ["--require-signature"]
    arm = arm_gcc()
    if arm:
        cmd += ["--arm", str(Path(arm).parent.parent)]
    if plat_arg != "rp2040":
        rv, pt = riscv_toolchain(), picotool()
        if not rv or not pt:
            raise BuildError("RP2350 builds the universal (Arm + RISC-V) loader: needs RISCV_TOOLCHAIN and PICOTOOL")
        cmd += ["--riscv", rv, "--picotool", pt]
    elif picotool():
        cmd += ["--picotool", picotool()]
    log("building with the Pico SDK (a few minutes the first time)...")
    _run(cmd, quiet=True)
    dist = out / "work" / "dist"
    files = []
    for f in sorted(dist.glob("*")):
        if f.suffix in (".uf2", ".bin", ".elf"):
            shutil.copy2(f, out / f.name)
            files.append(f.name)
    rel = [str(c) for c in cmd]
    rel = [s.replace(str(out), "<output>").replace(str(ROOT), ".") for s in rel]
    info = {"board": t.name, "core": "komorebi", "build": "pico", "platform": plat_arg, "files": files,
            "recipe": {"kind": "pico", "command": rel},
            "features": {o.id: cfg.effective(o.id) for o in cfg.options()}}
    main_bin = next((out / f for f in files if f.endswith("mimiboot.bin") or f.endswith("universal.bin")), None)
    if main_bin:
        info["flash_used"], info["flash_region"] = main_bin.stat().st_size, 245760
    (out / "build-info.json").write_text(json.dumps(info, indent=2, default=str) + "\n")
    return info


# ---------------------------------------------------------------------------
def build(cfg: Config, out: Path | None = None, log=print) -> dict:
    """build into out (default: the config's OUTPUT_DIR/<board>); EXPORT_SOURCE adds source/"""
    out = Path(out) if out else cfg.output_dir()
    kind = cfg.t.build
    if kind == "mcu":
        from .layout import LayoutError
        try:
            info = build_mcu(cfg, out, log)
        except LayoutError as e:
            raise BuildError(f"flash layout: {e} (fewer slots, CFG_FILE off, or a smaller BOOT_SIZE)") from None
    elif kind == "pico":
        info = build_pico(cfg, out, log)
    elif kind == "avr":
        from .avr import build_avr
        info = build_avr(cfg, out, log)
    else:
        raise BuildError(f"no builder for {kind}")
    info["out"] = str(out)
    if cfg.effective("EXPORT_SOURCE"):
        from .export import export_source
        export_source(cfg, out, info)
        info["files"] = list(info.get("files", [])) + ["source/"]
    return info
