"""AVR (Lite core) builds: pick the smallest boot section the build fits in."""
from __future__ import annotations

import json
from pathlib import Path

from . import gen
from .build import BuildError, _run, _sizes, _tool, avr_gcc
from .model import ROOT, Config, parse_size

# hfuse with BOOTRST programmed and BOOTSZ = 00, as Arduino ships these chips;
# BOOTSZ sits in the extended fuse on the ATmega168.
FUSE = {"atmega328p": ("hfuse", 0xD8), "atmega168": ("efuse", 0xF8), "atmega644p": ("hfuse", 0xD8),
        "atmega1284p": ("hfuse", 0xD8), "atmega2560": ("hfuse", 0xD8)}


def build_avr(cfg: Config, out: Path, log=print) -> dict:
    gcc = avr_gcc()
    if not gcc:
        raise BuildError("avr-gcc not found: install the Arduino AVR core (or avr-gcc) or set MU_AVR_GCC")
    problems = [m for lvl, m in cfg.problems() if lvl == "error"]
    if problems:
        raise BuildError("; ".join(problems))
    t = cfg.t
    flash = parse_size(t.get("flash"))
    sizes = sorted(t.get("boot_sizes"))
    mcu = t.get("mcu")
    f_cpu = t.board.get("f_cpu", 16000000)
    api = bool(cfg.effective("SPM_API"))
    out.mkdir(parents=True, exist_ok=True)

    def link(boot):
        hdr = out / "mu_config.h"
        hdr.write_text(gen.avr_header(cfg, boot))
        elf = out / "mimiboot-lite.elf"
        cmd = [gcc, f"-mmcu={mcu}", f"-DF_CPU={f_cpu}UL", "-Os", "-std=gnu11", "-Wall", "-Wextra",
               "-ffunction-sections", "-fdata-sections", "-fno-split-wide-types", "-mrelax", "-fno-jump-tables",
               "-include", hdr.as_posix(), "-I.", "lite/avr/mu_avr.c", "-nostartfiles", "-Wl,--gc-sections",
               f"-Wl,--section-start=.text=0x{flash - boot:x}", f"-Wl,-Map={(out / 'mimiboot-lite.map').as_posix()}"]
        if api:
            cmd += [f"-Wl,--section-start=.mu_api=0x{flash - 8:x}", "-Wl,-u,mu_api_table"]
        cmd += ["-o", elf]
        _run(cmd, cwd=ROOT)
        return elf

    # measure in the largest section, then use the smallest that fits
    elf = link(sizes[-1])
    used = _sizes(gcc, elf)["sections"].get(".text", 0) + (8 if api else 0)
    boot = next((b for b in sizes if b >= used), None)
    if boot is None:
        raise BuildError(f"{used} bytes don't fit the largest boot section ({sizes[-1]}): turn features off")
    elf = link(boot)
    text = _sizes(gcc, elf)["sections"].get(".text", 0)
    if text + (8 if api else 0) > boot:
        raise BuildError("relinked build grew past its section")
    _run([_tool(gcc, "objcopy"), "-O", "ihex", "-R", ".eeprom", elf, out / "mimiboot-lite.hex"])
    bootsz = len(sizes) - 1 - sizes.index(boot)             # largest section = 0b00
    fname, fbase = FUSE.get(mcu, ("hfuse", 0xD8))
    fuse = fbase | (bootsz << 1)
    app_max = flash - boot
    baud = cfg.effective("BAUD")
    notes = [f"boot section {boot} bytes: BOOTSZ=0b{bootsz:02b}, BOOTRST programmed -> {fname} 0x{fuse:02X} "
             f"(typical; only BOOTSZ/BOOTRST change)",
             f"apps may use up to {app_max} bytes (Arduino: upload.maximum_size={app_max})"]
    if mcu == "atmega328p" and boot > 512:
        notes.append("the Uno's stock fuses reserve 512 bytes: this build needs the fuse change above, written "
                     "once with an ISP programmer (avrdude -c usbasp ... -U hfuse:w:0x%02X:m)" % fuse)
    (out / "boards.txt").write_text(
        f"# MimiBoot-Mu Lite for {t.name}: add to your boards.txt (or a hardware/ folder of your own)\n"
        f"mimiboot_{t.name.replace('-', '_')}.name=MimiBoot-Mu {t.title}\n"
        f"mimiboot_{t.name.replace('-', '_')}.upload.protocol=arduino\n"
        f"mimiboot_{t.name.replace('-', '_')}.upload.speed={baud}\n"
        f"mimiboot_{t.name.replace('-', '_')}.upload.maximum_size={app_max}\n"
        f"mimiboot_{t.name.replace('-', '_')}.bootloader.{'extended' if fname == 'efuse' else 'high'}_fuses=0x{fuse:02X}\n"
        f"mimiboot_{t.name.replace('-', '_')}.bootloader.file=mimiboot/mimiboot-lite.hex\n")
    ld = [f"-Wl,--section-start=.text=0x{flash - boot:x}"]
    if api:
        ld += [f"-Wl,--section-start=.mu_api=0x{flash - 8:x}", "-Wl,-u,mu_api_table"]
    recipe = {"cc": "avr-gcc", "sources": ["lite/avr/mu_avr.c"], "headers": ["lite/*.h"],
              "cflags": [f"-mmcu={mcu}", f"-DF_CPU={f_cpu}UL", "-Os", "-std=gnu11", "-Wall", "-Wextra",
                         "-ffunction-sections", "-fdata-sections", "-fno-split-wide-types", "-mrelax", "-fno-jump-tables"],
              "include": "mu_config.h", "ldflags": ["-nostartfiles", "-Wl,--gc-sections", *ld],
              "config": "mu_config.h", "target": "mimiboot-lite", "hex_args": ["-R", ".eeprom"]}
    info = {"board": t.name, "core": "lite", "build": "avr", "flash_used": text + (8 if api else 0), "flash_region": boot,
            "boot_start": flash - boot, "bootsz": bootsz, "fuse": {fname: fuse},
            "features": {o.id: cfg.effective(o.id) for o in cfg.options()},
            "files": ["mimiboot-lite.hex", "mimiboot-lite.elf", "boards.txt"], "notes": notes, "recipe": recipe}
    (out / "build-info.json").write_text(json.dumps(info, indent=2, default=str) + "\n")
    return info
