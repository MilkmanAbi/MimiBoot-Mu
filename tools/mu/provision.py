"""What it takes to lock a board for good: the persistent protection steps that
a bootloader can't (or shouldn't) do to itself.

`mbtool provision <build dir>` prints these for the board a build was made for.
Nothing here is run: several steps are irreversible, and every one of them
needs a full chip erase to undo. Check each against the reference manual of
your exact part before you run it.
"""
from __future__ import annotations

import json
from pathlib import Path

from .model import Db, parse_sectors


class ProvisionError(Exception):
    pass


def _load(build_dir: Path) -> tuple[dict, dict | None]:
    info_p = build_dir / "build-info.json"
    if not info_p.exists():
        raise ProvisionError(f"{info_p}: not a MuConfigurator build directory (no build-info.json)")
    info = json.loads(info_p.read_text())
    lay_p = build_dir / "layout.json"
    return info, json.loads(lay_p.read_text()) if lay_p.exists() else None


def _covering_units(sectors, start: int, size: int) -> list[int]:
    """indices of the erase units [start, start+size) consists of; must line up exactly"""
    idx, end = [], start + size
    for i, (off, sz) in enumerate(sectors):
        if off >= start and off + sz <= end:
            idx.append(i)
    covered = sum(sectors[i][1] for i in idx)
    if covered != size:
        raise ProvisionError(f"the region to lock (0x{start:x}, {size} bytes) doesn't line up with the chip's "
                             "protection units")
    return idx


def steps(build_dir: Path) -> list[str]:
    info, lay = _load(build_dir)
    db = Db()
    t = db.target(info["board"])
    vendor = t.get("vendor")
    feats = info.get("features", {})
    out = [f"Locking {info['board']} ({t.chip_name}) for production", ""]

    if info.get("core") == "lite":
        part = t.get("avrdude_part") or t.chip_name
        out += [
            "AVR (Lite core): the boot section is protected by lock bits, written once with an ISP programmer.",
            "",
            "  1. Boot section: SPM may not write it (BLB1 mode 2), the app section stays writable",
            "     (the Lite flash service and staged updates write it):",
            f"       avrdude -c <programmer> -p {part} -U lock:w:0x2F:m",
            "  2. Optional, also stops an ISP programmer reading the flash out (LB mode 3):",
            f"       avrdude -c <programmer> -p {part} -U lock:w:0x2C:m",
            "",
            "Undo: a chip erase (avrdude -e) clears the lock bits, and erases the bootloader with them.",
            "0x2F is what Optiboot boards ship with; check the 'Boot Loader Lock Bits' table in your part's datasheet.",
        ]
        return out
    if not lay:
        raise ProvisionError("no layout.json: provisioning steps are generated for bare-metal (mcu) builds and AVR")
    fb, boot = lay["flash_base"], lay["boot"]
    b0, bsize = boot["offset"], boot["size"]
    two = bool(info.get("two_stage")) and lay.get("floor")
    if two:
        # only stage 0's code is locked for good: its store (right after it) and the
        # stage-1 copies are written by the bootloader, and stage 1 is updated in the field
        st = lay["floor"]
        bsize = st["offset"] - b0
        out.append(f"Two-stage build: lock stage 0 only, 0x{fb + b0:08x}, {bsize // 1024} KB. Its store "
                   f"(0x{fb + st['offset']:08x}, {st['size'] // 1024} KB) and the stage-1 copies must stay writable.")
    else:
        out.append(f"Bootloader region: 0x{fb + b0:08x}, {bsize // 1024} KB. The boot log right after it must stay writable.")
    out.append("")

    if vendor == "nrf":
        series = t.get("series")
        lock = t.get("flash_lock", "bprot")
        out += [
            f"nRF{series}: the flash lock is applied by the bootloader itself on every boot"
            + (" (BOOT_LOCK is on in this build)." if feats.get("BOOT_LOCK") else
               ": BOOT_LOCK is OFF in this build, turn it on (MuConfigurator, security menu)."),
            f"  mechanism: {'MPU PROTENSET' if lock == 'mpu' else lock.upper()}, until each reset; nothing to provision."
            + ("\n  Two-stage: stage 1 locks stage 0, the store and both stage-1 copies before it starts an app."
               if two else ""),
            "",
            "Debug port (persistent):",
            "  nrfjprog --rbp ALL          sets UICR.APPROTECT (nRF51: UICR.RBPCONF): no debugger access after reset",
        ]
        if series == 52:
            out += [
                "  On nRF52 silicon with the firmware-controlled APPROTECT (most parts made since 2021) the",
                "  bootloader opens debug only if UICR.APPROTECT is 0x5A, so after --rbp ALL it stays shut."
                + (" DEBUG_LOCK is on: it also forces it shut until each reset." if feats.get("DEBUG_LOCK") else
                   " DEBUG_LOCK adds a force-shut until each reset, whatever UICR says."),
            ]
        out += ["", "Undo: nrfjprog --recover (erases everything, the bootloader too)."]
        return out

    sectors = parse_sectors(t.get("sectors"))
    if vendor == "stm32":
        drv = t.family["flash_driver"]
        idx = _covering_units(sectors, b0, bsize)
        first, last = idx[0], idx[-1]
        out.append("STM32: write protection and read protection are option bytes (STM32CubeProgrammer).")
        out.append("  Look first:   STM32_Programmer_CLI -c port=SWD -ob displ")
        if drv == "L4G0G4":
            page = sectors[0][1]
            out += [f"  1. Write-protect pages {first}..{last} ({page // 1024} KB pages) with WRP area A of bank 1:",
                    f"       STM32_Programmer_CLI -c port=SWD -ob WRP1A_STRT={first} WRP1A_END={last}",
                    "     (some CubeProgrammer versions ignore WRP fields on the command line: check with -ob displ,",
                    "      or set them in the GUI's Option bytes tab)"]
        elif drv == "F2F4":
            out += [f"  1. Write-protect sectors {first}..{last}: clear nWRP for each of them",
                    "       STM32_Programmer_CLI -c port=SWD -ob " + " ".join(f"nWRP{i}=0" for i in idx),
                    "     (option names as CubeProgrammer lists them for your part: check -ob displ)"]
        else:  # F0/F1/F3: one WRP bit covers several pages
            out += [f"  1. Write-protect pages {first}..{last}: on F0/F1/F3 each WRP bit covers a group of pages",
                    "     (2 or 4 KB depending on the part). Find the bits for this range in the reference manual's",
                    "     'Write protection' table and clear them in CubeProgrammer's Option bytes tab."]
        out += [
            "  2. Read protection level 1: no flash reads over SWD, debug still possible, reversible with a mass erase:",
            "       STM32_Programmer_CLI -c port=SWD -ob RDP=0xBB",
            "     Level 2 (RDP=0xCC) disables debug and option-byte changes FOREVER. Only for a final product,",
            "     and only after everything else here is right.",
            "",
            "Write protection also stops the bootloader writing what it covers; MimiBoot never writes there",
            "(PROTECTED_FLOOR exists only on nRF, where the lock is applied after the bootloader's own writes;",
            "a two-stage build's store is left out of the range above for the same reason). Without a runtime",
            "lock the store and the stage-1 copies stay writable by the app on STM32: see docs/SECURITY.md.",
            "Undo: RDP back to 0xAA (mass erase), then set the WRP bits/area back.",
        ]
        return out

    if vendor == "samd":
        series = t.get("series")
        if series == 21:
            ok = {0, 512, 1024, 2048, 4096, 8192, 16384, 32768}
            if bsize not in ok:
                raise ProvisionError(f"SAM D21 BOOTPROT covers 512 B..32 KB in powers of two; the bootloader region is "
                                     f"{bsize} bytes. Rebuild with BOOT_SIZE set to one of those so the protection "
                                     "doesn't cover the boot log.")
            cmd = "at91samd"
        else:
            if bsize % 8192 or bsize > 15 * 8192:
                raise ProvisionError(f"SAM D51 BOOTPROT covers multiples of 8 KB up to 120 KB; the bootloader region is "
                                     f"{bsize} bytes. Rebuild with a matching BOOT_SIZE.")
            cmd = "atsame5"
        out += [
            f"SAM D{series}: the BOOTPROT fuse (user row) write-protects the first {bsize // 1024} KB, from the CPU too.",
            f"  1. openocd -f <your interface/target cfg> -c 'init; reset init; {cmd} bootloader {bsize}; reset; shutdown'",
            "     (takes effect after a reset)",
            "  2. Optional, no debugger access at all (Security Bit): openocd ... -c 'init; reset init; "
            + ("at91samd set-security enable" if series == 21 else "<atsame5 has no set-security: use Microchip Studio / edbg>")
            + "; shutdown'",
            "     Only a chip erase clears it, and OpenOCD can't talk to a secured chip (use edbg or Microchip Studio).",
            "",
            "Note: software can rewrite the user row. A compromised app could clear BOOTPROT; it takes effect only",
            "after a reset, and MimiBoot doesn't yet check and restore it at boot (see docs/SECURITY.md).",
            f"Undo: openocd ... -c '{cmd} bootloader 0' (and a chip erase if the security bit is set).",
        ]
        return out

    if t.build == "pico":
        out += ["RP2040: no flash or debug protection exists on this chip.",
                "RP2350: secure boot means burning OTP (boot key hashes, SECURE_BOOT_ENABLE, debug disable), which",
                "can never be undone. MimiBoot doesn't automate it: see the RP2350 datasheet (secure boot chapter)",
                "and picotool seal / picotool otp."]
        return out
    raise ProvisionError(f"no provisioning steps for vendor {vendor!r}")
