#!/usr/bin/env python3
"""
mbtool - host side of MimiBoot-Mu: images, keys and the console upload protocol

Images
  pack    app.elf -o app.mimg --name NAME --version 1.2.3 [--secver N] [--key K] [--golden]
          wrap a pico-sdk build in a MimiBoot image (one 4 KB header sector,
          then the payload byte for byte). From an .elf it takes the load
          address (flash = run in place, SRAM = RAM image), the architecture
          (Arm / RISC-V) and the `mb_handoff` buffer address, and checks them
          against the payload's own IMAGE_DEF. A .bin is taken as a flash
          image; its arch comes from the IMAGE_DEF.
  info    app.mimg [--pub keys/mimiboot.pub]      show and check an image
  sign    app.mimg --key keys/mimiboot.key        (re)sign an image in place
  keygen  [--out keys/mimiboot]                   new Ed25519 key: .key (secret, keep it
                                                  out of git), .pub, and _keys.h for the build
  uf2     app.mimg --slot a -o app_a.uf2          a UF2 that lands the image in a slot
  flash   app.mimg --slot a                       picotool load at the slot address (never -x)

Talking to the bootloader console (press BOOT while the backlight is lit
right after power-up, or have the app request the menu)
  install app.mimg --slot b       upload into a slot (recv), it boots as a trial next
  ramboot app.mimg [-- args...]   send a RAM image and start it; flash untouched
  cfg push boot.cfg | cfg show    the boot config
  cmd "ls" "verify" ...           run console commands, print the output

Talking to a running OS (OTA)
  ota app.mimg [--slot b]         the OS's `boot recv` command (mb_client_recv): installs into the other slot

One step, no buttons
  deploy app.mimg [--slot b]      an OS running? ask it for MimiBoot's flash mode
                                  (`boot flash`), wait for MimiBoot, install into the
                                  slot it isn't running from, boot it as a trial

  layout                          the default flash map
"""
import argparse
import hashlib
import os
import re
import struct
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mb_ed25519 as ed25519  # noqa: E402

MAGIC = 0x474D494D
HDR_VERSION = 2
HDR_SIZE = 256
SIGNED_BYTES = 188
PAYLOAD_OFF = 4096
LOAD_CHAIN, LOAD_RAM = 1, 2
ARCH_ANY, ARCH_ARM, ARCH_RISCV = 0, 1, 2
ARCH_NAMES = {ARCH_ANY: "any", ARCH_ARM: "arm", ARCH_RISCV: "riscv"}
F_GOLDEN, F_SIGNED = 0x1, 0x2
TARGET = "rp2350"
XIP_BASE = 0x10000000
SRAM_BASE, SRAM_END = 0x20000000, 0x20082000
# offset, size (bytes) - keep in sync with include/mimiboot/mb_layout.h
LAYOUTS = {
    "2m": {"boot": (0, 0x3c000), "log": (0x3c000, 0x2000), "cfg": (0x3e000, 0x2000),
           "a": (0x40000, 0x80000), "b": (0xc0000, 0x80000), "g": (0x140000, 0x40000),
           "c": (0x180000, 0x40000), "data": (0x1c0000, 0x40000)},
    "16m": {"boot": (0x000000, 0x03C000), "log": (0x03C000, 0x2000), "cfg": (0x03E000, 0x2000),
            "a": (0x040000, 0x200000), "b": (0x240000, 0x200000), "g": (0x440000, 0x100000),
            "c": (0x540000, 0x200000), "d": (0x740000, 0x200000), "data": (0x940000, (16 << 20) - 0x940000)},
    "4m": {"boot": (0x000000, 0x03C000), "log": (0x03C000, 0x2000), "cfg": (0x03E000, 0x2000),
           "a": (0x040000, 0x100000), "b": (0x140000, 0x100000), "g": (0x240000, 0x080000),
           "c": (0x2C0000, 0x080000), "data": (0x340000, 0x0C0000)},
}
SLOTS = ("a", "b", "g", "c", "d")
UF2_MAGIC0, UF2_MAGIC1, UF2_MAGIC_END = 0x0A324655, 0x9E5D5157, 0x0AB16F30
UF2_FAMILY_RP2040 = 0xE48BFF56
UF2_FAMILY_ABSOLUTE = 0xE48BFF57
UF2_FAMILY_RP2350_ARM_S = 0xE48BFF59
UF2_FAMILY_RP2350_RISCV = 0xE48BFF5A
UF2_EXT_RP2_IGNORE_BLOCK = 0x9957E3

# mb_image_hdr_t (include/mimiboot/mb_image.h), everything but hdr_crc
HDR_FMT = "<IHHIIII32sIIIIII32s16sB3sII48s64s"
HDR_FIELDS = ["magic", "hdr_version", "hdr_size", "flags", "load_type", "payload_offset", "payload_size", "sha256",
              "version", "security_version", "build_time", "load_addr", "entry", "trial_timeout_ms", "name", "target",
              "arch", "pad", "handoff_addr", "key_id", "reserved", "signature"]
assert struct.calcsize(HDR_FMT) == HDR_SIZE - 4
assert struct.calcsize(HDR_FMT[:HDR_FMT.index("64s")]) == SIGNED_BYTES


def die(msg):
    raise SystemExit("mbtool: " + msg)


def parse_version(s):
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", s)
    if not m:
        die("version must look like 1.2.3")
    a, b, c = (int(x or 0) for x in m.groups())
    if a > 255 or b > 255 or c > 0xFFFF:
        die("version parts too big (255.255.65535)")
    return a << 24 | b << 16 | c


def fmt_version(v):
    return "%d.%d.%d" % (v >> 24, (v >> 16) & 0xFF, v & 0xFFFF)


# ---------------------------------------------------------------------------
# Inputs: ELF, UF2, BIN
# ---------------------------------------------------------------------------

def read_elf(data):
    """Flat image of the PT_LOAD segments (by physical address), e_machine, symbols."""
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        die("only 32-bit little-endian ELF files")
    e_machine = struct.unpack_from("<H", data, 18)[0]
    e_phoff, e_shoff = struct.unpack_from("<II", data, 28)
    e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHHHH", data, 42)
    segs = []
    for i in range(e_phnum):
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _, _ = struct.unpack_from("<IIIIIIII", data, e_phoff + i * e_phentsize)
        if p_type == 1 and p_filesz:
            segs.append((p_paddr, data[p_offset:p_offset + p_filesz]))
    if not segs:
        die("no loadable segments in the ELF")
    base = min(a for a, _ in segs)
    end = max(a + len(d) for a, d in segs)
    if end - base > 16 << 20:
        die("ELF segments span %d bytes - not one image" % (end - base))
    img = bytearray(b"\xff" * (end - base))
    for a, d in segs:
        img[a - base:a - base + len(d)] = d
    # symbols, for mb_handoff
    syms = {}
    for i in range(e_shnum):
        sh = struct.unpack_from("<IIIIIIIIII", data, e_shoff + i * e_shentsize)
        if sh[1] != 2:                                      # SHT_SYMTAB
            continue
        strtab = struct.unpack_from("<IIIIIIIIII", data, e_shoff + sh[6] * e_shentsize)
        for k in range(sh[5] // 16):
            st_name, st_value = struct.unpack_from("<II", data, sh[4] + k * 16)
            nm = data[strtab[4] + st_name:data.index(b"\0", strtab[4] + st_name)].decode(errors="replace")
            syms[nm] = st_value
    arch = {40: ARCH_ARM, 243: ARCH_RISCV}.get(e_machine)
    if arch is None:
        die("ELF machine %d is neither Arm nor RISC-V" % e_machine)
    return bytes(img), base, arch, syms


def uf2_to_bin(data):
    blocks = {}
    for i in range(0, len(data), 512):
        b = data[i:i + 512]
        m0, m1, flags, addr, size, _, _, family = struct.unpack_from("<IIIIIIII", b)
        if m0 != UF2_MAGIC0 or m1 != UF2_MAGIC1 or flags & 1 or not flags & 0x2000:
            continue
        if family not in (UF2_FAMILY_RP2040, UF2_FAMILY_RP2350_ARM_S, UF2_FAMILY_RP2350_RISCV):     # skips the E10 ignore-block
            continue
        blocks[addr] = b[32:32 + size]
    if not blocks:
        die("no RP2040/RP2350 blocks in the UF2")
    lo, hi = min(blocks), max(a + len(d) for a, d in blocks.items())
    out = bytearray(b"\xff" * (hi - lo))
    for a, d in blocks.items():
        out[a - lo:a - lo + len(d)] = d
    return bytes(out), lo


def find_image_def(payload):
    """The payload's own picobin IMAGE_DEF: (cpu, chip) or None. Searched in the first 4 KB."""
    marker = struct.pack("<I", 0xFFFFDED3)
    at = 0
    while True:
        at = payload.find(marker, at, 4096 + 4)
        if at < 0 or at % 4:
            if at < 0:
                return None
            at += 1
            continue
        p = at + 4
        while p + 4 <= len(payload):
            item = payload[p]
            size = (payload[p + 1] | payload[p + 2] << 8) if item & 0x80 else payload[p + 1]
            if item == 0x42:                                # IMAGE_TYPE: 1-byte size, flags in bytes 2-3
                flags = payload[p + 2] | payload[p + 3] << 8
                if flags & 0x000F == 1:                      # EXE
                    return ((flags >> 8) & 7, (flags >> 12) & 7)
            if item == 0xFF or size == 0:                    # LAST item / garbage
                break
            p += size * 4
        at += 4


def read_input(path, load_addr=None, target=TARGET):
    """-> payload, base address, arch, handoff_addr"""
    data = open(path, "rb").read()
    low = path.lower()
    if data[:4] == struct.pack("<I", MAGIC):
        die("%s is already a MimiBoot image" % path)
    syms = {}
    if data[:4] == b"\x7fELF":
        payload, base, arch, syms = read_elf(data)
    elif low.endswith(".uf2"):
        payload, base = uf2_to_bin(data)
        arch = None
    else:
        payload, base, arch = data, load_addr if load_addr is not None else XIP_BASE, None
    idef = find_image_def(payload) if target.startswith("rp2") else None
    if idef is None and target.startswith("rp2350"):
        print("warning: no IMAGE_DEF in the first 4 KB - the RP2350 bootrom won't start this")
    elif idef is not None:
        cpu = {0: ARCH_ARM, 1: ARCH_RISCV}.get(idef[0])
        if arch is not None and cpu is not None and cpu != arch:
            die("the ELF says %s but the IMAGE_DEF says %s" % (ARCH_NAMES[arch], ARCH_NAMES[cpu]))
        arch = cpu if arch is None else arch
    if arch is None:
        arch = ARCH_ARM
    return payload, base, arch, syms.get("mb_handoff", 0), syms.get("__vectors", base)


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

def build_header(payload, name, version, secver=0, golden=False, trial_ms=0, target=TARGET, arch=ARCH_ARM,
                 load_type=LOAD_CHAIN, load_addr=0, handoff_addr=0, secret=None, build_time=None, entry=None):
    flags = F_GOLDEN if golden else 0
    key_id = 0
    if secret:
        flags |= F_SIGNED
        key_id = struct.unpack("<I", ed25519.public_key(secret)[:4])[0]
    fields = [MAGIC, HDR_VERSION, HDR_SIZE, flags, load_type, PAYLOAD_OFF, len(payload), hashlib.sha256(payload).digest(),
              version, secver, int(time.time() if build_time is None else build_time), load_addr, load_addr if entry is None else entry, trial_ms,
              name.encode()[:31].ljust(32, b"\0"), target.encode()[:15].ljust(16, b"\0"), arch, b"\0" * 3,
              handoff_addr, key_id, b"\0" * 48, b"\0" * 64]
    body = struct.pack(HDR_FMT, *fields)
    if secret:
        body = body[:SIGNED_BYTES] + ed25519.sign(secret, body[:SIGNED_BYTES])
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def resign(hdr, secret):
    body = bytearray(hdr[:HDR_SIZE - 4])
    flags = struct.unpack_from("<I", body, 8)[0] | F_SIGNED
    struct.pack_into("<I", body, 8, flags)
    struct.pack_into("<I", body, 136, struct.unpack("<I", ed25519.public_key(secret)[:4])[0])
    body[SIGNED_BYTES:] = ed25519.sign(secret, bytes(body[:SIGNED_BYTES]))
    return bytes(body) + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def parse_header(img):
    if len(img) < PAYLOAD_OFF:
        die("too short for a MimiBoot image")
    h = dict(zip(HDR_FIELDS, struct.unpack(HDR_FMT, img[:HDR_SIZE - 4])))
    h["name"] = h["name"].split(b"\0")[0].decode(errors="replace")
    h["target"] = h["target"].split(b"\0")[0].decode(errors="replace")
    h["crc_ok"] = (zlib.crc32(img[:HDR_SIZE - 4]) & 0xFFFFFFFF) == struct.unpack_from("<I", img, HDR_SIZE - 4)[0]
    return h


def image_file(path):
    img = open(path, "rb").read()
    h = parse_header(img)
    problems = []
    if h["magic"] != MAGIC:
        problems.append("bad magic")
    if h["hdr_version"] != HDR_VERSION:
        problems.append("header version %d (this mbtool writes %d)" % (h["hdr_version"], HDR_VERSION))
    if not h["crc_ok"]:
        problems.append("header CRC mismatch")
    payload = img[h["payload_offset"]:h["payload_offset"] + h["payload_size"]]
    if len(payload) != h["payload_size"]:
        problems.append("file shorter than the payload")
    elif hashlib.sha256(payload).digest() != h["sha256"]:
        problems.append("payload SHA-256 mismatch")
    return img, h, payload, problems


def read_key(path):
    s = open(path).read().strip()
    try:
        k = bytes.fromhex(s)
    except ValueError:
        die("%s: expected 64 hex digits" % path)
    if len(k) != 32:
        die("%s: a key is 32 bytes" % path)
    return k


def slot_region(slot, layout):
    key = {"golden": "g"}.get(slot.lower(), slot.lower())
    if key not in LAYOUTS[layout] or key in ("boot", "log", "cfg", "data"):
        die("slot is one of %s" % ", ".join(s for s in SLOTS if s in LAYOUTS[layout]))
    return LAYOUTS[layout][key]


# ---------------------------------------------------------------------------
# Image commands
# ---------------------------------------------------------------------------

# MCU flash (no XIP remapping: an image runs where it is linked)
MCU_FLASH = ((0x08000000, 16 << 20),    # STM32
             (0x00000000, 4 << 20))     # nRF, SAM D (flash at address 0)


def pack_mcu(a, payload, base, arch, handoff):
    """Cortex-M MCUs other than RP: XIP images are linked at their slot's address + 0x1000."""
    if any(lo <= base < lo + size for lo, size in MCU_FLASH):
        load_type, load_addr = LOAD_CHAIN, 0
        if base % 4096:
            die("the vector table (0x%08x) must sit 0x1000 into a slot: link at <slot address> + 0x1000 (layout.txt)" % base)
    elif SRAM_BASE <= base < 0x20200000:
        load_type, load_addr = LOAD_RAM, base
    else:
        die("load address 0x%08x is neither MCU flash (0x08000000 STM32, 0x0 nRF/SAMD) nor SRAM" % base)
    if arch != ARCH_ARM:
        die("Cortex-M targets take Arm images")
    if len(payload) < 8:
        die("payload too short for a vector table")
    sp, pc = struct.unpack_from("<II", payload, 0)
    if sp & 3 or not (0x10000000 <= sp <= 0x20200000) or not pc & 1 or not (base <= (pc & ~1) < base + len(payload)):
        die("no valid vector table at the start of the payload (sp 0x%08x, reset 0x%08x)" % (sp, pc))
    return load_type, load_addr


def cmd_pack(a):
    payload, base, arch, handoff, vectors = read_input(a.input, int(a.load_addr, 0) if a.load_addr else None, a.target)
    if not a.target.startswith("rp2"):
        load_type, load_addr = pack_mcu(a, payload, base, arch, handoff)
    elif XIP_BASE <= base < XIP_BASE + (16 << 20):
        if base != XIP_BASE:
            die("flash images must be linked at 0x10000000 (this one starts at 0x%08x)" % base)
        load_type, load_addr = LOAD_CHAIN, 0
    elif SRAM_BASE <= base < SRAM_END:
        load_type, load_addr = LOAD_RAM, base
        if base + len(payload) > SRAM_END:
            die("RAM image runs past the end of SRAM")
    else:
        die("load address 0x%08x is neither flash nor SRAM" % base)
    if a.arch:
        want = {"arm": ARCH_ARM, "riscv": ARCH_RISCV}[a.arch]
        if want != arch:
            die("--arch %s, but the image is built for %s" % (a.arch, ARCH_NAMES[arch]))
    if a.target == "rp2040":
        if load_type != LOAD_RAM or arch != ARCH_ARM:
            die("RP2040 requires an Arm RAM-linked ELF (no XIP slot remapping)")
        if vectors & 255 or not (load_addr <= vectors <= load_addr + len(payload) - 8):
            die("RP2040 needs an aligned vector table inside its payload")
        sp, pc = struct.unpack_from("<II", payload, vectors-load_addr)
        if not (0x20000000 <= sp <= 0x20042000) or sp & 7 or not pc & 1 or not (load_addr <= (pc & ~1) < load_addr+len(payload)):
            die("RP2040 vector table has an invalid stack pointer or reset PC")
        if load_addr + len(payload) > 0x20020000:
            die("RP2040 RAM payload overlaps loader at 0x20020000")
    secret = read_key(a.key) if a.key else None
    name = a.name or os.path.splitext(os.path.basename(a.input))[0]
    hdr = build_header(payload, name, parse_version(a.version), a.secver, a.golden, a.trial_ms, a.target, arch,
                       load_type, load_addr, handoff, secret, entry=vectors if a.target=="rp2040" else None)
    img = hdr + b"\xff" * (PAYLOAD_OFF - HDR_SIZE) + payload
    out = a.output or os.path.splitext(a.input)[0] + ".mimg"
    open(out, "wb").write(img)
    print("%s: %s v%s, %s %s%s, %d bytes, sha256 %s%s%s" % (
        out, name, a.version, ARCH_NAMES[arch], "xip" if load_type == LOAD_CHAIN else "ram@0x%08x" % load_addr,
        " (golden)" if a.golden else "", len(payload), hashlib.sha256(payload).hexdigest()[:16],
        ", handoff @0x%08x" % handoff if handoff else "", ", signed" if secret else ""))


def cmd_info(a):
    img, h, payload, problems = image_file(a.image)
    print("name      %s%s" % (h["name"], "   (golden)" if h["flags"] & F_GOLDEN else ""))
    print("version   %s   security %d" % (fmt_version(h["version"]), h["security_version"]))
    print("target    %s/%s   load %s" % (h["target"], ARCH_NAMES.get(h["arch"], "?"),
                                         "xip" if h["load_type"] == LOAD_CHAIN else "ram @0x%08x" % h["load_addr"]))
    print("payload   %d bytes at +0x%x" % (h["payload_size"], h["payload_offset"]))
    print("sha256    %s" % h["sha256"].hex())
    if h["handoff_addr"]:
        print("handoff   @0x%08x" % h["handoff_addr"])
    print("built     %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["build_time"])))
    if h["flags"] & F_SIGNED:
        line = "signed    key %08x" % h["key_id"]
        if a.pub:
            ok = ed25519.verify(read_key(a.pub), img[:SIGNED_BYTES], h["signature"])
            line += ": signature %s" % ("OK" if ok else "BAD")
            if not ok:
                problems.append("bad signature")
        print(line)
    else:
        print("signed    no")
    for s in SLOTS:
        if s in LAYOUTS[a.layout]:
            fits = len(payload) + PAYLOAD_OFF <= LAYOUTS[a.layout][s][1]
            print("fits %-5s %s (%d KB)" % (s, "yes" if fits else "NO", LAYOUTS[a.layout][s][1] // 1024))
    print("check     %s" % ("OK" if not problems else ", ".join(problems)))
    return 0 if not problems else 1


def cmd_sign(a):
    img, h, _, problems = image_file(a.image)
    if problems:
        die("refusing to sign a broken image: " + ", ".join(problems))
    img = resign(img[:HDR_SIZE], read_key(a.key)) + img[HDR_SIZE:]
    open(a.output or a.image, "wb").write(img)
    print("signed %s with key %s" % (a.output or a.image, ed25519.public_key(read_key(a.key))[:4].hex()))


def cmd_keygen(a):
    base = a.out
    if os.path.exists(base + ".key") and not a.force:
        die("%s.key exists (--force to replace it; images signed with it would stop booting)" % base)
    os.makedirs(os.path.dirname(base) or ".", exist_ok=True)
    secret = os.urandom(32)
    pub = ed25519.public_key(secret)
    open(base + ".key", "w").write(secret.hex() + "\n")
    open(base + ".pub", "w").write(pub.hex() + "\n")
    with open(base + "_keys.h", "w") as f:
        f.write("/* MimiBoot trusted keys: generated by mbtool keygen. Build with -DMB_KEYS_HEADER=... */\n")
        f.write("#define MB_TRUSTED_KEY_COUNT 1\n#define MB_TRUSTED_KEYS { { %s } }\n" % ", ".join("0x%02x" % b for b in pub))
    gi = os.path.join(os.path.dirname(base) or ".", ".gitignore")
    lines = open(gi).read().split() if os.path.exists(gi) else []
    if "*.key" not in lines:
        open(gi, "a").write("*.key\n")
    print("secret %s.key (keep it private; *.key is gitignored)\npublic %s.pub  key id %s\nbuild  %s_keys.h"
          % (base, base, pub[:4].hex(), base))


def cmd_uf2(a):
    img, h, _, problems = image_file(a.image)
    if problems:
        die("refusing a broken image: " + ", ".join(problems))
    off, size = slot_region(a.slot, a.layout)
    if len(img) > size:
        die("image is %d bytes, slot %s holds %d" % (len(img), a.slot, size))
    img += b"\xff" * (-len(img) % 256)
    n = len(img) // 256
    ext = struct.pack("<I", 4 | UF2_EXT_RP2_IGNORE_BLOCK << 8)
    # first an ignored absolute-family block (RP2350-E10 workaround, as picotool does), then the data
    out = bytearray(struct.pack("<IIIIIIII", UF2_MAGIC0, UF2_MAGIC1, 0xA000, 0x10FFFF00, 256, 0, 2, UF2_FAMILY_ABSOLUTE)
                    + b"\xef" * 256 + ext + b"\0" * (476 - 256 - 4) + struct.pack("<I", UF2_MAGIC_END))
    if h["target"] == "rp2040":
        out = bytearray()
    fam = UF2_FAMILY_RP2350_RISCV if h["arch"] == ARCH_RISCV else UF2_FAMILY_RP2350_ARM_S
    if h["target"] == "rp2040":
        fam = UF2_FAMILY_RP2040
    for i in range(n):
        out += struct.pack("<IIIIIIII", UF2_MAGIC0, UF2_MAGIC1, 0x2000, XIP_BASE + off + i * 256, 256, i, n, fam) \
            + img[i * 256:(i + 1) * 256] + b"\0" * (476 - 256) + struct.pack("<I", UF2_MAGIC_END)
    dst = a.output or os.path.splitext(a.image)[0] + "_slot%s.uf2" % a.slot.lower()
    open(dst, "wb").write(out)
    print("%s: %d blocks at 0x%08x (slot %s)" % (dst, n, XIP_BASE + off, a.slot))


def cmd_flash(a):
    import subprocess
    img, h, _, problems = image_file(a.image)
    if problems:
        die("refusing a broken image: " + ", ".join(problems))
    off, size = slot_region(a.slot, a.layout)
    if len(img) > size:
        die("image doesn't fit slot %s" % a.slot)
    tmp = a.image + ".bin"
    open(tmp, "wb").write(img)
    # never -x and never a load at 0x10000000: that would overwrite the bootloader
    cmd = [a.picotool, "load", tmp, "-o", "0x%08x" % (XIP_BASE + off)] + (["-f"] if a.force else [])
    print(" ".join(cmd))
    r = subprocess.call(cmd)
    os.remove(tmp)
    if r == 0:
        print("loaded; reboot with: %s reboot" % a.picotool)
    return r


# ---------------------------------------------------------------------------
# Serial: bootloader console, a running OS
# ---------------------------------------------------------------------------

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
PROMPT = r"mimiboot\x1b\[0m> $|mimiboot> $"


def open_serial(port):
    import serial
    from serial.tools import list_ports
    if not port:
        cands = [p for p in list_ports.comports() if p.vid == 0x2E8A]
        cands.sort(key=lambda p: (p.location or "")[-1:] != "0")       # interface 0 first
        if not cands:
            die("no RP2040/RP2350 serial port found (MimiBoot console: press BOOT while the backlight is lit after power-up)")
        if len(cands) > 1:
            die("multiple RP boards found; specify --port: " + ", ".join(p.device for p in cands))
        port = cands[0].device
    s = serial.Serial(port, 115200, timeout=0.1)
    s.dtr = True
    time.sleep(0.5)
    return s


def read_until(s, pattern, timeout):
    buf = b""
    end = time.time() + timeout
    rx = re.compile(pattern)
    while time.time() < end:
        buf += s.read(4096)
        m = rx.search(buf.decode("utf-8", "replace"))
        if m:
            return buf.decode("utf-8", "replace"), m
    return buf.decode("utf-8", "replace"), None


def to_shell(s):
    """Menu or shell -> shell prompt. Never Enter first: in the menu it boots the selection."""
    s.write(b"c")
    out, m = read_until(s, PROMPT, 3)
    if not m:
        s.write(b"\r")
        out, m = read_until(s, PROMPT, 3)
    if not m:
        die("no MimiBoot prompt; output was:\n" + out[-500:])


def send_image(s, img, payload, ready_timeout=10):
    """The mb_recv protocol, after the device has been told to receive.
    (Replies end in 
 on real hardware - pico stdio translates - and in 
 in the simulator.)"""
    out, m = read_until(s, r"MB READY (\d+) (\S+)|MB ERR[^\r\n]*|golden is the recovery[^\r\n]*|which slot[^\r\n]*", ready_timeout)
    if not m or not m.group(0).startswith("MB READY"):
        die("device refused: " + ANSI.sub("", out)[-300:])
    max_frame, where = int(m.group(1)), m.group(2)
    s.write(b"H" + img[:HDR_SIZE])
    out, m = read_until(s, r"MB (OK|ERR[^\r\n]*)\r?\n", 180)        # erasing a big slot takes a while
    if not m or m.group(1) != "OK":
        die("header rejected: " + (m.group(0) if m else out[-200:]))
    t0 = time.time()
    off = 0
    while off < len(payload):
        data = payload[off:off + max_frame]
        frame = b"D" + struct.pack("<IH", off, len(data)) + data + struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)
        for _ in range(5):
            s.write(frame)
            _, m = read_until(s, r"MB (OK \d+|ERR[^\r\n]*)\r?\n", 5)
            if m and m.group(1).startswith("OK"):
                break
            print("  resend @%d (%s)" % (off, m.group(1) if m else "timeout"))
        else:
            s.write(b"X")
            die("giving up at offset %d" % off)
        off += len(data)
        if off % (64 * 1024) < max_frame or off == len(payload):
            rate = off / max(time.time() - t0, 1e-3) / 1024
            print("\r  %3d%%  %d KB  %.0f KB/s  -> %s" % (off * 100 // len(payload), off // 1024, rate, where), end="", flush=True)
    print()
    s.write(b"E")
    out, m = read_until(s, r"MB (DONE|ERR[^\r\n]*)\r?\n", 60)
    if not m or m.group(1) != "DONE":
        die("failed: " + (m.group(0) if m else out[-200:]))


def checked_image(path):
    img, h, payload, problems = image_file(path)
    if problems:
        die("refusing a broken image: " + ", ".join(problems))
    return img, h, payload


def cmd_install(a):
    img, h, payload = checked_image(a.image)
    s = open_serial(a.port)
    to_shell(s)
    s.write(("recv %s%s\r" % (a.slot, " force" if a.slot.lower().startswith("g") else "")).encode())
    send_image(s, img, payload)
    print("installed in slot %s; it boots next (as a trial if it's an A/B update)" % a.slot)


def cmd_ramboot(a):
    img, h, payload = checked_image(a.image)
    if h["load_type"] != LOAD_RAM:
        die("%s is a flash image: ramboot needs one linked for SRAM (pico_set_binary_type(... no_flash))" % a.image)
    s = open_serial(a.port)
    to_shell(s)
    s.write(("ramboot %s\r" % " ".join(a.args)).encode())
    send_image(s, img, payload)
    out, _ = read_until(s, r"starting [^\r\n]*\r?\n|launch failed[^\r\n]*", 5)
    print(ANSI.sub("", out).strip())


def cmd_ota(a):
    img, h, payload = checked_image(a.image)
    s = open_serial(a.port)
    s.write(b"\x15\r")                                         # Ctrl-U + Enter: a clean OS shell prompt
    read_until(s, r"\$ $", 3)
    s.write(("boot recv%s\r" % (" " + a.slot if a.slot else "")).encode())
    send_image(s, img, payload, ready_timeout=15)
    print("installed; `boot` shows it, reboot to try it (MimiBoot boots it as a trial)")


def rp_ports():
    from serial.tools import list_ports
    return sorted(p.device for p in list_ports.comports() if p.vid == 0x2E8A)


def wait_reconnect(before, timeout=20):
    """After a reboot: wait for the device's ports to go away and come back."""
    t0 = time.time()
    gone = False
    while time.time() - t0 < timeout:
        now = rp_ports()
        if not now or now != before:
            gone = True
        if gone and now:
            time.sleep(0.5)                                     # let Windows finish enumerating
            return
        time.sleep(0.1)
    die("the device didn't come back after rebooting")


def who(s):
    """'os', 'menu' or 'mimiboot' (its prompt). Sends only Ctrl-U: harmless everywhere."""
    s.reset_input_buffer()
    s.write(b"\x15")
    # prompts are coloured: match on the text with the ANSI codes taken out
    out, _ = read_until(s, r"fox(?:\x1b\[[0-9;]*m)*@|MimiBoot(?:-Night)? \d|MB FLASH READY", 1.5)
    text = ANSI.sub("", out)
    if "fox@" in text:
        return "os"
    if "MimiBoot" in text:
        return "menu"
    return "mimiboot"


def cmd_deploy(a):
    img, h, payload = checked_image(a.image)
    s = open_serial(a.port)
    kind = who(s)
    slot = a.slot
    if kind == "os":
        if not slot:
            s.write(b"boot\r")
            out, _ = read_until(s, r"running from slot (\w+)|not started by MimiBoot", 5)
            m = re.search(r"running from slot (\w+)", out)
            slot = {"a": "b", "b": "a"}.get(m.group(1) if m else "", "a")
            print("the OS runs from %s: installing into %s" % (m.group(1) if m else "?", slot))
        before = rp_ports()
        s.write(b"boot flash\r")
        read_until(s, r"rebooting", 3)
        s.close()
        print("OS -> MimiBoot flash mode...")
        wait_reconnect(before)
        s = open_serial(a.port)
        out, m = read_until(s, r"MB FLASH READY", 10)
        if not m:
            die("MimiBoot didn't enter flash mode; it said:\n" + ANSI.sub("", out)[-300:])
        to_shell(s)
    else:
        to_shell(s)
        slot = slot or "a"
    print("installing %s into slot %s" % (h["name"], slot))
    s.write(("recv %s%s\r" % (slot, " force" if slot.lower().startswith("g") else "")).encode())
    send_image(s, img, payload)
    s.write(b"exit\r")                                          # leave flash mode: MimiBoot boots normally
    print("installed; MimiBoot boots it (a new A/B image as a trial: the OS must confirm it)")


def cmd_cfg(a):
    s = open_serial(a.port)
    to_shell(s)
    if a.action == "show":
        s.write(b"cfg show\r")
        out, _ = read_until(s, PROMPT, 10)
        print("\n".join(ANSI.sub("", out).replace("\r", "").split("\n")[1:-1]))
        return
    text = open(a.file, "rb").read()
    if len(text) > 3840:
        die("config is %d bytes, the limit is 3840" % len(text))
    s.write(b"cfg recv\r")
    out, m = read_until(s, r"MB CFG READY", 5)
    if not m:
        die("no CFG READY: " + out[-200:])
    s.write(struct.pack("<H", len(text)) + text + struct.pack("<I", zlib.crc32(text) & 0xFFFFFFFF))
    out, m = read_until(s, r"MB (DONE|ERR[^\r\n]*)", 20)
    print(ANSI.sub("", out).strip())
    if not m or m.group(1) != "DONE":
        return 1


def cmd_cmd(a):
    s = open_serial(a.port)
    to_shell(s)
    import serial
    for c in a.commands:
        s.write(c.encode() + b"\r")
        try:
            out, _ = read_until(s, PROMPT, a.timeout)
        except serial.SerialException:
            # exit / boot / reboot: the bootloader hands over and the port goes away
            print("(device went away after '%s': it is booting)" % c)
            return
        lines = ANSI.sub("", out).replace("\r", "").split("\n")
        print("\n".join(lines[1:-1]) if len(lines) > 2 else "\n".join(lines))


def cmd_layout(a):
    for k, (off, size) in LAYOUTS[a.layout].items():
        print("%-5s 0x%06x  %6d KB   XIP 0x%08x" % (k, off, size // 1024, XIP_BASE + off))


def main():
    ap = argparse.ArgumentParser(description="MimiBoot host tool", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--layout", default="4m", choices=LAYOUTS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pack"); p.add_argument("input"); p.add_argument("-o", "--output")
    p.add_argument("--name"); p.add_argument("--version", default="0.0.1"); p.add_argument("--secver", type=int, default=0)
    p.add_argument("--golden", action="store_true"); p.add_argument("--trial-ms", type=int, default=0)
    p.add_argument("--key", help="sign with this secret key file"); p.add_argument("--arch", choices=["arm", "riscv"],
                                                                                    help="refuse to pack anything else")
    p.add_argument("--load-addr", help=".bin only: where it runs (default flash)")
    p.add_argument("--target", default=TARGET, help="target as the bootloader names it: rp2040, rp2350, or the chip from mimiconf (e.g. stm32f411ce); RP2040 requires a RAM-linked payload"); p.set_defaults(fn=cmd_pack)
    p = sub.add_parser("info"); p.add_argument("image"); p.add_argument("--pub"); p.set_defaults(fn=cmd_info)
    p = sub.add_parser("sign"); p.add_argument("image"); p.add_argument("--key", required=True); p.add_argument("-o", "--output")
    p.set_defaults(fn=cmd_sign)
    p = sub.add_parser("keygen"); p.add_argument("--out", default="keys/mimiboot"); p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_keygen)
    p = sub.add_parser("uf2"); p.add_argument("image"); p.add_argument("--slot", required=True); p.add_argument("-o", "--output")
    p.set_defaults(fn=cmd_uf2)
    p = sub.add_parser("flash"); p.add_argument("image"); p.add_argument("--slot", required=True)
    p.add_argument("--picotool", default=os.environ.get("PICOTOOL", "picotool")); p.add_argument("-f", "--force", action="store_true")
    p.set_defaults(fn=cmd_flash)
    p = sub.add_parser("install"); p.add_argument("image"); p.add_argument("--slot", required=True); p.add_argument("--port")
    p.set_defaults(fn=cmd_install)
    p = sub.add_parser("ramboot"); p.add_argument("image"); p.add_argument("args", nargs="*"); p.add_argument("--port")
    p.set_defaults(fn=cmd_ramboot)
    p = sub.add_parser("ota"); p.add_argument("image"); p.add_argument("--slot"); p.add_argument("--port"); p.set_defaults(fn=cmd_ota)
    p = sub.add_parser("deploy"); p.add_argument("image"); p.add_argument("--slot"); p.add_argument("--port"); p.set_defaults(fn=cmd_deploy)
    p = sub.add_parser("cfg"); p.add_argument("action", choices=["push", "show"]); p.add_argument("file", nargs="?")
    p.add_argument("--port"); p.set_defaults(fn=cmd_cfg)
    p = sub.add_parser("cmd"); p.add_argument("commands", nargs="+"); p.add_argument("--port"); p.add_argument("--timeout", type=float, default=10)
    p.set_defaults(fn=cmd_cmd)
    p = sub.add_parser("layout"); p.set_defaults(fn=cmd_layout)
    a = ap.parse_args()
    if a.cmd == "cfg" and a.action == "push" and not a.file:
        die("cfg push <file>")
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
