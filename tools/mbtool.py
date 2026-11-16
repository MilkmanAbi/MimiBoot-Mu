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
  keygen  [--out keys/mimiboot] [--type ...]      new key: .key (secret, keep it out of git),
                                                  .pub, and _keys.h for the build. Ed25519 by default;
                                                  p256, lms (post-quantum, stateful), x25519 (decryption)
  uf2     app.mimg --slot a -o app_a.uf2          a UF2 that lands the image in a slot
  flash   app.mimg --slot a                       picotool load at the slot address (never -x)

Talking to the bootloader console (press BOOT while the backlight is lit
right after power-up, or have the app request the menu)
  install app.mimg --slot b       upload into a slot (recv), it boots as a trial next
  ramboot app.mimg [-- args...]   send a RAM image and start it; flash untouched
  cfg push boot.cfg | cfg show    the boot config
  cmd "ls" "verify" ...           run console commands, print the output
  loader build/ [--reboot]        two-stage boards: new stage 1 into the copy that isn't running

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
import json
import os
import re
import struct
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mb_ed25519 as ed25519  # noqa: E402
import mb_p256 as p256  # noqa: E402
import mb_enc as enc  # noqa: E402
import mb_lms as lms  # noqa: E402

MAGIC = 0x474D494D
HDR_VERSION = 2
HDR_SIZE = 256
SIGNED_BYTES = 188
PAYLOAD_OFF = 4096
LOAD_CHAIN, LOAD_RAM = 1, 2
ARCH_ANY, ARCH_ARM, ARCH_RISCV = 0, 1, 2
ARCH_NAMES = {ARCH_ANY: "any", ARCH_ARM: "arm", ARCH_RISCV: "riscv"}
F_GOLDEN, F_SIGNED, F_ECDSA, F_STAGE1, F_ENCRYPTED, F_LMS = 0x1, 0x2, 0x4, 0x8, 0x10, 0x20
TLV_LMS = 0x4C              # header-sector TLV: an LMS signature (enc.TLV_X25519 = 0x33: a key envelope)
TLV_AREA = 4096 - 256
TARGET = "rp2350"
RECORD_ADDR = 0             # set by read_input(): the image's mb_boot_record buffer
HANDOFF_SIZE = 0            # set by read_input(): the size of its mb_handoff buffer (160: v1, 320: v2)
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
HDR_FMT = "<IHHIIII32sIIIIII32s16sB3sIIIH42s64s"
HDR_FIELDS = ["magic", "hdr_version", "hdr_size", "flags", "load_type", "payload_offset", "payload_size", "sha256",
              "version", "security_version", "build_time", "load_addr", "entry", "trial_timeout_ms", "name", "target",
              "arch", "pad", "handoff_addr", "key_id", "record_addr", "handoff_size", "reserved", "signature"]
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

SYM_SIZES = {}


def read_elf(data):
    """Flat image of the PT_LOAD segments (by physical address), e_machine, symbols."""
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        die("only 32-bit little-endian ELF files")
    e_machine = struct.unpack_from("<H", data, 18)[0]
    e_phoff, e_shoff = struct.unpack_from("<II", data, 28)
    e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHHHH", data, 42)
    # file ranges of the sections that hold loadable bytes (SHF_ALLOC, not NOBITS)
    secs = []
    for i in range(e_shnum if e_shoff else 0):
        sh = struct.unpack_from("<IIIIIIIIII", data, e_shoff + i * e_shentsize)
        if sh[1] != 8 and sh[2] & 2 and sh[5]:
            secs.append((sh[4], sh[4] + sh[5]))
    segs = []
    for i in range(e_phnum):
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _, _ = struct.unpack_from("<IIIIIIII", data, e_phoff + i * e_phentsize)
        if p_type == 1 and p_filesz:
            # A segment may start before its first section: when the link address isn't
            # page aligned, the linker maps the ELF and program headers in front of it.
            # Keep only what the sections cover, like objcopy -O binary does.
            inside = [(lo, hi) for lo, hi in secs if p_offset <= lo < p_offset + p_filesz]
            lo = min((s for s, _ in inside), default=p_offset)
            hi = max((min(e, p_offset + p_filesz) for _, e in inside), default=p_offset + p_filesz)
            if hi > lo:
                segs.append((p_paddr + lo - p_offset, data[lo:hi]))
    if not segs:
        die("no loadable segments in the ELF")
    base = min(a for a, _ in segs)
    end = max(a + len(d) for a, d in segs)
    if end - base > 16 << 20:
        die("ELF segments span %d bytes - not one image" % (end - base))
    img = bytearray(b"\xff" * (end - base))
    for a, d in segs:
        img[a - base:a - base + len(d)] = d
    # symbols, for mb_handoff (address, and in SYM_SIZES its size)
    syms = {}
    SYM_SIZES.clear()
    for i in range(e_shnum):
        sh = struct.unpack_from("<IIIIIIIIII", data, e_shoff + i * e_shentsize)
        if sh[1] != 2:                                      # SHT_SYMTAB
            continue
        strtab = struct.unpack_from("<IIIIIIIIII", data, e_shoff + sh[6] * e_shentsize)
        for k in range(sh[5] // 16):
            st_name, st_value, st_size = struct.unpack_from("<III", data, sh[4] + k * 16)
            nm = data[strtab[4] + st_name:data.index(b"\0", strtab[4] + st_name)].decode(errors="replace")
            syms[nm] = st_value
            SYM_SIZES[nm] = st_size
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
    global RECORD_ADDR, HANDOFF_SIZE
    RECORD_ADDR = syms.get("mb_boot_record", 0)            # a MB_BOOT_RECORD_BUFFER, if the image has one
    # how big its handoff buffer is: MimiBoot writes no more than that (an older image: 160)
    HANDOFF_SIZE = SYM_SIZES.get("mb_handoff", 0) if "mb_handoff" in syms else 0
    if HANDOFF_SIZE and HANDOFF_SIZE < 160:
        die("mb_handoff is %d bytes: a handoff buffer holds at least 160 (MB_HANDOFF_BUFFER)" % HANDOFF_SIZE)
    return payload, base, arch, syms.get("mb_handoff", 0), syms.get("__vectors", base)


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

def build_header(payload, name, version, secver=0, golden=False, trial_ms=0, target=TARGET, arch=ARCH_ARM,
                 load_type=LOAD_CHAIN, load_addr=0, handoff_addr=0, secret=None, build_time=None, entry=None,
                 stage1=False, encrypted=False, record_addr=0, handoff_size=None):
    """stage1: a two-stage build's stage 1 (entry = the flash offset of its vector table).
    encrypted: the file will carry the payload encrypted (the header still describes the plaintext)"""
    flags = (F_GOLDEN if golden else 0) | (F_STAGE1 if stage1 else 0) | (F_ENCRYPTED if encrypted else 0)
    key_id = 0
    if secret is not None and not isinstance(secret, Secret):
        secret = Secret("ed25519", secret)
    if secret:
        flags |= secret.flags
        key_id = secret.key_id
    fields = [MAGIC, HDR_VERSION, HDR_SIZE, flags, load_type, PAYLOAD_OFF, len(payload), hashlib.sha256(payload).digest(),
              version, secver, int(time.time() if build_time is None else build_time), load_addr, load_addr if entry is None else entry, trial_ms,
              name.encode()[:31].ljust(32, b"\0"), target.encode()[:15].ljust(16, b"\0"), arch, b"\0" * 3,
              handoff_addr, key_id, record_addr,
              min(HANDOFF_SIZE if handoff_size is None else handoff_size, 0xFFFF) if handoff_addr else 0, b"\0" * 42, b"\0" * 64]
    body = struct.pack(HDR_FMT, *fields)
    if secret:
        body = body[:SIGNED_BYTES] + secret.sign(body[:SIGNED_BYTES])
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def resign(hdr, secret):
    """a new header signed by secret (an LMS signature is left in secret.pending_tlv)"""
    body = bytearray(hdr[:HDR_SIZE - 4])
    flags = (struct.unpack_from("<I", body, 8)[0] & ~(F_ECDSA | F_LMS)) | secret.flags
    struct.pack_into("<I", body, 8, flags)
    struct.pack_into("<I", body, 136, secret.key_id)
    body[SIGNED_BYTES:] = secret.sign(bytes(body[:SIGNED_BYTES]))
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
    h["envelope"] = h["lms_sig"] = None
    try:
        tl = tlvs_of(img)
        if h["flags"] & F_ENCRYPTED:
            h["envelope"] = envelope_of(img)
        if h["flags"] & F_LMS:
            h["lms_sig"] = lms_sig_of(img)
        elif TLV_LMS in tl:
            problems.append("an LMS signature in the header sector, but the header doesn't say LMS")
    except ValueError as e:
        problems.append(str(e))
    if len(payload) != h["payload_size"]:
        problems.append("file shorter than the payload")
    elif not h["flags"] & F_ENCRYPTED and hashlib.sha256(payload).digest() != h["sha256"]:
        problems.append("payload SHA-256 mismatch")      # (encrypted: only the board can check it)
    return img, h, payload, problems


def tlv(t, data):
    return struct.pack("<BBH", t, 0, len(data)) + data


def tlvs_of(img):
    """The header sector's TLV list (offset 256..): {type: whole TLV}. Only a key envelope and an
    LMS signature may be there, each once, then 0xFF to the end of the sector (as the board checks)."""
    out, at = {}, HDR_SIZE
    while at < PAYLOAD_OFF and img[at] != 0xFF:
        if PAYLOAD_OFF - at < 4:
            raise ValueError("header sector: a TLV cut short")
        t, z, n = struct.unpack_from("<BBH", img, at)
        if z or at + 4 + n > PAYLOAD_OFF:
            raise ValueError("header sector: a malformed TLV at +%d" % at)
        if t not in (enc.TLV_X25519, TLV_LMS) or t in out:
            raise ValueError("header sector: TLV type 0x%02x %s" % (t, "twice" if t in out else "unknown"))
        out[t] = img[at:at + 4 + n]
        at += 4 + n
    if img[at:PAYLOAD_OFF].strip(b"\xff"):
        raise ValueError("header sector not blank after its TLVs")
    return out


def header_sector(hdr, tlvs=b""):
    if len(tlvs) > TLV_AREA:
        die("the header sector has room for %d bytes of TLVs, these are %d" % (TLV_AREA, len(tlvs)))
    return hdr + tlvs + b"\xff" * (TLV_AREA - len(tlvs))


def envelope_of(img):
    """An encrypted image's key envelope (TLV 0x33, head included)"""
    e = tlvs_of(img).get(enc.TLV_X25519)
    if not e or len(e) - 4 not in (80, 96):
        raise ValueError("encrypted, but no key envelope after the header")
    return e


def lms_sig_of(img):
    """An LMS-signed image's signature (without the TLV head)"""
    t = tlvs_of(img).get(TLV_LMS)
    if not t:
        raise ValueError("LMS-signed, but no LMS signature in the header sector")
    return t[4:]


def not_encrypted(h, what):
    if h["flags"] & F_ENCRYPTED:
        die("%s writes the file into flash as it is, and an encrypted image has to be decrypted on the way: "
            "use `mbtool install` (MimiBoot's console) or SMP" % what)


class Secret:
    """A signing key: Ed25519 (file: 64 hex digits), ECDSA P-256 (file: "p256:" + 64 hex digits)
    or LMS (a JSON key file from keygen --type lms; raw = mb_lms.PrivateKey, stateful)."""

    def __init__(self, kind, raw):
        self.kind, self.raw = kind, raw
        self.ecdsa = kind == "p256"
        self.lms = kind == "lms"
        self.pending_tlv = b""
        if self.lms:
            self.public = raw.public
            self.key_id = lms.key_id(self.public)                  # the first 4 bytes of I
        else:
            self.public = p256.public_key(raw) if self.ecdsa else ed25519.public_key(raw)
            self.key_id = struct.unpack("<I", self.public[:4])[0]  # the first 4 bytes of the public key

    @property
    def flags(self):
        return F_SIGNED | (F_ECDSA if self.ecdsa else 0) | (F_LMS if self.lms else 0)

    def describe(self):
        if self.lms:
            return "LMS key %08x (%s, %d signatures left)" % (self.key_id, lms.describe(self.public), self.raw.remaining)
        return "%s key %s" % (self.kind, self.public[:4].hex())

    def sign(self, msg):
        """the header's 64-byte signature field; an LMS signature goes to pending_tlv (the field: zeros)"""
        if self.lms:
            try:
                self.pending_tlv = tlv(TLV_LMS, self.raw.sign(msg))
            except ValueError as e:                 # used up, or a damaged key file
                die(str(e))
            return b"\0" * 64
        return p256.sign(self.raw, msg) if self.ecdsa else ed25519.sign(self.raw, msg)


def read_secret(path):
    if lms.is_private_key_file(path):
        try:
            return Secret("lms", lms.PrivateKey(path))
        except (ValueError, KeyError) as e:
            die("%s: %s" % (path, e))
    s = open(path).read().strip()
    if s.startswith("p256:"):
        raw = bytes.fromhex(s[5:])
        if len(raw) != 32:
            die("%s: a P-256 secret is 32 bytes" % path)
        return Secret("p256", raw)
    return Secret("ed25519", read_key(path))


def read_public(path):
    """-> (kind, key): hex Ed25519 (32 bytes), P-256 (64, X || Y) or LMS (56/48, or one-level HSS);
    a binary LMS / HSS public key file (as hash-sigs or pyhsslms write) works too"""
    raw = open(path, "rb").read()
    try:
        k = bytes.fromhex(raw.decode().split()[0])
    except (ValueError, IndexError, UnicodeDecodeError):
        k = raw
    if len(k) == 32:
        return "ed25519", k
    if len(k) == 64:
        return "p256", k
    try:
        return "lms", lms.parse_public(k)
    except ValueError:
        die("%s: a public key is Ed25519 (32 bytes), P-256 (64) or LMS (56)" % path)


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
        # Slots start on an erase sector (as small as 256 bytes on SAM D21, 1 KB on many
        # STM32s), so a slot address needn't be 4 KB aligned. The bootloader checks the
        # chip's own vector table alignment when it boots the image.
        if base % 256:
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
    secret = read_secret(a.key) if a.key else None
    name = a.name or os.path.splitext(os.path.basename(a.input))[0]
    entry = vectors if a.target == "rp2040" else None
    stage1 = getattr(a, "stage1", False)
    if stage1:
        # a two-stage build's stage 1: the header says which flash offset it is linked for
        lo = next((lo for lo, size in MCU_FLASH if lo <= base < lo + size), None)
        if a.target.startswith("rp2") or lo is None or load_type != LOAD_CHAIN:
            die("--stage1 is for a Cortex-M MCU's flash-linked stage 1")
        entry = base - lo
    encrypt = getattr(a, "encrypt", None)
    hdr = build_header(payload, name, parse_version(a.version), a.secver, a.golden, a.trial_ms, a.target, arch,
                       load_type, load_addr, handoff, secret, entry=entry, stage1=stage1, encrypted=bool(encrypt),
                       record_addr=RECORD_ADDR)
    plain_sha = hashlib.sha256(payload).hexdigest()
    env = b""
    if encrypt:
        if stage1:
            die("--encrypt: a stage 1 is installed by stage 0, which has no decryption key")
        key = os.urandom(getattr(a, "encrypt_keylen", 128) // 8)
        env = enc.wrap(enc.load_key(encrypt), key)
        payload = enc.aes_ctr(key, payload)
    img = header_sector(hdr, (secret.pending_tlv if secret else b"") + env) + payload
    out = a.output or os.path.splitext(a.input)[0] + ".mimg"
    open(out, "wb").write(img)
    print("%s: %s v%s, %s %s%s, %d bytes, sha256 %s%s%s%s" % (
        out, name, a.version, ARCH_NAMES[arch], "xip" if load_type == LOAD_CHAIN else "ram@0x%08x" % load_addr,
        " (golden)" if a.golden else "", len(payload), plain_sha[:16],
        ", handoff @0x%08x" % handoff if handoff else "", ", signed" if secret else "",
        ", encrypted (AES-%d)" % ((len(env) - 68) * 8) if encrypt else ""))
    if secret and secret.lms:
        print("signed with " + secret.describe())


def cmd_info(a):
    img, h, payload, problems = image_file(a.image)
    print("name      %s%s" % (h["name"], "   (golden)" if h["flags"] & F_GOLDEN else
                                 "   (bootloader stage 1, for flash offset 0x%x)" % h["entry"] if h["flags"] & F_STAGE1 else ""))
    print("version   %s   security %d" % (fmt_version(h["version"]), h["security_version"]))
    print("target    %s/%s   load %s" % (h["target"], ARCH_NAMES.get(h["arch"], "?"),
                                         "xip" if h["load_type"] == LOAD_CHAIN else "ram @0x%08x" % h["load_addr"]))
    print("payload   %d bytes at +0x%x" % (h["payload_size"], h["payload_offset"]))
    print("sha256    %s" % h["sha256"].hex())
    if h["handoff_addr"]:
        print("handoff   @0x%08x, %s" % (h["handoff_addr"], "%d bytes (v2: OS hooks, mailbox)" % h["handoff_size"]
                                          if h["handoff_size"] >= 320 else "v1 (160 bytes: no mailbox)"))
    if h["record_addr"]:
        print("record    @0x%08x (boot record: what MimiBoot checked and measured)" % h["record_addr"])
    print("built     %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["build_time"])))
    if h["flags"] & F_SIGNED:
        line = "signed    key %08x" % h["key_id"]
        is_lms = bool(h["flags"] & F_LMS)
        sig = h["lms_sig"]
        if is_lms:
            line += " (LMS%s)" % (", %d-byte signature, leaf %d" % (len(sig), struct.unpack(">I", sig[:4])[0]) if sig else "")
        else:
            line += " (%s)" % ("ECDSA P-256" if h["flags"] & F_ECDSA else "Ed25519")
        if a.pub:
            kind, pub = read_public(a.pub)
            want = "lms" if is_lms else "p256" if h["flags"] & F_ECDSA else "ed25519"
            if kind != want:
                ok = False
            elif kind == "lms":
                ok = bool(sig) and lms.key_id(pub) == h["key_id"] and lms.verify(pub, img[:SIGNED_BYTES], sig)
            elif kind == "p256":
                ok = p256.verify(pub, img[:SIGNED_BYTES], h["signature"])
            else:
                ok = ed25519.verify(pub, img[:SIGNED_BYTES], h["signature"])
            line += ": signature %s" % ("OK" if ok else "BAD")
            if not ok:
                problems.append("bad signature")
        print(line)
    else:
        print("signed    no")
    if h["envelope"]:
        line ="encrypted AES-%d (ECIES-X25519 envelope, MCUboot TLV 0x33)" % ((len(h["envelope"]) - 68) * 8)
        dec = getattr(a, "enc_key", None)
        if dec:
            try:
                plain = enc.aes_ctr(enc.unwrap(enc.load_key(dec), h["envelope"]), payload)
                ok = hashlib.sha256(plain).digest() == h["sha256"]
                line += ": decrypts %s" % ("OK" if ok else "to the WRONG payload")
                if not ok:
                    problems.append("decrypted payload SHA-256 mismatch")
            except ValueError as e:
                line += ": " + str(e)
                problems.append(str(e))
        print(line)
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
    secret = read_secret(a.key)
    hdr = resign(img[:HDR_SIZE], secret)
    keep = tlvs_of(img).get(enc.TLV_X25519, b"")             # an envelope stays; an old LMS signature goes
    img = header_sector(hdr, secret.pending_tlv + keep) + img[PAYLOAD_OFF:]
    open(a.output or a.image, "wb").write(img)
    print("signed %s with %s" % (a.output or a.image, secret.describe()))


def cmd_keygen(a):
    base = a.out
    if os.path.exists(base + ".key") and not a.force:
        die("%s.key exists (--force to replace it; images signed with it would stop booting)" % base)
    os.makedirs(os.path.dirname(base) or ".", exist_ok=True)
    if a.type == "lms":
        if os.path.exists(base + ".key"):
            os.remove(base + ".key")                               # (--force)
        t0 = time.time()
        leaves = 1 << a.lms_height
        k = lms.generate(base + ".key", a.lms_height, a.lms_w,
                         progress=lambda q, n: print("\r  building the tree: %d/%d leaves" % (q, n), end="", flush=True))
        print("\r  %d one-time keys in %.0f s%s" % (leaves, time.time() - t0, " " * 20))
        pub = k.public
        open(base + ".pub", "w").write(pub.hex() + "\n")
        with open(base + "_keys.h", "w") as f:
            f.write("/* MimiBoot trusted keys: generated by mbtool keygen. Build with -DMB_KEYS_HEADER=... */\n")
            f.write("#define MB_TRUSTED_LMS_KEY_COUNT 1\n#define MB_TRUSTED_LMS_KEYS { { %s } }\n"
                    % ", ".join("0x%02x" % b for b in pub))
        gi = os.path.join(os.path.dirname(base) or ".", ".gitignore")
        lines = open(gi).read().split() if os.path.exists(gi) else []
        for pat in ("*.key", "*.key.tree"):
            if pat not in lines:
                open(gi, "a").write(pat + "\n")
        print("secret %s.key  STATEFUL: it counts the signatures it has made. Never copy it, restore it from a\n"
              "                 backup or sign from two machines with it: each of those reuses one-time keys.\n"
              "public %s.pub  key id %08x, %s, %d signatures, %d-byte signature\n"
              "build  %s_keys.h (or put the .pub line in MuConfigurator's KEYS file; turn on LMS)"
              % (base, base, k.key_id, lms.describe(pub), leaves, lms.sig_len(k.lt, k.ot), base))
        return
    if a.type == "x25519":
        secret = os.urandom(32)
        open(base + ".key", "w").write(secret.hex() + "\n")
        open(base + ".pub", "w").write(enc.public_key(secret).hex() + "\n")
        gi = os.path.join(os.path.dirname(base) or ".", ".gitignore")
        lines = open(gi).read().split() if os.path.exists(gi) else []
        if "*.key" not in lines:
            open(gi, "a").write("*.key\n")
        print("device %s.key: the bootloader's decryption key (MuConfigurator ENC_KEY; keep it private)\n"
              "public %s.pub: encrypt with `mbtool pack --encrypt %s.pub`" % (base, base, base))
        return
    if a.type == "p256":
        secret = p256.generate()
        pub = p256.public_key(secret)
        open(base + ".key", "w").write("p256:" + secret.hex() + "\n")
    else:
        secret = os.urandom(32)
        pub = ed25519.public_key(secret)
        open(base + ".key", "w").write(secret.hex() + "\n")
    open(base + ".pub", "w").write(pub.hex() + "\n")
    with open(base + "_keys.h", "w") as f:
        f.write("/* MimiBoot trusted keys: generated by mbtool keygen. Build with -DMB_KEYS_HEADER=... */\n")
        tag = "P256_" if a.type == "p256" else ""
        f.write("#define MB_TRUSTED_%sKEY_COUNT 1\n#define MB_TRUSTED_%sKEYS { { %s } }\n"
                % (tag, tag, ", ".join("0x%02x" % b for b in pub)))
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
    not_encrypted(h, "uf2")
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
    not_encrypted(h, "flash")
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


UNLOCK_KEY = os.environ.get("MB_UNLOCK_KEY")       # set by --unlock-key
UNLOCK_DOMAIN = b"MimiBoot console unlock v1\0"


def unlock_message(target: bytes, nonce: bytes) -> bytes:
    """what the device's 'unlock' checks the signature against (core/mb_console.c)"""
    return UNLOCK_DOMAIN + target[:16].ljust(16, b"\0") + nonce


REVOKE_DOMAIN = b"MimiBoot revoke v1\0"


def revoke_signature(secret: bytes, target: bytes, key_id: int) -> bytes:
    """what a board with REVOKE_KEYS checks before it stops trusting key_id (core/mb_image.c)"""
    return ed25519.sign(secret, REVOKE_DOMAIN + target[:16].ljust(16, b"\0") + struct.pack("<I", key_id))


CONFIG_DOMAIN = b"MimiBoot config v1\0"


def config_signature(secret: bytes, target: bytes, version: int, text: bytes) -> bytes:
    """what a CFG_SIGNED board checks (core/mb_config.c cfg_sig_ok)"""
    msg = CONFIG_DOMAIN + target[:16].ljust(16, b"\0") + struct.pack("<II", version, len(text)) \
        + hashlib.sha256(text).digest()
    return ed25519.sign(secret, msg)


def unlock(s, key_path):
    """Answer the console's unlock challenge with an Ed25519 key (CONSOLE_AUTH builds)."""
    s.write(b"unlock\r")
    out, m = read_until(s, r"MB CHALLENGE (\S+) ([0-9a-f]{64})\r?\n|MB ERR[^\r\n]*|MB UNLOCKED|unknown command", 5)
    if not m:
        die("no unlock challenge; output was:\n" + ANSI.sub("", out)[-300:])
    if m.group(0).startswith("unknown command"):
        return                                          # this build has no console lock
    if m.group(0).startswith("MB UNLOCKED"):
        read_until(s, PROMPT, 3)
        return
    if m.group(0).startswith("MB ERR"):
        die("unlock: " + m.group(0))
    sig = ed25519.sign(read_key(key_path), unlock_message(m.group(1).encode(), bytes.fromhex(m.group(2))))
    s.write(sig.hex().encode() + b"\r")
    out, m = read_until(s, r"MB UNLOCKED|MB ERR[^\r\n]*", 15)
    if not m or not m.group(0).startswith("MB UNLOCKED"):
        die("unlock refused: " + (m.group(0) if m else ANSI.sub("", out)[-200:]))
    read_until(s, PROMPT, 3)


def to_shell(s):
    """Menu or shell -> shell prompt. Never Enter first: in the menu it boots the selection.
    With an unlock key (--unlock-key / MB_UNLOCK_KEY) the console is unlocked too."""
    s.write(b"c")
    out, m = read_until(s, PROMPT, 3)
    if not m:
        s.write(b"\r")
        out, m = read_until(s, PROMPT, 3)
    if not m:
        die("no MimiBoot prompt; output was:\n" + out[-500:])
    if UNLOCK_KEY:
        unlock(s, UNLOCK_KEY)


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
    out, m = read_until(s, r"MB (OK|KEY|SIG|ERR[^\r\n]*)\r?\n", 180)    # erasing a big slot takes a while
    if m and m.group(1) == "KEY":                                   # an encrypted image: the envelope next
        env = envelope_of(img)
        s.write(b"K" + struct.pack("<H", len(env)) + env + struct.pack("<I", zlib.crc32(env) & 0xFFFFFFFF))
        out, m = read_until(s, r"MB (OK|SIG|ERR[^\r\n]*)\r?\n", 180)
    if m and m.group(1) == "SIG":                                   # LMS-signed: the signature next
        sig = lms_sig_of(img)
        s.write(b"S" + struct.pack("<H", len(sig)) + sig + struct.pack("<I", zlib.crc32(sig) & 0xFFFFFFFF))
        out, m = read_until(s, r"MB (OK|ERR[^\r\n]*)\r?\n", 180)
    if not m or m.group(1) != "OK":
        why = m.group(0).strip() if m else out[-200:]
        hint = {"-3": "the header doesn't suit this slot: the image is bigger than the slot, or it's linked "
                      "for another address (layout.txt says where and how big)",
                "-5": "built for another chip (--target), or this build lacks what the image needs",
                "-6": "timed out", "-7": "the board won't put it there (the stage 1 it is running from)",
                "-8": "unsigned, or not signed by a key this board trusts"}
        code = re.search(r"\((-\d+)\)", why)
        die("header rejected: " + why + ("; " + hint[code.group(1)] if code and code.group(1) in hint else ""))
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


def loader_upload(s, build_dir):
    """Two-stage boards: put the build's stage 1 into the copy that isn't running.
    -> (slot written, image path). The board must already be at the prompt."""
    s.write(b"version\r")
    out, m = read_until(s, r"stage 1 from (\S+),", 5)
    if not m:
        die("the board didn't say which stage 1 it runs: not a two-stage build? output:\n" + ANSI.sub("", out)[-400:])
    running = m.group(1)
    read_until(s, PROMPT, 3)
    lay = json.load(open(os.path.join(build_dir, "layout.json")))
    copies = [x["name"] for x in lay["slots"] if x["role"] == "stage 1"]
    if running not in copies or len(copies) != 2:
        die("%s/layout.json doesn't match the board (stage-1 copies %s, running %s)" % (build_dir, copies, running))
    other = copies[1 - copies.index(running)]
    path = os.path.join(build_dir, "stage1-%s.img" % other)
    img, h, payload = checked_image(path)
    if not h["flags"] & F_STAGE1:
        die("%s is not a stage-1 image" % path)
    s.write(("recv %s\r" % other).encode())
    send_image(s, img, payload)
    return other, path


def cmd_loader(a):
    s = open_serial(a.port)
    to_shell(s)
    other, path = loader_upload(s, a.build_dir)
    print("stage 1 from %s installed in %s; on the next boot stage 0 tries it (and goes back to the old "
          "copy if it doesn't get as far as starting an app within %d boots)" % (path, other, 3))
    if a.reboot:
        s.write(b"reboot\r")


def revoke_on(s, secret, target, key_id):
    """At the prompt: 'revoke <id>', then the statement. -> the board's answer line"""
    s.write(("revoke %08x\r" % key_id).encode())
    out, m = read_until(s, r"MB REVOKE [0-9a-f]{8} statement\?|MB ERR[^\r\n]*\r?\n", 5)
    if not m or m.group(0).startswith("MB ERR"):
        die("the board won't take a revocation: " + ANSI.sub("", out)[-300:])
    s.write(revoke_signature(secret, target, key_id).hex().encode() + b"\r")
    out, m = read_until(s, r"MB (REVOKED|ERR[^\r\n]*)\r?\n", 10)    # the whole line, not what came so far
    return m.group(0).rstrip() if m else "no answer: " + ANSI.sub("", out)[-200:]


def cmd_revoke(a):
    """stop a board trusting one signing key (statement signed with a REVOKE_KEYS key)"""
    key_id = int(a.keyid, 16)
    secret = read_key(a.key)
    if a.print:
        print(revoke_signature(secret, a.target.encode(), key_id).hex())
        return
    s = open_serial(a.port)
    to_shell(s)
    res = revoke_on(s, secret, a.target.encode(), key_id)
    print(res)
    if not res.startswith("MB REVOKED"):
        sys.exit(1)


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
    out, _ = read_until(s, r"fox(?:\x1b\[[0-9;]*m)*@|MimiBoot(?:-\w+)? \d|MB FLASH READY", 1.5)
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
    out, m = read_until(s, r"MB CFG READY \d+(?: (\S+) (signed|plain))?", 5)
    if not m:
        die("no CFG READY: " + out[-200:])
    blob = struct.pack("<H", len(text)) + text + struct.pack("<I", zlib.crc32(text) & 0xFFFFFFFF)
    if m.group(2) == "signed":
        if not a.key:
            s.write(b"X")
            die("this board only takes signed configs: cfg push <file> --key <secret key>")
        version = a.cfg_version if a.cfg_version is not None else int(time.time())
        blob += struct.pack("<I", version) + config_signature(read_key(a.key), m.group(1).encode(), version, text)
        print("signed config version %d" % version)
    s.write(blob)
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


def cmd_provision(a):
    from pathlib import Path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mu.provision import ProvisionError, steps
    try:
        print("\n".join(steps(Path(a.build_dir))))
    except ProvisionError as e:
        die(str(e))
    print("\nNothing was changed: these are the steps to run yourself.")


def main():
    ap = argparse.ArgumentParser(description="MimiBoot host tool", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--layout", default="4m", choices=LAYOUTS)
    ap.add_argument("--unlock-key", help="secret key that answers the console's unlock challenge "
                                         "(CONSOLE_AUTH builds; or set MB_UNLOCK_KEY)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pack"); p.add_argument("input"); p.add_argument("-o", "--output")
    p.add_argument("--name"); p.add_argument("--version", default="0.0.1"); p.add_argument("--secver", type=int, default=0)
    p.add_argument("--golden", action="store_true"); p.add_argument("--trial-ms", type=int, default=0)
    p.add_argument("--key", help="sign with this secret key file"); p.add_argument("--arch", choices=["arm", "riscv"],
                                                                                    help="refuse to pack anything else")
    p.add_argument("--load-addr", help=".bin only: where it runs (default flash)")
    p.add_argument("--stage1", action="store_true", help="a two-stage build's stage 1 (MuConfigurator builds these itself)")
    p.add_argument("--encrypt", metavar="PUB", help="encrypt the payload for the board whose key is PUB (mbtool keygen --type x25519)")
    p.add_argument("--encrypt-keylen", type=int, choices=[128, 256], default=128, help="AES key size (default 128)")
    p.add_argument("--target", default=TARGET, help="target as the bootloader names it: rp2040, rp2350, or the chip from MuConfigurator (e.g. stm32f411ce); RP2040 requires a RAM-linked payload"); p.set_defaults(fn=cmd_pack)
    p = sub.add_parser("info"); p.add_argument("image"); p.add_argument("--pub")
    p.add_argument("--enc-key", help="an encrypted image: decrypt with this device key and check the payload")
    p.set_defaults(fn=cmd_info)
    p = sub.add_parser("sign"); p.add_argument("image"); p.add_argument("--key", required=True); p.add_argument("-o", "--output")
    p.set_defaults(fn=cmd_sign)
    p = sub.add_parser("keygen"); p.add_argument("--out", default="keys/mimiboot"); p.add_argument("--force", action="store_true")
    p.add_argument("--type", choices=["ed25519", "p256", "lms", "x25519"], default="ed25519",
                   help="ed25519 (default), p256 (ECDSA P-256: boards built with ECDSA) or lms (hash-based, "
                        "post-quantum; boards built with LMS) signing keys; "
                        "x25519: a board's decryption key (ENC_KEY) for encrypted images")
    p.add_argument("--lms-height", type=int, choices=[5, 10, 15, 20], default=10,
                   help="LMS: 2^H signatures per key (default 10: 1024; each step up takes 32x longer to make)")
    p.add_argument("--lms-w", type=int, choices=[4, 8], default=4,
                   help="LMS Winternitz width: 4 (default; faster checks, 2.5 KB signatures) or 8 (1.4 KB, ~8x slower checks)")
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
    p.add_argument("--port"); p.add_argument("--key", help="sign the config (boards built with CFG_SIGNED)")
    p.add_argument("--cfg-version", type=int, help="signed config version (default: the current Unix time)")
    p.set_defaults(fn=cmd_cfg)
    p = sub.add_parser("cmd"); p.add_argument("commands", nargs="+"); p.add_argument("--port"); p.add_argument("--timeout", type=float, default=10)
    p.set_defaults(fn=cmd_cmd)
    p = sub.add_parser("layout"); p.set_defaults(fn=cmd_layout)
    p = sub.add_parser("revoke", help="stop a board trusting one signing key (needs a REVOKE_KEYS key)")
    p.add_argument("--key", required=True, help="the revocation key's secret file (mbtool keygen)")
    p.add_argument("--keyid", required=True, help="the key to revoke: 8 hex digits (the board's 'keys' lists them)")
    p.add_argument("--target", required=True, help="the chip as the board names it (e.g. nrf52840)")
    p.add_argument("--print", action="store_true", help="only print the statement (to send later, or by hand)")
    p.add_argument("--port"); p.set_defaults(fn=cmd_revoke)
    p = sub.add_parser("loader", help="two-stage boards: update the bootloader (stage 1) from a MuConfigurator build")
    p.add_argument("build_dir", help="the build directory (stage1-s1a.img, stage1-s1b.img, layout.json)")
    p.add_argument("--port"); p.add_argument("--reboot", action="store_true", help="reboot into it straight away")
    p.set_defaults(fn=cmd_loader)
    p = sub.add_parser("provision", help="print the steps to lock a board for production (runs nothing)")
    p.add_argument("build_dir", help="a MuConfigurator build directory (has build-info.json)"); p.set_defaults(fn=cmd_provision)
    a = ap.parse_args()
    if a.unlock_key:
        global UNLOCK_KEY
        UNLOCK_KEY = a.unlock_key
    if a.cmd == "cfg" and a.action == "push" and not a.file:
        die("cfg push <file>")
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
