"""
Encrypted images on the PC side, without third-party packages: X25519 (RFC 7748),
AES-CTR (FIPS-197 / SP 800-38A), and MCUboot's ECIES-X25519 key envelope
(TLV 0x33: ephemeral public key || HMAC-SHA256 tag || wrapped key, keys from
HKDF-SHA256 with no salt and info "MCUBoot_ECIES_v1").

Plain Python, so slow (a few seconds for a large image) but small enough to
read. Nothing here runs on the device; core/mb_enc.c is the device side.
"""
import hashlib
import hmac
import os
import struct

TLV_X25519 = 0x33
INFO = b"MCUBoot_ECIES_v1"

# ---------------------------------------------------------------------------
# X25519
# ---------------------------------------------------------------------------
P = 2 ** 255 - 19
A24 = 121665


def _clamp(k: bytes) -> int:
    b = bytearray(k)
    b[0] &= 248
    b[31] = (b[31] & 127) | 64
    return int.from_bytes(b, "little")


def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 section 5 (a straight ladder; host-side, so timing doesn't matter)"""
    if len(k) != 32 or len(u) != 32:
        raise ValueError("X25519 keys are 32 bytes")
    s = _clamp(k)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (s >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def public_key(priv: bytes) -> bytes:
    return x25519(priv, (9).to_bytes(32, "little"))


# ---------------------------------------------------------------------------
# AES (encryption only: CTR mode needs nothing else)
# ---------------------------------------------------------------------------
def _xt(a):
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a, b = _xt(a), b >> 1
    return r


def _make_sbox():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    box = []
    for a in range(256):
        x = inv[a]
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        box.append(s ^ 0x63)
    return bytes(box)


SBOX = _make_sbox()


def _expand(key: bytes):
    nk = len(key) // 4
    if nk not in (4, 8):
        raise ValueError("AES-128 or AES-256 keys only")
    rounds = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xt(rcon) & 0xFF
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return rounds, [sum(w[4 * r:4 * r + 4], []) for r in range(rounds + 1)]


def _encrypt_block(ks, block: bytes) -> bytes:
    rounds, rk = ks
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, rounds + 1):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]          # shift rows (column-major state)
        if r != rounds:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                m += [_gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3],
                      a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3],
                      a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3),
                      _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)]
            s = m
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


def aes_block(key: bytes, block: bytes) -> bytes:
    return _encrypt_block(_expand(key), block)


def aes_ctr(key: bytes, data: bytes, nonce: bytes = bytes(16)) -> bytes:
    """CTR with a 128-bit big-endian counter starting at `nonce` (encrypt = decrypt)"""
    ks = _expand(key)
    c = int.from_bytes(nonce, "big")
    out = bytearray()
    for i in range(0, len(data), 16):
        stream = _encrypt_block(ks, ((c + i // 16) % (1 << 128)).to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], stream))
    return bytes(out)


# ---------------------------------------------------------------------------
# HKDF and the envelope
# ---------------------------------------------------------------------------
def hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes = b"") -> bytes:
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, t, n = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([n]), hashlib.sha256).digest()
        out += t
        n += 1
    return out[:length]


def wrap(device_pub: bytes, image_key: bytes, ephemeral: bytes = None) -> bytes:
    """The TLV (head included) carrying image_key to the device with device_pub"""
    if len(image_key) not in (16, 32):
        raise ValueError("image keys are 16 or 32 bytes")
    eph = ephemeral or os.urandom(32)
    shared = x25519(eph, device_pub)
    if shared == bytes(32):
        raise ValueError("not a usable X25519 public key")
    derived = hkdf_sha256(shared, INFO, len(image_key) + 32)
    ckey = aes_ctr(derived[:len(image_key)], image_key)
    tag = hmac.new(derived[len(image_key):], ckey, hashlib.sha256).digest()
    body = public_key(eph) + tag + ckey
    return struct.pack("<BBH", TLV_X25519, 0, len(body)) + body


def unwrap(device_priv: bytes, env: bytes) -> bytes:
    """image key from a TLV (tests and `mbtool` checks)"""
    t, z, n = struct.unpack_from("<BBH", env)
    if t != TLV_X25519 or z or n != len(env) - 4 or n not in (80, 96):
        raise ValueError("not an X25519 key envelope")
    klen = n - 64
    epk, tag, ckey = env[4:36], env[36:68], env[68:68 + klen]
    derived = hkdf_sha256(x25519(device_priv, epk), INFO, klen + 32)
    if not hmac.compare_digest(hmac.new(derived[klen:], ckey, hashlib.sha256).digest(), tag):
        raise ValueError("envelope not made for this key")
    return aes_ctr(derived[:klen], ckey)


def load_key(path) -> bytes:
    """A key file: 32 bytes raw, or 64 hex characters (comments with # allowed)"""
    raw = open(path, "rb").read()
    if len(raw) == 32:
        return raw
    text = "".join(line.split("#")[0] for line in raw.decode("ascii").splitlines()).strip()
    key = bytes.fromhex(text)
    if len(key) != 32:
        raise ValueError(f"{path}: an X25519 key is 32 bytes")
    return key
