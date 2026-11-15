"""
LMS hash-based signatures (RFC 8554, NIST SP 800-208) on the PC side: keys,
a stateful signer, a verifier. Single-level LMS only (no HSS tree of trees);
HSS files with one level (L = 1) are read and written for other tools.

LMS keys are stateful: every signature uses up one one-time key (leaf q of
the tree), and signing two different messages with the same q gives the key
away. So:
  - the private key file holds the next q, and is rewritten (and synced to
    disk) *before* a signature leaves this module;
  - never copy a private key file, restore it from a backup, or sign from two
    machines with the same file: each of those reuses leaves;
  - a key signs 2^h messages, then refuses.

The one-time keys come from a secret SEED as in RFC 8554 Appendix A /
SP 800-208 section 6.1 (x_q[i] = H(I || q || i || 0xFF || SEED)), so the key
file is small. The tree's public nodes are cached next to it (.tree); they
are public, and rebuilt if the cache is missing.

Plain Python, standard library only. Nothing here runs on the device;
core/mb_lms.c is the device side.
"""
import hashlib
import json
import os
import struct

# typecodes (RFC 8554 section 5.1/4.1, SP 800-208 section 4)
LMS_TYPES = {}      # code -> (name, m, h)
for _i, _h in enumerate((5, 10, 15, 20, 25)):
    LMS_TYPES[5 + _i] = ("LMS_SHA256_M32_H%d" % _h, 32, _h)
    LMS_TYPES[0x0A + _i] = ("LMS_SHA256_M24_H%d" % _h, 24, _h)
OTS_TYPES = {}      # code -> (name, n, w)
for _i, _w in enumerate((1, 2, 4, 8)):
    OTS_TYPES[1 + _i] = ("LMOTS_SHA256_N32_W%d" % _w, 32, _w)
    OTS_TYPES[5 + _i] = ("LMOTS_SHA256_N24_W%d" % _w, 24, _w)

D_PBLC, D_MESG, D_LEAF, D_INTR = 0x8080, 0x8181, 0x8282, 0x8383
PUB_LEN = {32: 56, 24: 48}      # u32 type || u32 otstype || I[16] || T[1]


def u32(x):
    return struct.pack(">I", x)


def u16(x):
    return struct.pack(">H", x)


def ots_params(n, w):
    """-> (p, ls): number of chains and the checksum shift (RFC 8554 Appendix B)"""
    u = (8 * n + w - 1) // w
    v = ((((1 << w) - 1) * u).bit_length() + w - 1) // w
    return u + v, 16 - v * w


def lms_type_for(h, w, n=32):
    lt = next(k for k, (_, m, hh) in LMS_TYPES.items() if m == n and hh == h)
    ot = next(k for k, (_, nn, ww) in OTS_TYPES.items() if nn == n and ww == w)
    return lt, ot


def sig_len(lms_type, ots_type):
    _, m, h = LMS_TYPES[lms_type]
    _, n, w = OTS_TYPES[ots_type]
    p, _ = ots_params(n, w)
    return 4 + (4 + n + p * n) + 4 + h * m


def _H(n, *parts):
    s = hashlib.sha256()
    for x in parts:
        s.update(x)
    return s.digest()[:n]


def _coef(s, i, w):
    return (s[i * w // 8] >> (8 - (w * (i % (8 // w)) + w))) & ((1 << w) - 1)


def _cksm(s, n, w, ls):
    return sum((1 << w) - 1 - _coef(s, i, w) for i in range(8 * n // w)) << ls


def _digits(Q, n, w, ls):
    v = Q + u16(_cksm(Q, n, w, ls))
    p, _ = ots_params(n, w)
    return [_coef(v, i, w) for i in range(p)]


def _chain(n, pre, i, x, start, stop):
    """x hashed from step start up to (not including) stop; pre = I || u32(q)"""
    for j in range(start, stop):
        s = hashlib.sha256(pre)
        s.update(u16(i))
        s.update(bytes([j]))
        s.update(x)
        x = s.digest()[:n]
    return x


def _ots_pub(ots_type, I, q, seed):
    _, n, w = OTS_TYPES[ots_type]
    p, _ = ots_params(n, w)
    pre = I + u32(q)
    top = (1 << w) - 1
    s = hashlib.sha256(pre + u16(D_PBLC))
    for i in range(p):
        x = _H(n, pre, u16(i), b"\xff", seed)
        s.update(_chain(n, pre, i, x, 0, top))
    return s.digest()[:n]


def _ots_sign(ots_type, I, q, seed, msg, C):
    _, n, w = OTS_TYPES[ots_type]
    _, ls = ots_params(n, w)
    pre = I + u32(q)
    Q = _H(n, pre, u16(D_MESG), C, msg)
    out = [u32(ots_type), C]
    for i, a in enumerate(_digits(Q, n, w, ls)):
        x = _H(n, pre, u16(i), b"\xff", seed)
        out.append(_chain(n, pre, i, x, 0, a))
    return b"".join(out)


def _ots_candidate(ots_sig, I, q, msg, n):
    """Kc from an LM-OTS signature (RFC 8554 Algorithm 4b); None if malformed"""
    if len(ots_sig) < 4:
        return None
    t = struct.unpack(">I", ots_sig[:4])[0]
    if t not in OTS_TYPES or OTS_TYPES[t][1] != n:
        return None
    _, n, w = OTS_TYPES[t]
    p, ls = ots_params(n, w)
    if len(ots_sig) != 4 + n + p * n:
        return None
    C = ots_sig[4:4 + n]
    pre = I + u32(q)
    Q = _H(n, pre, u16(D_MESG), C, msg)
    top = (1 << w) - 1
    s = hashlib.sha256(pre + u16(D_PBLC))
    for i, a in enumerate(_digits(Q, n, w, ls)):
        y = ots_sig[4 + n + i * n:4 + n + (i + 1) * n]
        s.update(_chain(n, pre, i, y, a, top))
    return s.digest()[:n]


def verify(pub, msg, sig):
    """True if sig is a valid LMS signature of msg under the LMS public key pub (RFC 8554 Algorithm 6a)"""
    if len(pub) < 8:
        return False
    lt, ot = struct.unpack(">II", pub[:8])
    if lt not in LMS_TYPES or ot not in OTS_TYPES:
        return False
    _, m, h = LMS_TYPES[lt]
    if OTS_TYPES[ot][1] != m or len(pub) != 24 + m:
        return False
    I, T1 = pub[8:24], pub[24:]
    if len(sig) != sig_len(lt, ot):
        return False
    q = struct.unpack(">I", sig[:4])[0]
    if q >= 1 << h or struct.unpack(">I", sig[4:8])[0] != ot:
        return False
    ots_len = sig_len(lt, ot) - 8 - h * m
    rest = 4 + ots_len
    if struct.unpack(">I", sig[rest:rest + 4])[0] != lt:
        return False
    Kc = _ots_candidate(sig[4:rest], I, q, msg, m)
    if Kc is None:
        return False
    node = (1 << h) + q
    tmp = _H(m, I, u32(node), u16(D_LEAF), Kc)
    path = sig[rest + 4:]
    for i in range(h):
        sib = path[i * m:(i + 1) * m]
        tmp = _H(m, I, u32(node >> 1), u16(D_INTR), sib, tmp) if node & 1 else _H(m, I, u32(node >> 1), u16(D_INTR), tmp, sib)
        node >>= 1
    return tmp == T1


# ---------------------------------------------------------------------------
# public key encodings
# ---------------------------------------------------------------------------

def parse_public(raw):
    """An LMS public key, raw (56/48 bytes) or as a one-level HSS key (u32 L = 1 first). -> raw LMS key"""
    if len(raw) in (60, 52) and raw[:4] == u32(1):
        raw = raw[4:]
    if len(raw) < 8:
        raise ValueError("not an LMS public key")
    lt, ot = struct.unpack(">II", raw[:8])
    if lt not in LMS_TYPES or ot not in OTS_TYPES or len(raw) != 24 + LMS_TYPES[lt][1] \
            or OTS_TYPES[ot][1] != LMS_TYPES[lt][1]:
        raise ValueError("not an LMS public key (types %#x/%#x, %d bytes)" % (lt, ot, len(raw)))
    return raw


def hss_public(pub):
    return u32(1) + pub


def hss_signature(sig):
    """a one-level HSS signature (Nspk = 0) from an LMS signature"""
    return u32(0) + sig


def from_hss_signature(sig):
    if len(sig) < 4 or sig[:4] != u32(0):
        raise ValueError("only one-level HSS signatures (Nspk = 0)")
    return sig[4:]


def key_id(pub):
    """MimiBoot's key id for an LMS key: the first 4 bytes of I, little-endian (the type codes
    at the front are the same for every key)"""
    return struct.unpack("<I", pub[8:12])[0]


def describe(pub):
    lt, ot = struct.unpack(">II", pub[:8])
    return "%s / %s" % (LMS_TYPES[lt][0], OTS_TYPES[ot][0])


# ---------------------------------------------------------------------------
# private keys: generation and stateful signing
# ---------------------------------------------------------------------------

def _tree(lt, ot, I, seed, progress=None):
    """all public tree nodes T[1 .. 2^(h+1)-1], as one bytes object (node r at r*m)"""
    _, m, h = LMS_TYPES[lt]
    leaves = 1 << h
    T = [b""] * (2 * leaves)
    for q in range(leaves):
        T[leaves + q] = _H(m, I, u32(leaves + q), u16(D_LEAF), _ots_pub(ot, I, q, seed))
        if progress and (q + 1) % 64 == 0:
            progress(q + 1, leaves)
    for r in range(leaves - 1, 0, -1):
        T[r] = _H(m, I, u32(r), u16(D_INTR), T[2 * r], T[2 * r + 1])
    T[0] = b"\0" * m
    return b"".join(T)


def public_from_seed(lt, ot, I, seed, progress=None):
    _, m, _ = LMS_TYPES[lt]
    T = _tree(lt, ot, I, seed, progress)
    return u32(lt) + u32(ot) + I + T[m:2 * m], T


def _write_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if hasattr(os, "O_DIRECTORY"):      # make the rename itself durable (POSIX)
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class PrivateKey:
    """A stateful LMS private key file (JSON: types, I, SEED, the next unused leaf)."""

    def __init__(self, path):
        self.path = path
        d = json.load(open(path))
        if d.get("kind") != "mimiboot-lms-private" or d.get("version") != 1:
            raise ValueError("%s: not a MimiBoot LMS private key" % path)
        self.lt, self.ot = d["lms_type"], d["ots_type"]
        self.I, self.seed = bytes.fromhex(d["I"]), bytes.fromhex(d["seed"])
        self.next = d["next"]
        self.public = bytes.fromhex(d["public"])
        _, self.m, self.h = LMS_TYPES[self.lt]
        self._T = None

    @property
    def remaining(self):
        return (1 << self.h) - self.next

    @property
    def key_id(self):
        return key_id(self.public)

    def _nodes(self):
        if self._T is None:
            cache = self.path + ".tree"
            want = 2 * (1 << self.h) * self.m
            T = open(cache, "rb").read() if os.path.exists(cache) else b""
            if len(T) != want or T[self.m:2 * self.m] != self.public[24:]:
                pub, T = public_from_seed(self.lt, self.ot, self.I, self.seed)
                if pub != self.public:
                    raise ValueError("%s: the seed doesn't give the stored public key" % self.path)
                open(cache, "wb").write(T)
            self._T = T
        return self._T

    def _save(self, nxt):
        d = json.load(open(self.path))
        d["next"] = nxt
        _write_atomic(self.path, json.dumps(d, indent=1) + "\n")

    def sign(self, msg):
        """Use up the next leaf and sign msg with it. The key file records the leaf
        as used (synced to disk) before the signature is computed."""
        if self.remaining <= 0:
            raise ValueError("%s: all %d signatures used; make a new key" % (self.path, 1 << self.h))
        T = self._nodes()
        q = self.next
        self._save(q + 1)               # first: a crash after this wastes a leaf, never reuses one
        self.next = q + 1
        sig = sign_leaf(self.lt, self.ot, self.I, self.seed, T, q, msg, os.urandom(self.m))
        if not verify(self.public, msg, sig):
            raise RuntimeError("LMS signature failed its own check")
        return sig


def sign_leaf(lt, ot, I, seed, T, q, msg, C):
    """The LMS signature of msg with leaf q (T: the tree from public_from_seed, C: the randomizer).
    Stateless: the caller makes sure q is never used twice (PrivateKey does)."""
    _, m, h = LMS_TYPES[lt]
    ots = _ots_sign(ot, I, q, seed, msg, C)
    node = (1 << h) + q
    path = []
    for _ in range(h):
        sib = node ^ 1
        path.append(T[sib * m:(sib + 1) * m])
        node >>= 1
    return u32(q) + ots + u32(lt) + b"".join(path)


def generate(path, h=10, w=4, n=32, progress=None):
    """A new key at path (refuses to overwrite). -> PrivateKey"""
    if os.path.exists(path):
        raise FileExistsError(path)
    lt, ot = lms_type_for(h, w, n)
    I, seed = os.urandom(16), os.urandom(n)
    pub, T = public_from_seed(lt, ot, I, seed, progress)
    d = {"kind": "mimiboot-lms-private", "version": 1, "lms_type": lt, "ots_type": ot,
         "params": "%s / %s" % (LMS_TYPES[lt][0], OTS_TYPES[ot][0]),
         "I": I.hex(), "seed": seed.hex(), "next": 0, "public": pub.hex(),
         "warning": "stateful key: never copy, restore or share this file; each signature uses up one leaf"}
    _write_atomic(path, json.dumps(d, indent=1) + "\n")
    open(path + ".tree", "wb").write(T)
    return PrivateKey(path)


def is_private_key_file(path):
    try:
        with open(path) as f:
            return '"mimiboot-lms-private"' in f.read(200)
    except (OSError, UnicodeDecodeError):
        return False
