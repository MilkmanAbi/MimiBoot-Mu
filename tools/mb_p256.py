"""ECDSA over NIST P-256 (secp256r1) with SHA-256, in plain Python.

For signing images on the host: keys are generated with os.urandom, signatures
use deterministic nonces (RFC 6979), so the same key and message always give
the same signature. Signatures are raw r || s (64 bytes, big-endian), public
keys the raw point X || Y (64 bytes): the formats MimiBoot's verifier takes.

Not constant-time: fine on a signing machine you control, not for a device.
"""
import hashlib
import hmac
import os

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def on_curve(pt) -> bool:
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def public_key(secret: bytes) -> bytes:
    d = int.from_bytes(secret, "big")
    if not 1 <= d < N:
        raise ValueError("P-256 secret out of range")
    x, y = _mul(d, G)
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def generate() -> bytes:
    while True:
        d = int.from_bytes(os.urandom(32), "big")
        if 1 <= d < N:
            return d.to_bytes(32, "big")


def _rfc6979_k(d: int, h1: bytes):
    """deterministic nonces (RFC 6979 section 3.2), HMAC-SHA-256"""
    x = d.to_bytes(32, "big")
    h = (int.from_bytes(h1, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            yield t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(secret: bytes, digest: bytes) -> bytes:
    d = int.from_bytes(secret, "big")
    e = int.from_bytes(digest, "big")
    for k in _rfc6979_k(d, digest):
        r = _mul(k, G)[0] % N
        if not r:
            continue
        s = pow(k, -1, N) * (e + r * d) % N
        if s:
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign(secret: bytes, msg: bytes) -> bytes:
    return sign_digest(secret, hashlib.sha256(msg).digest())


def verify_digest(public: bytes, digest: bytes, sig: bytes) -> bool:
    if len(public) != 64 or len(sig) != 64:
        return False
    q = (int.from_bytes(public[:32], "big"), int.from_bytes(public[32:], "big"))
    if not on_curve(q):
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    w = pow(s, -1, N)
    e = int.from_bytes(digest, "big")
    pt = _add(_mul(e * w % N, G), _mul(r * w % N, q))
    return pt is not None and pt[0] % N == r


def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    return verify_digest(public, hashlib.sha256(msg).digest(), sig)
