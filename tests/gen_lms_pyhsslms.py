#!/usr/bin/env python3
"""
Cross-checks against pyhsslms (an independent HSS/LMS implementation), run in a
venv that has it:  <venv>/python -I tests/gen_lms_pyhsslms.py make OUT.json
                   <venv>/python -I tests/gen_lms_pyhsslms.py check IN.json

make:  LMS signatures made by pyhsslms for parameter sets the published vectors
       don't cover (N32 W1/W2/W4/W8 with H5, H10/W4, N24 W4/W8), for gen_lms.py --pyhsslms
check: verify signatures made by tools/mb_lms.py (a JSON list of {pub, msg, sig}
       in hex) with pyhsslms; exit 1 if any fails
"""
import json
import os
import sys

import pyhsslms.pyhsslms as P


def make(out):
    sets = [("m32_h5", "n32_w1"), ("m32_h5", "n32_w2"), ("m32_h5", "n32_w4"), ("m32_h5", "n32_w8"),
            ("m32_h10", "n32_w4"), ("m24_h5", "n24_w4"), ("m24_h5", "n24_w8")]
    vec = []
    for lms, ots in sets:
        k = P.LmsPrivateKey(lms_type=getattr(P, "lms_sha256_" + lms), lmots_type=getattr(P, "lmots_sha256_" + ots))
        pub = k.publicKey().serialize()
        k.q = 3                      # not leaf 0 only: the path differs per leaf
        for i in range(2):
            msg = os.urandom(188 if i == 0 else 37)
            sig = k.sign(msg)
            assert k.publicKey().verify(msg, sig)
            vec.append({"src": "pyhsslms %s/%s q%d" % (lms, ots, 3 + i), "pub": pub.hex(), "msg": msg.hex(),
                        "sig": sig.hex(), "ok": True})
    json.dump(vec, open(out, "w"), indent=1)
    print("%d pyhsslms signatures -> %s" % (len(vec), out))


def check(path):
    bad = 0
    items = json.load(open(path))
    for v in items:
        pub = P.LmsPublicKey.deserialize(bytes.fromhex(v["pub"]))
        ok = pub.verify(bytes.fromhex(v["msg"]), bytes.fromhex(v["sig"]))
        if not ok:
            bad += 1
            print("pyhsslms rejects:", v.get("src", "?"))
    print("pyhsslms: %d/%d mb_lms signatures verify" % (len(items) - bad, len(items)))
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1] == "make":
        make(sys.argv[2])
    else:
        sys.exit(check(sys.argv[2]))
