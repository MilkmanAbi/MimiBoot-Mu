#!/usr/bin/env python3
"""
LMS test vectors for tests/test_crypto.c and tests/test_tools.py, from published
sources (nothing typed in by hand):

  RFC 8554 Appendix F, test cases 1 and 2 (two-level HSS; each level's LMS
      signature is checked on its own, since MimiBoot verifies single LMS)
  NIST ACVP-Server LMS sigVer / sigGen / keyGen (gen-val/json-files, the
      internalProjection.json of each), SHA-256 parameter sets only: positive
      and negative (testPassed = false) signature checks, and seed -> public key
  pyhsslms (an independent Python HSS/LMS by R. Housley), optional: signatures
      with N32 parameter sets the other sources don't cover (`--pyhsslms DIR`, the
      output of tests/gen_lms_pyhsslms.py run in its own venv)

usage: gen_lms.py REF_DIR [--pyhsslms FILE]   (REF_DIR holds rfc8554.txt and the ACVP folders)
writes tests/gen_lms.h (signatures) and tests/lms_keygen.json (seed -> public key)
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HEX = re.compile(r"^[0-9a-f]{2,}$")


def rfc_cases(path):
    """{case: {"pub": hex, "msg": hex, "sig": hex}} from RFC 8554 Appendix F"""
    text = open(path).read()
    text = text[text.index("Appendix F.  Test Cases", text.index("Appendix F.  Test Cases") + 1):]
    cases, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"\s+Test Case (\d) (Private Key|Public Key|Message|Signature)\s*$", line)
        if m:
            cur = cases.setdefault(int(m.group(1)), {}).setdefault(m.group(2), [])
            continue
        if line.startswith(("McGrew", "RFC 8554")) or cur is None:
            continue
        if line.strip().startswith("Acknowledgements"):
            break
        body = line.split("#")[0].split("|")[0]
        for tok in body.split():
            if HEX.match(tok) and len(tok) % 2 == 0:
                cur.append(tok)
    out = {}
    for n, parts in cases.items():
        out[n] = {"pub": "".join(parts["Public Key"]), "msg": "".join(parts["Message"]),
                  "sig": "".join(parts["Signature"]), "priv": "".join(parts.get("Private Key", []))}
    return out


def split_hss(pub_hex, sig_hex, msg_hex):
    """Two-level HSS -> [(lms_pub, msg, lms_sig)] for each level (RFC 8554 section 6.3)"""
    sys.path.insert(0, os.path.join(HERE, "..", "tools"))
    import mb_lms
    pub, sig, msg = bytes.fromhex(pub_hex), bytes.fromhex(sig_hex), bytes.fromhex(msg_hex)
    levels = int.from_bytes(pub[:4], "big")
    assert levels == 2 and int.from_bytes(sig[:4], "big") == 1
    pub0 = pub[4:]
    at = 4
    out = []
    for lvl in range(levels):
        lt0 = int.from_bytes(pub0[:4], "big")
        ot0 = int.from_bytes(sig[at + 4:at + 8], "big")
        n = mb_lms.sig_len(lt0, ot0)
        s = sig[at:at + n]
        at += n
        if lvl < levels - 1:
            m = mb_lms.LMS_TYPES[int.from_bytes(sig[at:at + 4], "big")][1]
            nxt = sig[at:at + 24 + m]
            at += 24 + m
            out.append((pub0, nxt, s))
            pub0 = nxt
        else:
            out.append((pub0, msg, s))
    assert at == len(sig)
    return out


SHA256 = re.compile(r"^LM(S|OTS)_SHA256_[MN](24|32)_")


def acvp(ref):
    sigs, keygens = [], []
    for d in ("LMS-sigVer-1.0", "LMS-sigVer-SP800-208", "LMS-sigGen-1.0", "LMS-sigGen-SP800-208"):
        p = os.path.join(ref, d, "internalProjection.json")
        if not os.path.exists(p):
            continue
        for g in json.load(open(p))["testGroups"]:
            if not SHA256.match(g["lmsMode"]) or not SHA256.match(g["lmOtsMode"]):
                continue
            for t in g["tests"][:3] if "sigGen" in d else g["tests"]:     # sigGen: a few per group is enough
                pub = t.get("publicKey", g.get("publicKey"))
                sigs.append({"src": "%s tg%d tc%d" % (d, g["tgId"], t["tcId"]), "pub": pub.lower(),
                             "msg": t["message"].lower(), "sig": t["signature"].lower(),
                             "ok": t.get("testPassed", True)})
    p = os.path.join(ref, "LMS-keyGen-1.0", "internalProjection.json")
    if os.path.exists(p):
        for g in json.load(open(p))["testGroups"]:
            if SHA256.match(g["lmsMode"]) and SHA256.match(g["lmOtsMode"]):
                for t in g["tests"]:
                    keygens.append({"src": "keyGen tg%d tc%d" % (g["tgId"], t["tcId"]), "seed": t["seed"].lower(),
                                    "I": t["i"].lower(), "pub": t["publicKey"].lower()})
    return sigs, keygens


def c_hex(h):
    """a hex string literal, split into lines (the test decodes it)"""
    return "\n".join('    "%s"' % h[i:i + 96] for i in range(0, len(h), 96)) if h else '    ""'


def main():
    ref = sys.argv[1]
    sigs, rfc_keys = [], []
    for n, c in sorted(rfc_cases(os.path.join(ref, "rfc8554.txt")).items()):
        levels = split_hss(c["pub"], c["sig"], c["msg"])
        for lvl, (pub, msg, sig) in enumerate(levels):
            sigs.append({"src": "RFC 8554 test case %d level %d" % (n, lvl), "pub": pub.hex(), "msg": msg.hex(),
                         "sig": sig.hex(), "ok": True})
        if c["priv"]:       # test case 2: SEED || I for each level (Appendix A key generation)
            priv = bytes.fromhex(c["priv"])
            assert len(priv) == 2 * 48
            for lvl in range(2):
                seed, I = priv[48 * lvl:48 * lvl + 32], priv[48 * lvl + 32:48 * lvl + 48]
                pub = levels[lvl][0]
                assert pub[8:24] == I
                rfc_keys.append({"src": "RFC 8554 test case %d level %d key" % (n, lvl), "seed": seed.hex(),
                                 "I": I.hex(), "pub": pub.hex()})
    a_sigs, keygens = acvp(ref)
    keygens = rfc_keys + keygens
    sigs += a_sigs
    if "--pyhsslms" in sys.argv:
        sigs += json.load(open(sys.argv[sys.argv.index("--pyhsslms") + 1]))
    json.dump(keygens, open(os.path.join(HERE, "lms_keygen.json"), "w"), indent=1)     # signatures: gen_lms.h only
    with open(os.path.join(HERE, "gen_lms.h"), "w") as f:
        f.write("/* generated by tests/gen_lms.py from RFC 8554 Appendix F, NIST ACVP-Server LMS vectors and\n"
                " * pyhsslms: do not edit. */\n#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n")
        f.write("/* hex strings: public key, message, signature, expected result */\n"
                "static const struct { const char *src, *pub, *msg, *sig; bool ok; } lms_vectors[] = {\n")
        for v in sigs:
            f.write('  {"%s",\n%s,\n%s,\n%s,\n    %s},\n' % (v["src"], c_hex(v["pub"]), c_hex(v["msg"]), c_hex(v["sig"]),
                                                  "true" if v["ok"] else "false"))
        f.write("};\n")
    print("%d signature vectors (%d negative), %d keyGen" % (len(sigs), sum(not v["ok"] for v in sigs), len(keygens)))


if __name__ == "__main__":
    main()
