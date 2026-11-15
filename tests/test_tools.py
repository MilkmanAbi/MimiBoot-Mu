#!/usr/bin/env python3
"""No-device tests for chip-specific pack/UF2 generation and slot bounds."""
import importlib.util,struct,tempfile,types,contextlib,io
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("mbtool",ROOT/"tools/mbtool.py");m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix="mu-tools-") as td:
    d=Path(td);payload=b"\0"*512
    for target,arch,layout,family in [("rp2040",m.ARCH_ARM,"2m",m.UF2_FAMILY_RP2040),("rp2350",m.ARCH_ARM,"4m",m.UF2_FAMILY_RP2350_ARM_S),("rp2350",m.ARCH_RISCV,"16m",m.UF2_FAMILY_RP2350_RISCV)]:
        img=d/(target+str(arch)+".mimg");hdr=m.build_header(payload,"test",0x10000,target=target,arch=arch,load_type=m.LOAD_RAM,load_addr=0x20000000)
        img.write_bytes(hdr+b"\xff"*(4096-len(hdr))+payload)
        out=img.with_suffix(".uf2");m.cmd_uf2(types.SimpleNamespace(image=str(img),layout=layout,slot="a",output=str(out)))
        data=out.read_bytes();start=0 if target=="rp2040" else 512
        fields=struct.unpack_from("<8I",data,start)
        assert fields[3]==0x10040000 and fields[7]==family
        assert len(data)%512==0 and fields[6]==len(data)//512-start//512
        for offset in range(start,len(data),512):assert struct.unpack_from("<I",data,offset+508)[0]==m.UF2_MAGIC_END
    for layout in m.LAYOUTS:
        try:m.slot_region("boot",layout)
        except SystemExit:pass
        else:raise AssertionError("boot region allowed")
    binary=d/"raw.bin";binary.write_bytes(payload)
    # A header for an RP2040 XIP image must never be generated.
    args=types.SimpleNamespace(input=str(binary),load_addr=None,arch=None,key=None,name="bad",version="1.0.0",secver=0,golden=False,trial_ms=0,target="rp2040",output=str(d/"bad.mimg"))
    try:m.cmd_pack(args)
    except SystemExit:pass
    else:raise AssertionError("RP2040 XIP accepted")
    assert not (d/"bad.mimg").exists()
    binary.write_bytes(struct.pack("<II",0x20042000,0x20000101)+b"\0"*504)
    args.load_addr="0x20000000";args.output=str(d/"valid.mimg")
    m.cmd_pack(args)
    h=m.image_file(args.output)[1]
    assert h["entry"]==0x20000000 and h["target"]=="rp2040"
    # encrypted images: mb_enc.py against published vectors, then pack --encrypt / info / refusals
    e=m.enc;H=bytes.fromhex
    assert e.aes_block(H("000102030405060708090a0b0c0d0e0f"),H("00112233445566778899aabbccddeeff"))==H("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert e.aes_block(H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),H("00112233445566778899aabbccddeeff"))==H("8ea2b7ca516745bfeafc49904b496089")
    assert e.aes_ctr(H("2b7e151628aed2a6abf7158809cf4f3c"),H("6bc1bee22e409f96e93d7e117393172a"),H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))==H("874d6191b620e3261bef6864990db6ce")
    assert e.x25519(H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))==H("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    assert e.public_key(H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))==H("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert e.hkdf_sha256(b"\x0b"*22,b"",42)==H("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    with contextlib.redirect_stdout(io.StringIO()):
        m.cmd_keygen(types.SimpleNamespace(out=str(d/"dev"),force=False,type="x25519"))
    for bits in (128,256):
        out=d/("enc%d.mimg"%bits)
        args.output=str(out);args.encrypt=str(d/"dev.pub");args.encrypt_keylen=bits
        with contextlib.redirect_stdout(io.StringIO()):m.cmd_pack(args)
        img,h,ct,problems=m.image_file(str(out))
        assert not problems and h["flags"]&m.F_ENCRYPTED and len(h["envelope"])==4+64+bits//8
        assert ct!=binary.read_bytes() and e.aes_ctr(e.unwrap(e.load_key(str(d/"dev.key")),h["envelope"]),ct)==binary.read_bytes()
        info=types.SimpleNamespace(image=str(out),pub=None,enc_key=str(d/"dev.key"),layout="4m")
        with contextlib.redirect_stdout(io.StringIO()) as o:rc=m.cmd_info(info)
        assert rc==0 and "decrypts OK" in o.getvalue()
        for cmd in (m.cmd_uf2,m.cmd_flash):
            try:cmd(types.SimpleNamespace(image=str(out),layout="4m",slot="a",output=str(d/"x.uf2"),picotool="false",force=True))
            except SystemExit:pass
            else:raise AssertionError("raw flashing of an encrypted image accepted")
    other=e.wrap(e.public_key(b"\x42"*32),b"k"*16)
    try:e.unwrap(e.load_key(str(d/"dev.key")),other)
    except ValueError:pass
    else:raise AssertionError("an envelope for another key opened")

    # LMS: mb_lms.py against the published vectors (tests/gen_lms.py output), then keygen / pack / sign / info
    import json, re
    L = m.lms
    vec = (ROOT / "tests/gen_lms.h").read_text()
    n_sig = 0
    for v in re.finditer(r'\{"([^"]+)",(.*?),\s*(true|false)\}', vec, re.S):
        pub, msg, sig = (bytes.fromhex("".join(re.findall(r'"([0-9a-f]*)"', part)))
                         for part in re.findall(r'((?:\s*"[0-9a-f]*")+)', v.group(2)))
        assert L.verify(pub, msg, sig) == (v.group(3) == "true"), v.group(1)
        n_sig += 1
    assert n_sig >= 40
    for k in json.loads((ROOT / "tests/lms_keygen.json").read_text()):
        pub = H(k["pub"])
        if pub[3] in (5, 0x0A):                         # the H5 ones (the H10 trees take seconds each)
            got, _ = L.public_from_seed(int.from_bytes(pub[:4], "big"), int.from_bytes(pub[4:8], "big"), H(k["I"]), H(k["seed"]))
            assert got == pub, k["src"]
    with contextlib.redirect_stdout(io.StringIO()):
        m.cmd_keygen(types.SimpleNamespace(out=str(d / "pq"), force=False, type="lms", lms_height=5, lms_w=4))
    pq = json.loads((d / "pq.key").read_text())
    assert pq["next"] == 0 and (d / "pq.key.tree").exists() and "MB_TRUSTED_LMS_KEYS" in (d / "pq_keys.h").read_text()
    assert "*.key.tree" in (d / ".gitignore").read_text().split()
    args.encrypt = None; args.key = str(d / "pq.key"); args.output = str(d / "pq.mimg")
    with contextlib.redirect_stdout(io.StringIO()): m.cmd_pack(args)
    img, h, _, problems = m.image_file(args.output)
    assert not problems and h["flags"] & m.F_LMS and h["flags"] & m.F_SIGNED and h["signature"] == bytes(64)
    assert h["key_id"] == L.key_id(H((d / "pq.pub").read_text().split()[0]))
    assert json.loads((d / "pq.key").read_text())["next"] == 1, "the key file counts the signature it made"
    info = types.SimpleNamespace(image=args.output, pub=str(d / "pq.pub"), enc_key=None, layout="4m")
    with contextlib.redirect_stdout(io.StringIO()) as o: rc = m.cmd_info(info)
    assert rc == 0 and "signature OK" in o.getvalue() and "LMS" in o.getvalue(), o.getvalue()
    # a one-level HSS public key file (binary, as hash-sigs / pyhsslms write it) works too
    (d / "pq.hss.pub").write_bytes(L.hss_public(H((d / "pq.pub").read_text().split()[0])))
    info.pub = str(d / "pq.hss.pub")
    with contextlib.redirect_stdout(io.StringIO()) as o: rc = m.cmd_info(info)
    assert rc == 0 and "signature OK" in o.getvalue()
    # re-signing replaces the signature (one LMS TLV, a fresh leaf); a flipped bit is caught
    with contextlib.redirect_stdout(io.StringIO()): m.cmd_sign(types.SimpleNamespace(image=args.output, key=args.key, output=None))
    img, h, _, problems = m.image_file(args.output)
    assert not problems and json.loads((d / "pq.key").read_text())["next"] == 2
    assert struct.unpack(">I", h["lms_sig"][:4])[0] == 1, "leaf 1 for the second signature"
    bad = bytearray(img); bad[m.HDR_SIZE + 4 + 500] ^= 1
    (d / "pq-bad.mimg").write_bytes(bytes(bad)); info.image = str(d / "pq-bad.mimg"); info.pub = str(d / "pq.pub")
    with contextlib.redirect_stdout(io.StringIO()) as o: rc = m.cmd_info(info)
    assert rc == 1 and "signature BAD" in o.getvalue()
    # an Ed25519 key re-signs it: the LMS signature goes, the flag with it
    with contextlib.redirect_stdout(io.StringIO()):
        m.cmd_keygen(types.SimpleNamespace(out=str(d / "ed"), force=False, type="ed25519"))
        m.cmd_sign(types.SimpleNamespace(image=args.output, key=str(d / "ed.key"), output=str(d / "ed.mimg")))
    img, h, _, problems = m.image_file(str(d / "ed.mimg"))
    assert not problems and not h["flags"] & m.F_LMS and m.TLV_LMS not in m.tlvs_of(img)
    # a used-up key refuses, and leaves its file alone
    pq = json.loads((d / "pq.key").read_text()); pq["next"] = 32; (d / "pq.key").write_text(json.dumps(pq))
    try: m.cmd_pack(args)
    except (SystemExit, ValueError): pass
    else: raise AssertionError("an exhausted LMS key signed")
    assert json.loads((d / "pq.key").read_text())["next"] == 32
    # a stray TLV in the header sector is refused (the board refuses it too)
    junk = bytearray(img); junk[m.HDR_SIZE:m.HDR_SIZE + 8] = bytes([0x77, 0, 4, 0, 1, 2, 3, 4])
    (d / "junk.mimg").write_bytes(bytes(junk))
    assert m.image_file(str(d / "junk.mimg"))[3], "unknown TLV accepted"
print("host tool tests: PASS (three UF2 families, layout bounds, RP2040 XIP refusal, encrypted images, LMS)")
