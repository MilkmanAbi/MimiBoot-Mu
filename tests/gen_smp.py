"""
SMP (mcumgr) requests for the C tests, made by an independent implementation:
the `smp` package (Intercreate's, the one smpclient and smpmgr use) builds the
messages and frames them the way Zephyr's serial transport does.

    pip install smp==4.3.0
    python tests/gen_smp.py > tests/gen_smp.h

The output is committed, so the host tests don't need the package.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import mbtool  # noqa: E402
from smp import header as smphdr  # noqa: E402
from smp import image_management as img  # noqa: E402
from smp import os_management as osm  # noqa: E402
from smp import packet  # noqa: E402

LINE = 127                      # Zephyr's MCUMGR_SERIAL_MAX_FRAME
SEED, SIZE = 61, 5000           # the uploaded MimiBoot image's payload: not a whole number of pages


def payload(seed, size):
    """Same generator as make_payload() in test_mimiboot.c (xorshift32)."""
    x = (seed * 2654435761 + 1) & 0xFFFFFFFF
    out = bytearray(size)
    for i in range(size):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        out[i] = x & 0xFF
    return bytes(out)


def frames(msg) -> bytes:
    return b"".join(packet.encode(msg.BYTES, line_length=LINE))


def c_array(name, data):
    rows = ", ".join("0x%02x" % b for b in data)
    return "__attribute__((unused)) static const uint8_t %s[%d] = { %s };" % (name, len(data), rows)


def upload(image: bytes, chunks, image_no=0, stop_after=None, resync_after=None, seq=10):
    """the chunks of one upload, as an SMP client sends them"""
    out, off, n = b"", 0, 0
    sha = hashlib.sha256(image).digest()
    for size in chunks:
        if off >= len(image) or (stop_after is not None and n == stop_after):
            break
        data = image[off:off + size]
        extra = {"image": image_no, "len": len(image), "sha": sha, "upgrade": False} if off == 0 else {}
        out += frames(img.ImageUploadWriteRequest(off=off, data=data, sequence=seq + n, **extra))
        if resync_after is not None and n == resync_after:
            # a chunk at the wrong offset: the board says where it is, the client goes on from there
            out += frames(img.ImageUploadWriteRequest(off=off + 4 * len(data), data=data, sequence=200))
        off += len(data)
        n += 1
    return out


def main():
    pay = payload(SEED, SIZE)
    hdr = mbtool.build_header(pay, "smp-app", mbtool.parse_version("4.5.6"), 2, target="sim",
                              arch=mbtool.ARCH_ARM, build_time=0)
    image = hdr + b"\xff" * (mbtool.PAYLOAD_OFF - len(hdr)) + pay
    chunks = [300, 900, 450, 1000, 777] + [900] * 20      # odd sizes: pages are assembled on the board
    # the same image signed with the key the simulator trusts (RFC 8032 test 1)
    rfc1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    shdr = mbtool.build_header(pay, "smp-app", mbtool.parse_version("4.5.6"), 2, target="sim",
                               arch=mbtool.ARCH_ARM, build_time=0, secret=rfc1)
    signed = shdr + b"\xff" * (mbtool.PAYLOAD_OFF - len(shdr)) + pay
    bad = bytearray(image)
    bad[mbtool.PAYLOAD_OFF + 1234] ^= 0x40                 # the payload no longer matches its header
    # the same image encrypted (as `mbtool pack --encrypt` makes it) for the simulator's device key,
    # with fixed keys so the output is reproducible
    dev = hashlib.sha256(b"MimiBoot test encryption key").digest()
    ehdr = mbtool.build_header(pay, "smp-app", mbtool.parse_version("4.5.6"), 2, target="sim",
                               arch=mbtool.ARCH_ARM, build_time=0, encrypted=True)
    ikey = hashlib.sha256(b"smp image key").digest()[:16]
    env = mbtool.enc.wrap(mbtool.enc.public_key(dev), ikey, ephemeral=hashlib.sha256(b"smp ephemeral").digest())
    encimg = ehdr + env + b"\xff" * (mbtool.PAYLOAD_OFF - len(ehdr) - len(env)) + mbtool.enc.aes_ctr(ikey, pay)
    badenv = bytearray(encimg)
    badenv[mbtool.HDR_SIZE + 40] ^= 0x01                   # a flipped bit in the envelope's tag

    # LMS-signed (tests/gen_signed.py's fixed "app" key, H5 / W4, leaf 20): the signature is a TLV after the header
    import mb_lms
    lt, ot = mb_lms.lms_type_for(5, 4)
    I, seed = hashlib.sha256(b"I app").digest()[:16], hashlib.sha256(b"SEED app").digest()
    pub, T = mb_lms.public_from_seed(lt, ot, I, seed)
    lsec = mbtool.Secret.__new__(mbtool.Secret)
    lsec.kind, lsec.ecdsa, lsec.lms, lsec.public, lsec.key_id = "lms", False, True, pub, mb_lms.key_id(pub)

    class _Leaf:
        def sign(self, msg):
            return mb_lms.sign_leaf(lt, ot, I, seed, T, 20, msg, hashlib.sha256(b"smp C" + msg).digest())
    lsec.raw = _Leaf()
    lhdr = mbtool.build_header(pay, "smp-app", mbtool.parse_version("4.5.6"), 2, target="sim",
                               arch=mbtool.ARCH_ARM, build_time=0, secret=lsec)
    lmsimg = mbtool.header_sector(lhdr, lsec.pending_tlv) + pay
    assert mb_lms.verify(pub, lhdr[:mbtool.SIGNED_BYTES], mbtool.lms_sig_of(lmsimg))
    badsig = bytearray(lmsimg)
    badsig[mbtool.HDR_SIZE + 4 + 300] ^= 0x01               # a flipped bit in one chain value

    print("/* generated by tests/gen_smp.py (smp %s) - do not edit */" % getattr(packet, "__version__", "4.x"))
    print("#define SMP_IMG_SEED %d\n#define SMP_IMG_SIZE %d\n#define SMP_IMG_LEN %d" % (SEED, SIZE, len(image)))
    print(c_array("smp_img_hdr", hdr))
    print(c_array("smp_img_sha", hashlib.sha256(image).digest()))
    print(c_array("smp_echo", frames(osm.EchoWriteRequest(d="hi from smp", sequence=1))))
    print(c_array("smp_echo_v1", frames(osm.EchoWriteRequest(d="v1 talk", version=smphdr.Version.V1, sequence=2))))
    print(c_array("smp_params", frames(osm.MCUMgrParametersReadRequest(sequence=3))))
    print(c_array("smp_bootinfo", frames(osm.BootloaderInformationReadRequest(sequence=4))))
    print(c_array("smp_list", frames(img.ImageStatesReadRequest(sequence=5))))
    print(c_array("smp_upload", upload(image, chunks, resync_after=0)))
    print(c_array("smp_upload_golden", upload(image, chunks, image_no=3, stop_after=1)))
    print(c_array("smp_upload_bad", upload(bytes(bad), chunks, image_no=2)))
    print(c_array("smp_upload_cut", upload(image, chunks, image_no=2, stop_after=3)))
    print(c_array("smp_upload_signed", upload(signed, chunks, image_no=2)))
    print(c_array("smp_upload_unsigned_first", upload(image, chunks, image_no=2, stop_after=1)))
    print(c_array("smp_upload_enc", upload(encimg, chunks, image_no=2)))
    print(c_array("smp_upload_enc_badenv", upload(bytes(badenv), chunks, image_no=2)))
    print(c_array("smp_upload_lms", upload(lmsimg, chunks, image_no=2)))
    print(c_array("smp_upload_lms_badsig", upload(bytes(badsig), chunks, image_no=2)))
    print(c_array("smp_confirm", frames(img.ImageStatesWriteRequest(hash=hashlib.sha256(pay).digest(), confirm=True,
                                                                   sequence=6))))
    print(c_array("smp_erase_b", frames(img.ImageEraseRequest(slot=1, sequence=7))))
    print(c_array("smp_erase_a", frames(img.ImageEraseRequest(slot=0, sequence=11))))
    print(c_array("smp_slot_info", frames(img.ImageSlotInfoReadRequest(sequence=8))))
    print(c_array("smp_reset", frames(osm.ResetWriteRequest(sequence=9))))


if __name__ == "__main__":
    main()
