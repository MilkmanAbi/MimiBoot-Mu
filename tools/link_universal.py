"""Link a universal RP2350 image without a stale embedded RISC-V IMAGE_DEF.

picotool creates a relocated descriptor for its second input. The original
descriptor must be ignored, otherwise A2 ROM can select its unrelocated entry.
"""
import struct
import subprocess
from pathlib import Path


def link_universal(picotool, output, arm, riscv):
    output, arm, riscv = map(Path, (output, arm, riscv))
    subprocess.run([str(picotool), "link", str(output), str(arm), str(riscv)], check=True)
    image = bytearray(output.read_bytes())
    rv_offset = (arm.stat().st_size + 4095) & ~4095
    marker = riscv.read_bytes().find(struct.pack("<I", 0xffffded3), 0, 4096)
    if marker < 0:
        raise ValueError("RISC-V input has no initial metadata block")
    position = rv_offset + marker + 4
    word = struct.unpack_from("<I", image, position)[0]
    if word & 0xff != 0x42 or (word >> 24) & 7 != 1:
        raise ValueError("Unexpected RISC-V IMAGE_DEF layout")
    # Same one-word item length; preserve offsets and the final relocated block.
    struct.pack_into("<I", image, position, 0x000001fe)
    if len(image) > 245760:
        raise ValueError("Universal image exceeds the 240 KiB boot region")
    output.write_bytes(image)
