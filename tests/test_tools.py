#!/usr/bin/env python3
"""No-device tests for chip-specific pack/UF2 generation and slot bounds."""
import importlib.util,struct,tempfile,types,contextlib,io
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("mbtool",ROOT/"tools/mbtool.py");m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix="night-tools-") as td:
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
print("host tool tests: PASS (three UF2 families, layout bounds, RP2040 XIP refusal)")
