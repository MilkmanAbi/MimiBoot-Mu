#!/usr/bin/env python3
"""Build all CPU targets and link the RP2350 universal image. Never flashes hardware."""
import argparse, hashlib, json, os, shutil, subprocess, tempfile
from pathlib import Path
from link_universal import link_universal
ROOT=Path(__file__).resolve().parents[1]
def run(args):
    print("+", " ".join(map(str,args)),flush=True)
    subprocess.run(list(map(str,args)),check=True)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",default=os.environ.get("PICO_SDK_PATH",str(Path.home()/"pico/pico-sdk")))
    p.add_argument("--out",type=Path,default=Path(tempfile.gettempdir())/"mimiboot-night-build")
    p.add_argument("--picotool",default=os.environ.get("PICOTOOL",shutil.which("picotool")))
    p.add_argument("--riscv",default=os.environ.get("RISCV_TOOLCHAIN"))
    p.add_argument("--arm",default=os.environ.get("ARM_TOOLCHAIN"))
    p.add_argument("--platform",choices=["all","rp2040","rp2350-arm-s","rp2350-riscv","rp2350-universal"],default="all")
    p.add_argument("--config-header",type=Path,help="mimiconf feature header (default: every feature on)")
    p.add_argument("--flash-size",type=int,help="override the board's flash size in bytes")
    p.add_argument("--board2040",default="pico");p.add_argument("--board2350",default="pico2")
    p.add_argument("--keys",type=Path);p.add_argument("--require-signature",action="store_true")
    p.add_argument("--jobs",type=int,default=4)
    a=p.parse_args();a.out=a.out.resolve();dist=a.out/"dist";dist.mkdir(parents=True,exist_ok=True)
    universal=a.platform in ("all","rp2350-universal")
    platforms={"all":["rp2040","rp2350-arm-s","rp2350-riscv"],"rp2350-universal":["rp2350-arm-s","rp2350-riscv"]}.get(a.platform,[a.platform])
    cmake=shutil.which("cmake") or "cmake";pt=str(Path(a.picotool).resolve()) if a.picotool else None
    if a.require_signature and not a.keys:p.error("--require-signature needs --keys")
    for platform in platforms:
        b=a.out/platform;board=a.board2040 if platform=="rp2040" else a.board2350
        cmd=[cmake,"-S",ROOT,"-B",b,"-G","Ninja",f"-DPICO_SDK_PATH={Path(a.sdk).resolve()}",f"-DPICO_PLATFORM={platform}",f"-DPICO_BOARD={board}",f"-DMIMIBOOT_UNIVERSAL={'OFF' if platform=='rp2040' else 'ON'}",f"-DMIMIBOOT_REQUIRE_SIGNATURE={'ON' if a.require_signature else 'OFF'}"]
        toolchain=a.riscv if platform.endswith("riscv") else a.arm
        if toolchain:cmd += [f"-DPICO_TOOLCHAIN_PATH={Path(toolchain).resolve()}"]
        if pt:cmd += [f"-Dpicotool_DIR={Path(pt).parent}"]
        if a.keys:cmd += [f"-DMIMIBOOT_KEYS={a.keys.resolve()}"]
        cmd += [f"-DMIMIBOOT_CONFIG_HEADER={a.config_header.resolve() if a.config_header else ''}"]
        cmd += [f"-DMIMIBOOT_FLASH_SIZE={a.flash_size or ''}"]
        run(cmd);run([cmake,"--build",b,"--parallel",a.jobs])
        for stem in ["mimiboot_night"]+(["mimiboot_night_ram"] if platform=="rp2040" else []):
            for ext in ("elf","bin","uf2"):
                f=b/(stem+"."+ext)
                if f.exists():shutil.copy2(f,dist/(platform+"-"+f.name))
    if universal:
        if not pt:p.error("--picotool is required to link the universal image")
        variants=[""]
        for suffix in variants:
            stem="mimiboot_night"+suffix;out=dist/(stem+"_universal.bin")
            link_universal(pt,out,a.out/"rp2350-arm-s"/(stem+".bin"),a.out/"rp2350-riscv"/(stem+".bin"))
            if out.stat().st_size>245760:raise RuntimeError("universal image exceeds 240 KiB boot region")
            run([pt,"uf2","convert",out,out.with_suffix(".uf2"),"-o","0x10000000","--family","absolute"])
    manifest={f.name:{"bytes":f.stat().st_size,"sha256":hashlib.sha256(f.read_bytes()).hexdigest()} for f in sorted(dist.iterdir()) if f.suffix in (".elf",".bin",".uf2")}
    (dist/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print("Built artifacts:",dist)
if __name__=="__main__":main()
