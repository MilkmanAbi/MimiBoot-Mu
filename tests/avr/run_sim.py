#!/usr/bin/env python3
"""(Linux side) Run MimiBoot-Mu Lite in simavr and drive it with the real avrdude.

Called by tests/avr/test_avr.py with a JSON description of the builds.
Needs simavr's library + headers and avrdude: SIM_ROOT points at an
extracted root (dpkg -x of libsimavr-dev, libsimavrparts1, avrdude, ...),
or they are installed system-wide.
"""
import json
import os
import re
import select
import subprocess
import sys
import termios
import time
import tty
from pathlib import Path

SIM_ROOT = Path(os.environ.get("SIM_ROOT", str(Path.home() / "mu-sim/root")))
LIB = f"{SIM_ROOT}/usr/lib/x86_64-linux-gnu"
ENV = dict(os.environ, LD_LIBRARY_PATH=f"{LIB}:{SIM_ROOT}/lib/x86_64-linux-gnu")
AVRDUDE = [str(SIM_ROOT / "usr/bin/avrdude"), "-C", str(SIM_ROOT / "etc/avrdude.conf")] \
    if (SIM_ROOT / "usr/bin/avrdude").exists() else ["avrdude"]
PTY = "/tmp/simavr-uart0"
HERE = Path(__file__).resolve().parent
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}", flush=True)
    if not ok and detail:
        print("   " + detail.strip().replace("\n", "\n   ")[-2000:], flush=True)


def build_sim(work: Path) -> Path:
    exe = work / "sim_mu"
    inc = SIM_ROOT / "usr/include/simavr"
    subprocess.run(["gcc", "-O2", "-I", str(inc), "-I", str(inc / "avr"), str(HERE / "sim_mu.c"), "-o", str(exe),
                    "-L", LIB, "-lsimavrparts", "-lsimavr", "-l:libelf.so.1", "-lpthread", "-lutil",
                    f"-Wl,-rpath,{LIB}"], check=True)
    return exe


class Sim:
    def __init__(self, exe, mcu, hz, elf, boot_start, seconds=120):
        self.p = subprocess.Popen([str(exe), mcu, str(hz), elf, hex(boot_start), str(seconds)], env=ENV,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        seen = ""
        while "SIM READY" not in seen:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("simulator didn't start: " + seen)
            seen += line
        self.fd = os.open(PTY, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        tty.setraw(self.fd)
        a = termios.tcgetattr(self.fd)
        a[4] = a[5] = termios.B115200
        termios.tcsetattr(self.fd, termios.TCSANOW, a)
        self.buf = ""

    def read_until(self, pattern, timeout=5.0):
        end = time.time() + timeout
        rx = re.compile(pattern)
        while time.time() < end:
            m = rx.search(self.buf)
            if m:
                out, self.buf = self.buf[:m.end()], self.buf[m.end():]
                return out
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    self.buf += os.read(self.fd, 4096).decode(errors="replace")
                except BlockingIOError:
                    pass
        return None

    def banner(self, name=""):
        """the app's start line; avrdude may have swallowed it on close, so ask again with '?'"""
        pat = r"MU-AVR-APP " + name + r".*\r\n"
        line = self.read_until(pat, 2.5)
        if line is None:
            self.send(b"?")
            line = self.read_until(pat, 4)
        return line

    def quiet_for(self, pattern, seconds):
        """True when `pattern` does NOT show up within `seconds`"""
        return self.read_until(pattern, seconds) is None

    def send(self, data: bytes, pace=0.0):
        for i in range(0, len(data), 16 if pace else len(data)):
            os.write(self.fd, data[i:i + (16 if pace else len(data))])
            if pace:
                time.sleep(pace)

    def avrdude(self, part, *ops, timeout=60):
        self.buf = ""
        r = subprocess.run(AVRDUDE + ["-p", part, "-c", "arduino", "-P", PTY, "-b", "115200", "-D", "-x", "attempts=4", *ops],
                           env=ENV, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()


def flags_of(line):
    m = re.search(r"flags=([0-9a-f]{2})", line or "")
    return int(m.group(1), 16) if m else None


def scenario_default(exe, b, work):
    s = Sim(exe, b["mcu"], b["hz"], b["boot_elf"], b["boot_start"])
    try:
        rc, out = s.avrdude(b["part"], "-U", f"flash:w:{b['app_v1']}:i")
        check("avrdude uploads through the bootloader (write + verify)", rc == 0 and "verified" in out, out)
        line = s.banner()
        f = flags_of(line)
        check("the app starts after the upload, handoff says uploaded + CRC verified",
              line is not None and "by=01" in line and f is not None and f & 0x05 == 0x05, line or s.buf)
        s.send(b"b")
        s.read_until(r"REQ", 3)
        rc, out = s.avrdude(b["part"], "-U", f"eeprom:r:{work}/ee.bin:r")
        check("mu_enter_bootloader(): the bootloader answers avrdude (EEPROM read)", rc == 0, out)
        ee = bytearray(Path(f"{work}/ee.bin").read_bytes())
        rec = len(ee) - 16
        check("upload left an app record (magic 'Mu') at the top of EEPROM", ee[rec:rec + 2] == b"Mu", ee[rec:].hex())
        line = s.banner()
        check("after the session the app runs again", line is not None, s.buf)
        # damage the recorded CRC: the bootloader must refuse the app
        ee[rec + 6] ^= 0xFF
        Path(f"{work}/ee_bad.bin").write_bytes(ee)
        s.send(b"b")
        s.read_until(r"REQ", 3)
        rc, out = s.avrdude(b["part"], "-U", f"eeprom:w:{work}/ee_bad.bin:r")
        check("EEPROM written over STK500", rc == 0, out)
        check("app whose CRC doesn't match its record is not started", s.quiet_for(r"MU-AVR-APP", 4), s.buf)
        rc, out = s.avrdude(b["part"], "-U", f"flash:w:{b['app_v1']}:i")
        line = s.banner()
        check("bootloader kept listening; a fresh upload repairs it", rc == 0 and line is not None, out + s.buf)
    finally:
        s.close()


def scenario_trial(exe, b, work):
    s = Sim(exe, b["mcu"], b["hz"], b["boot_elf"], b["boot_start"])
    try:
        rc, out = s.avrdude(b["part"], "-U", f"flash:w:{b['app_v1']}:i")
        line = s.banner()
        f = flags_of(line)
        check("trial: first start after upload is a trial", rc == 0 and f is not None and f & 0x02, (line or "") + out)
        s.send(b"r")
        line = s.read_until(r"MU-AVR-APP .*\r\n", 6)
        check("trial: unconfirmed, it gets its second try", line is not None and flags_of(line) & 0x02, s.buf)
        s.send(b"r")
        check("trial: out of tries, the bootloader stops starting it", s.quiet_for(r"MU-AVR-APP", 4), s.buf)
        rc, out = s.avrdude(b["part"], "-U", f"flash:w:{b['app_v1']}:i")
        line = s.banner()
        s.send(b"c")
        conf = s.read_until(r"CONFIRMED", 3)
        s.send(b"r")
        line2 = s.read_until(r"MU-AVR-APP .*\r\n", 6)
        check("trial: confirmed build starts without a trial from then on",
              rc == 0 and conf is not None and line2 is not None and not flags_of(line2) & 0x02, out + s.buf)
    finally:
        s.close()


def scenario_stage(exe, b, work):
    s = Sim(exe, b["mcu"], b["hz"], b["boot_elf"], b["boot_start"])
    try:
        rc, out = s.avrdude(b["part"], "-U", f"flash:w:{b['app_v1']}:i")
        line = s.banner("v1")
        check("staged: v1 uploaded and running", rc == 0 and line is not None, out + s.buf)
        v2 = Path(b["app_v2_bin"]).read_bytes()
        import zlib
        hdr = b"s" + len(v2).to_bytes(2, "little") + (zlib.crc32(v2) & 0xFFFFFFFF).to_bytes(4, "little")
        s.send(hdr)
        page = b["page"]
        for i in range(0, len(v2), page):         # one page at a time: the app answers '.' per page
            s.send(v2[i:i + page], pace=0.002)
            s.read_until(r"\.", 3)
        staged = s.read_until(r"STAGED|STAGE-CRC-BAD|NO-API", 6)
        check("staged: app wrote v2 through the bootloader's flash service", staged is not None and "STAGED" in staged,
              s.buf)
        line = s.read_until(r"MU-AVR-APP .*\r\n", 8)
        f = flags_of(line)
        check("staged: the bootloader installed v2 and says so (INSTALLED + VERIFIED)",
              line is not None and "MU-AVR-APP v2" in line and f is not None and f & 0x09 == 0x09, line or s.buf)
    finally:
        s.close()


def main():
    spec = json.loads(Path(sys.argv[1]).read_text())
    work = Path(spec["work"])
    exe = build_sim(work)
    for name, fn in (("default", scenario_default), ("trial", scenario_trial), ("stage", scenario_stage)):
        if name in spec:
            print(f"\n--- {name} ({spec[name]['board']}) ---", flush=True)
            fn(exe, spec[name], work)
    bad = [n for n, ok in results if not ok]
    print(f"\navr sim: {len(results) - len(bad)}/{len(results)} passed", flush=True)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
