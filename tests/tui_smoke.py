#!/usr/bin/env python3
"""Drive the curses menuconfig in a real pseudo-terminal (Linux/WSL/macOS), wide
(details pane beside the list) and narrow (details below): pick a board through
maker > category > board, open a menu, toggle an option, save, quit; check the .config."""
import os
import pty
import select
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOWN = b"\x1bOB"     # cursor down in keypad-transmit mode (what curses switches xterm to)


def session(cols: int) -> dict:
    cfg = Path(tempfile.mkdtemp()) / ".config"
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(TERM="xterm-256color", LINES="40", COLUMNS=str(cols), LANG="C.UTF-8")
        os.chdir(ROOT)
        os.execvp(sys.executable, [sys.executable, "mimiconf.py", "-c", str(cfg)])
    screen = b""

    def pump(t=0.6):
        nonlocal screen
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    screen += os.read(fd, 65536)
                except OSError:
                    return

    def key(k, t=0.4):
        os.write(fd, k)
        pump(t)

    pump(1.5)
    seen_makers = all(f in screen for f in (b"STMicro", b"Nordic", b"Raspberry", b"Atmel"))  # curses may split words
    key(b"\r")                          # STMicroelectronics
    seen_cats = b"Nucleo boards" in screen
    key(b"\r")                          # Nucleo boards
    seen_details = b"tested" in screen and b"nucleo-f103rb" in screen
    key(b"\r")                          # the first Nucleo (nucleo-f103rb)
    seen_main = b"Slots and updates" in screen and b"Presets" in screen
    key(DOWN)                           # Presets
    key(DOWN)                           # Slots and updates
    key(b"\r")
    seen_menu = b"Updates must confirm" in screen
    key(DOWN)                           # AUX_SLOTS (greyed out, still selectable)
    key(DOWN)                           # AB_TRIAL
    key(b" ")                           # toggle it on
    key(b"S")
    key(b"q", 1.0)
    pump(1.0)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    text = cfg.read_text() if cfg.exists() else ""
    ok = {
        f"{cols} cols: maker list on a fresh start": seen_makers,
        f"{cols} cols: categories": seen_cats,
        f"{cols} cols: board list with details": seen_details,
        f"{cols} cols: home screen after picking a board": seen_main,
        f"{cols} cols: a menu opens": seen_menu,
        f"{cols} cols: .config saved with the toggled option": 'MU_BOARD="nucleo-f103rb"' in text and "MU_AB_TRIAL=y" in text,
    }
    if not all(ok.values()):
        print(text or "(no .config)")
        print(screen[-2000:].decode(errors="replace"))
    return ok


def main():
    results = {}
    for cols in (120, 80):
        results.update(session(cols))
    for k, v in results.items():
        print(f"[{'PASS' if v else 'FAIL'}] {k}")
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
