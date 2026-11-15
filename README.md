# MimiBoot-Mu

A bootloader for microcontrollers that you configure like a Linux kernel. It runs on the
RP2040 and RP2350, STM32, Nordic nRF51 and nRF52, Microchip SAM D21 and D51, and classic
AVRs such as the ATmega328P on an Arduino Uno.

You run **MuConfigurator** (`python muconfigurator.py`), pick your board, switch features
on or off, and build. The binary contains only what you picked. Change your mind later,
rerun it, rebuild.

**Documentation:** https://milkmaidabi.github.io/MimiBoot-Mu-Docs/ ·
[feature matrix](https://milkmaidabi.github.io/MimiBoot-Mu-Docs/matrix.html) ·
[before you flash](https://milkmaidabi.github.io/MimiBoot-Mu-Docs/before-you-flash.html)

> **Status: most of this hasn't run on real hardware yet.** Earlier builds of the
> RP2040 and RP2350 ports have run on real boards. Everything else has run in emulators
> (QEMU, simavr), against register models, or has only been compiled.
> **On STM32, no flash write has ever run on a real chip**: keep an ST-Link on SWD while
> you try one, and check that you can connect under reset before you start. On nRF and
> SAM D, have an SWD probe ready; on AVR, an ISP programmer. The
> [feature matrix](https://milkmaidabi.github.io/MimiBoot-Mu-Docs/matrix.html) shows how
> far each feature has been tested on each board.

## Why

There are good bootloaders already: Optiboot on AVR, the UF2 bootloaders on SAM D and
nRF52, MCUboot for Zephyr, the ROM loaders chips ship with. Each is one fixed design for
one family. If you want something it doesn't do, you end up patching it.

MimiBoot-Mu goes the other way. Every feature is a build option, the same options exist
on every chip that can support them, and turning one off removes its code. The smallest
build on an Uno is under 1 KB and only starts the app. A big one on an STM32 or nRF52
does signed A/B updates with rollback, a boot menu, uploads over a serial console or
mcumgr, and lets the running OS reboot, power off, roll back or pick its next boot,
in 30 to 50 KB. Most setups sit in between, and you move between them by flipping
options instead of switching bootloaders.

It's built for prototyping and for fiddling with: convenient first, and easy to bend.

## What it can do

On the 32-bit chips (the full core, codename Komorebi):

- **Slots**: one image, an A/B pair, or A/B plus a golden recovery image, plus extra
  slots for things you boot on purpose.
- **Safe updates**: new images get a few trial boots and roll back if the app never
  confirms itself, or are trusted once they check out, for firmware that knows nothing
  about MimiBoot. A crash-loop guard and a watchdog during trials.
- **Checks**: SHA-256 on every boot, on the first boot only, or never.
- **Signatures**: Ed25519, ECDSA P-256 and LMS (hash-based, post-quantum, RFC 8554), in
  any mix, optionally refusing anything unsigned. Anti-rollback floors, key revocation,
  a signed boot config.
- **Image formats**: MimiBoot's own, Zephyr / MCUboot images signed with imgtool, and
  plain binaries (FreeRTOS, bare metal, Arduino). Encrypted images in MCUboot's scheme.
  Images that run from RAM.
- **Console**: on a UART or USB, with a boot menu, a command line, uploads with
  `mbtool install`, mcumgr (SMP), and a boot config file with GRUB-style entries. It can
  be locked behind a signed unlock.
- **OS hooks**: the running OS learns how it was started and how the previous run ended
  (a reboot, an update, a panic with its message and address, the watchdog). It can ask
  for its next boot (the menu, another entry or slot, flash mode, the ROM loader) without
  writing flash, reboot with a reason, report a crash, roll back, or power off. `mbctl`
  puts all of it into your app's own shell, the way `bootctl` and `grub-reboot` do on
  Linux. See [docs/OS-INTEGRATION.md](docs/OS-INTEGRATION.md).
- **Lock-down**: write-protect the bootloader before the app starts and keep the debug
  port shut (nRF), wipe the bootloader's RAM before the jump, a measured-boot record for
  the app. `mbtool provision` prints the fuse and option-byte steps for each chip. What
  holds against whom is in [docs/SECURITY.md](docs/SECURITY.md).
- **Updating itself**: a two-stage build has a small fixed stage 0 and two copies of the
  rest, so a bootloader update can't brick the board.

On AVR (the Lite core, 1 to 2 KB):

- STK500 uploads, so the Arduino IDE and avrdude work unchanged.
- A CRC-32 check of the app on every boot, trial boots, and a flash-write service apps
  can use to stage an update that the bootloader installs.

[docs/OPTIONS.md](docs/OPTIONS.md) lists every option and what it costs in flash.

## Boards

| Family | Boards |
|---|---|
| RP2040, RP2350 | Raspberry Pi Pico, Pico 2 (Arm or RISC-V), Waveshare RP2350-LCD |
| STM32 F0, F1, F2, F3, F4, F7, L4, G0, G4 | Nucleo boards, Blue Pill, Black Pill F401/F411, F4 Discovery |
| nRF51822, nRF52832/833/840/810/811/820 | Nordic DKs, Feather nRF52840, XIAO nRF52840, Nano 33 BLE, micro:bit v1/v2 |
| SAM D21, SAM D51 | Arduino Zero, MKR boards, Feather M0/M4, Trinket M0, XIAO SAMD21, Wio Terminal |
| ATmega328P, 168, 644P, 1284P, 2560 | Uno, Nano, Pro Mini, Mega and friends |

54 boards in all. A board for a chip that's already supported is a few lines in
`config/targets.toml`. What ran where is in
[docs/HARDWARE-STATUS.md](docs/HARDWARE-STATUS.md).

## Getting started

You need Python 3.11+ and the toolchain for your chip: the Arm GNU Toolchain for STM32,
nRF and SAM D, avr-gcc (the one the Arduino IDE installs is fine), or the Pico SDK for RP
boards. `python muconfigurator.py toolchains` shows what it found. On Windows the menu
also needs `pip install windows-curses`.

```
python muconfigurator.py              # pick a board, change options, build
python muconfigurator.py build        # build the current .config
```

The home screen says what your configuration does, lists what you changed from the
board's defaults, and shows anything wrong (Enter on it goes to the fix). A gauge under
the title shows how much of the bootloader's flash it takes. `u` undoes, `d` puts an
option back to its default, `/` finds options or boards as you type.

Without the menu:

```
python muconfigurator.py defconfig nucleo-f411re
python muconfigurator.py preset hobby          # minimal / hobby / product / secure
python muconfigurator.py set IMG_MCUBOOT=y BOOT_VERIFY=once
python muconfigurator.py build
```

Builds land in `~/MimiBoot/<board>/` unless you set another folder. With the binary you
get a flash map that says where to link your app, linker snippets, a Zephyr partition
overlay, the list of files your app needs for the client library, and on AVR the fuse
value and a `boards.txt` entry. It can also export the exact sources it compiled, with a
Makefile.

Then read [before you flash](https://milkmaidabi.github.io/MimiBoot-Mu-Docs/before-you-flash.html).

## Tests

```
python tests/run.py                              # the core on the host
python tests/test_profiles.py                    # the core with features switched off
python tests/test_muconfigurator.py --build-all  # the configurator; every board compiles
python tests/qemu/test_qemu.py                   # STM32 and nRF51 in QEMU
python tests/test_sim_flash.py                   # SAM D flash driver against a model
python tests/avr/test_avr.py                     # AVR in simavr with avrdude (Linux/WSL)
python tests/fuzz/run_fuzz.py                    # libFuzzer on the input parsers (Linux)
```

CI runs these on every push.

## Source layout

```
muconfigurator.py   MuConfigurator: menu, command line, builder
config/             features.toml (the options), targets.toml (chips and boards)
tools/mu/           MuConfigurator's code
tools/mbtool.py     pack, sign, encrypt and upload images; keys; provisioning
core/               the full core (Komorebi)
port/               RP2040/RP2350 (Pico SDK), Cortex-M, and the STM32 / nRF / SAM D parts
lite/               the AVR core
client/             the app library and mbctl
docs/               test status, security, OS integration, options, Zephyr / FreeRTOS
```

## History

> This proj goes all the way back to like Dec 2025 or smth iirc, kinda lost the git
>  history because I deleted the repo during a iffy moment of bad mental health
> Some stuff was like poorly reimplemented and all. tryna recreate it.

## License

MIT. The STK500 code was written from Atmel's AVR061 application note. The ECDSA
arithmetic is micro-ecc (BSD 2-clause, `third_party/micro-ecc`). The USB console uses
TinyUSB 0.21.0 (MIT, `third_party/tinyusb`), Arm's CMSIS 6.4.0 core headers
(Apache-2.0, `third_party/cmsis`) and Microchip's SAM D USB and NVMCTRL register headers
(Apache-2.0, `third_party/microchip`), all unmodified, with their licence files next to
them. The AES in `core/mb_enc.c` is adapted from BearSSL's constant-time implementation
(MIT, Thomas Pornin; the notice is in the file).
