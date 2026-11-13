# MimiBoot-Mu

> TUI is damn ugly rn, Imma try to fix it soon? Idk, I can't make good UI. Sowwy OwO

MimiBoot-Mu is a bootloader for microcontrollers, from small to big bois: RP2040 and RP2350, STM32,
Nordic nRF51/nRF52, Microchip SAM D21/D51, and classic AVRs like the ATmega328P on
an Arduino Uno.

You configure it the way you'd configure a Linux kernel. `python mimiconf.py` opens a
menu, you pick your board and switch features on or off, and the build only contains
what you picked. Change your mind later, rerun it, rebuild.

Documentation: https://milkmaidabi.github.io/MimiBoot-Mu-Docs/

## Why another bootloader - Because duh, this proj is dumb?

There are good bootloaders around already. Optiboot on AVR, UF2 bootloaders on SAMD
and nRF52, MCUboot for Zephyr, the ROM loaders the chips ship with. Each of them is one
fixed design for one family, and if you want something they don't do - you kinda need to make
hooks and all, add modules. 

MimiBoot-Mu takes the opposite approach. Every feature is a build option, the same
options exist on every chip that can support them, and turning one off removes its code.
The smallest build on an Uno is under 1 KB and only starts the app. The biggest one on
an STM32 or nRF52 does signed A/B updates with rollback, a boot menu, uploads over the
console and an API for the running OS, in about 34 KB. Most real setups sit somewhere in
between, and you can move between them by flipping options instead of switching
bootloaders.

MimiBoot-Mu is literally no kidding meant to be customisable and an un-serious project.
Just idk, do stuff I guess? Makes it easy for rapid prototyping and all. Built to be 
fucked around with. A dumb project - better solutions exist. MimiBoot is a WORSE solution
that's convenient... because yes. I have no real justification.

## What it does / can do

On the 32-bit chips (the "full" core):

- Hold one image, an A/B pair, or A/B plus a golden recovery image, plus a few extra slots.
- Try new A/B images for a few boots and roll back if the app never confirms itself. Or
  skip that and trust a new image once it checks out, for firmware that knows nothing
  about MimiBoot.
- Check images with SHA-256 on every boot, only on their first boot, or not at all.
- Verify Ed25519 signatures, optionally refusing anything unsigned. Anti-rollback with a
  security version floor.
- Boot MimiBoot's own image format, Zephyr / MCUboot images signed with imgtool, and
  plain firmware binaries (FreeRTOS, bare metal, Arduino builds).
- Run images from RAM on chips that need it (RP2040) or when you want to try something
  without flashing it.
- A console on USB (RP) or a UART: boot menu with a countdown, a command line, uploads with
  `mbtool install`, a small boot config file with GRUB-style entries.
- Pass a handoff block to the started image (which slot, which entry, its arguments, why
  the chip reset) and take requests back from it ("reboot into the menu", "boot the
  other slot once").
- Wipe its own RAM before jumping, so the app starts with nothing of the bootloader left.
- A crash-loop guard and a watchdog during trial boots.

On AVR (the "lite" core, 1 to 2 KB):

- STK500 uploads, so the Arduino IDE and avrdude work unchanged.
- A CRC-32 check of the app on every boot.
- Apps can reboot into the bootloader, confirm a trial build, write their own flash
  through a small service, and stage an update that the bootloader installs.

All of it is optional. `docs/OPTIONS.md` lists every option with what it costs in flash.

## Supported boards - (Most untested. I kinda prioritised these because these are the ones I use. Easy to expand)

| Family | Boards |
|---|---|
| RP2040, RP2350 | Raspberry Pi Pico, Pico 2 (Arm or RISC-V), Waveshare RP2350-LCD |
| STM32 F0, F1, F2, F3, F4, F7, L4, G0, G4 | Nucleo boards, Blue Pill, Black Pill F401/F411, F4 Discovery |
| nRF52832/833/840/810/811/820, nRF51822 | Nordic DKs, Feather nRF52840, XIAO nRF52840, Nano 33 BLE, micro:bit v1/v2 |
| SAM D21, SAM D51 | Arduino Zero, MKR boards, Feather M0/M4, Trinket M0, XIAO SAMD21, Wio Terminal |
| ATmega328P, 168, 644P, 1284P, 2560 | Uno, Nano, Pro Mini, Mega and friends |

Adding a board for a chip that's already supported is a few lines in `config/targets.toml`.

How much of this has run on real hardware is written down in
[docs/HARDWARE-STATUS.md](docs/HARDWARE-STATUS.md). Short version: earlier builds of the
RP2040/RP2350 ports have run on boards; the rest has run in emulators (QEMU, simavr) or
only been compiled.
Read it before you flash something you can't easily recover. (Please, get SWD AND hardware debuggers ready if you wanna
test the NRF/ SAM D stuff - the code has been audited but just take caution...)

## Getting started

Need Python 3.11+ and the toolchain for your chip: the Arm GNU Toolchain for STM32,
nRF and SAMD, avr-gcc (the one the Arduino IDE installs is fine), or the Pico SDK for
RP boards. `python mimiconf.py toolchains` shows what it found.

```
python mimiconf.py              # pick a board, change options, build
python mimiconf.py build        # build the current .config
```

Or without the menu (just use the menu, it's easier):

```
python mimiconf.py defconfig nucleo-f411re
python mimiconf.py preset hobby          # minimal / hobby / product / secure
python mimiconf.py set IMG_MCUBOOT=y BOOT_VERIFY=once
python mimiconf.py build
```

Builds land in `~/MimiBoot/<board>/` unless you set another folder. Along with the
binary you get a flash map that tells you where to link your app, linker snippets, a
Zephyr partition overlay, and on AVR the fuse value and a `boards.txt` entry. You can
also have it export the exact sources it compiled, with a Makefile.

On Windows the menu needs `pip install windows-curses`. Everything also works from the
command line.

## Tests

```
python tests/run.py                       # core logic on the host
python tests/test_profiles.py             # the core with features switched off
python tests/test_mimiconf.py --build-all # configurator, every board compiles
python tests/qemu/test_qemu.py            # STM32 and nRF51 in QEMU
python tests/test_sim_flash.py            # SAM D flash driver against a model
python tests/avr/test_avr.py              # AVR in simavr with avrdude (Linux/WSL)
```

## Source layout - For roguh ref

```
mimiconf.py         configurator and builder
config/             features.toml (the options), targets.toml (chips and boards)
tools/mu/           the configurator's code
tools/mbtool.py     pack, sign and upload images
core/               the full core
port/               RP2040/RP2350 (Pico SDK), Cortex-M, and the STM32 / nRF / SAMD parts
lite/               the AVR core
client/             libraries for apps
docs/               test status, option reference, Zephyr / FreeRTOS notes
```

## License

MIT. The STK500 code was written from Atmel's AVR061 application note.

(I doubt people will even ever see this proj, so Imma just anyhow put MIT lol)
