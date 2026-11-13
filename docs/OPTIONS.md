# MimiBoot-Mu options

Generated from `config/features.toml` by `python mimiconf.py docs`; don't edit by hand.
Set options in the TUI (`python mimiconf.py`) or with `python mimiconf.py set ID=value`.

**Cost** is the flash a feature adds when it is on, measured by building a reference board with its defaults and again with that one option flipped: nucleo-f411re (mcu, default build 33.3 KB), uno (avr, default build 1.6 KB). Other chips differ a little (Cortex-M0 code is larger).

## Presets

| preset | what you get |
|---|---|
| `minimal` | **Minimal: just boot the app**. The smallest bootloader that still checks what it starts. No console, no uploads, one slot, no OS hooks. Flash it, link your firmware for the slot, done. |
| `hobby` | **Hobby: console, uploads, no ceremony**. Everything handy on the bench: boot menu, command line with diagnostics, uploads over the console, A/B slots without trials (new images just boot), Zephyr and raw firmware accepted. No signatures. |
| `product` | **Product: safe field updates**. A/B + golden recovery, updates must confirm or roll back, watchdog on trial boots, crash-loop guard, anti-rollback, OS hooks. Signatures are checked when present. Diagnostics off. |
| `secure` | **Secure boot: signed images only**. Only images signed with your keys start (set KEYS: mbtool keygen). Hash on every boot, anti-rollback, no raw/RAM images, no diagnostics, the bootloader's RAM is wiped before the handover. |

`python mimiconf.py preset <name>` (or Presets in the TUI): every option back to its default, then the preset's values. On small chips a preset doesn't turn back on what the chip's defaults trim to fit.

## Slots and updates

How many images the board holds and what happens when a new one arrives: A/B pairs, a golden recovery image, trial boots that must be confirmed, rollback, the crash-loop guard.

### `LAYOUT`: Slots: single / A-B / A-B + golden

default **ab**; ab+golden on RP; one of `single`, `ab`, `ab+golden`. (full core; builds: STM32/nRF/SAMD)

single: one slot, no A/B at all. The smallest setup: a new image simply replaces the old one.

ab: two slots; an update goes to the slot that isn't running, so a bad one can be rolled back.

ab+golden: A/B plus a recovery image that is only ever replaced by a newer version.

(RP boards use fixed presets with A/B + golden.)

### `AUX_SLOTS`: Extra (aux) slots

default **0**; 0..3; needs `LAYOUT=ab+golden`. (full core; builds: STM32/nRF/SAMD)

More images to boot from menu/config entries: a test build, a second OS, a factory-test firmware.

### `AB_TRIAL`: Updates must confirm (trial boots + automatic rollback)

default **on**; off on STM32/nRF/SAMD; needs `LAYOUT!=single`; cost ~16 B on nucleo-f411re. (full core)

A new A/B image gets a few boots to call mb_client_confirm(); if it doesn't, the bootloader goes back to the previous good image.

Off: new images are trusted once their checks pass (right for stock Zephyr, FreeRTOS, Arduino firmware that knows nothing about MimiBoot).

Off by default on bare-metal MCUs. The console's 'confirm' command confirms by hand.

C macro: `MB_FEAT_AB_TRIAL`

### `TRIES`: Trial boots before rollback

default **3**; 1..20; needs `AB_TRIAL`. (full core)

How many times an unconfirmed update is started before it is marked bad.

C macro: `MB_DEFAULT_TRIES`

### `TRIAL_WATCHDOG`: Watchdog during trial boots

default **on**; off on STM32/nRF/SAMD; needs `AB_TRIAL`. (full core)

Arm the watchdog before starting a trial image, so a hang also counts as a failed try.

STM32 and nRF: the watchdog can't be stopped once started, so the app must keep refreshing it forever. Off by default on bare-metal MCUs.

C macro: `MB_FEAT_TRIAL_WATCHDOG`

### `TRIAL_MS`: Trial watchdog timeout (ms)

default **15000**; 1000..30000; needs `TRIAL_WATCHDOG`. (full core)

Images can override it in their header (mbtool pack --trial-ms).

C macro: `MB_DEFAULT_TRIAL_MS`

### `CRASH_GUARD`: Crash-loop guard

default **on**; needs `LAYOUT!=single`; cost ~112 B on nucleo-f411re. (full core)

After several watchdog resets in a row of a confirmed image, boot the other good image (or golden) instead. Needs somewhere to fall back to, so not with a single slot.

C macro: `MB_FEAT_CRASH_GUARD`

### `ANTI_ROLLBACK`: Anti-rollback (security version floor)

default **on**; cost ~32 B on nucleo-f411re. (full core)

Once an image with security version N is confirmed, A/B images below N are refused, so nobody can reinstall an old vulnerable build.

C macro: `MB_FEAT_ANTI_ROLLBACK`

## Image formats

What a slot may contain: MimiBoot's own images, Zephyr / MCUboot images, plain firmware binaries, images that run from RAM.

### `IMG_NATIVE`: MimiBoot images (mbtool pack)

default **on**. (full core)

The MIMG header: name, version, SHA-256, optional Ed25519 signature, anti-rollback counter, handoff address. The full-featured format.

C macro: `MB_FEAT_IMG_NATIVE`

### `IMG_MCUBOOT`: Zephyr / MCUboot images (imgtool, west sign)

default **off**; cost ~792 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD, RP2040/RP2350)

Boot images in MCUboot format: what Zephyr builds with CONFIG_BOOTLOADER_MCUBOOT=y and signs with imgtool / west sign.

The SHA-256 TLV is checked like any image hash; an ED25519 TLV is checked against the build's keys (sign with: imgtool keygen -t ed25519).

mimiconf writes a devicetree overlay (zephyr-partitions.overlay) so the Zephyr app links at the right slot.

Not supported: encrypted images, 'pure' signatures, MCUboot swap trailers (use the MimiBoot client to confirm, or turn off 'Updates must confirm').

C macro: `MB_FEAT_IMG_MCUBOOT`

### `IMG_RAW`: Raw firmware (FreeRTOS, bare metal, Arduino .bin)

default **off**; cost ~356 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

Boot a plain .bin whose vector table sits at the very start of a slot (link the firmware at the slot address).

No metadata means no integrity check: the bootloader only sanity-checks the stack pointer and reset vector.

Prefer wrapping it (mbtool pack, link at slot + 0x1000) when you can.

C macro: `MB_FEAT_IMG_RAW`

### `RAM_IMAGES`: RAM images

default **on**; cost ~432 B on nucleo-f411re. (full core)

Images that are copied to RAM, checked there and started there, and the console's 'ramboot' (try an image without touching flash). The RP2040 port needs this (it can't remap XIP slots).

C macro: `MB_FEAT_RAM_IMAGES`

## Checks and security

What the bootloader checks before it starts an image: the payload hash (every boot, once, or never), Ed25519 signatures, the trusted keys.

### `BOOT_VERIFY`: Check the image hash: every boot / once / never

default **every-boot**; one of `every-boot`, `once`, `never`; `once` +48 B on nucleo-f411re. (full core)

every-boot: SHA-256 of the whole payload before every start (catches flash corruption; roughly 10-100 ms per 100 KB at reset clocks).

once: the first boot of a new image hashes it and records that in the boot log; later boots only check the header. Faster boots; corruption that happens later goes unnoticed.

never: header checks only. Images uploaded through MimiBoot (mbtool, the client library) are still hashed before their header is written; images written with a debugger are never checked. Fastest; for when something else guarantees the flash.

'Refuse unsigned images' needs every-boot.

C macro: `MB_BOOT_VERIFY`

### `SIGNATURES`: Ed25519 signatures

default **on**; cost ~5.4 KB on nucleo-f411re. (full core)

Verify image signatures against the public keys compiled in (KEYS). About 6 KB of code; checks take ~100-500 ms on a Cortex-M at reset clocks.

C macro: `MB_FEAT_SIGNATURES`

### `REQUIRE_SIGNATURE`: Refuse unsigned images (secure boot)

default **off**; needs `SIGNATURES`. (full core)

Only images signed by one of KEYS boot. Needs KEYS, and the hash on every boot.

C macro: `MB_REQUIRE_SIGNATURE`

### `KEYS`: Trusted public keys file

default ****; needs `SIGNATURES`. (full core)

A text file with one Ed25519 public key per line (64 hex digits): mbtool keygen writes keys/mimiboot.pub. Enter a path; quotes are fine.

## Console, menu and upload

The text console on USB (RP) or a UART: boot menu, command line, diagnostic commands, image upload with mbtool, the boot config file.

### `CONSOLE`: Console with boot menu

default **on**; cost ~14.5 KB on nucleo-f411re. (full core)

USB (RP) or UART (STM32, nRF, SAMD) text console with the boot menu. Without it, a board with nothing bootable falls back to the chip's ROM loader (RP, STM32; nRF and SAMD have none and wait for a debugger).

C macro: `MB_FEAT_CONSOLE`

### `SHELL`: Command line (ls, boot, confirm, recv, erase, cfg ...)

default **on**; needs `CONSOLE`; cost ~11.7 KB on nucleo-f411re. (full core)

The console's command line ('c' in the menu). Off: the menu alone (pick an entry, edit its args, reboot). Uploads need it.

C macro: `MB_FEAT_SHELL`

### `SHELL_DIAG`: Diagnostic commands (md memory dump, sha, log, layout, keys)

default **on**; needs `SHELL`; cost ~2.1 KB on nucleo-f411re. (full core)

Handy on the bench. Turn off for products: 'md' reads any flash or RAM the bootloader can see.

C macro: `MB_FEAT_SHELL_DIAG`

### `RECV`: Image upload over the console (mbtool install / ota / ramboot)

default **on**; needs `SHELL`; cost ~1.2 KB on nucleo-f411re. (full core)

Receive images in CRC-checked frames and write them to a slot.

C macro: `MB_FEAT_RECV`

### `CFG_FILE`: Boot config file in flash (entries, args, default, timeout)

default **on**; off on STM32/nRF/SAMD. (full core)

A small GRUB-ish text config kept in two flash sectors (atomic updates). Without it the built-in entries apply: os (A/B), recovery (golden), one per aux slot.

Off by default on bare-metal MCUs: on STM32F2/F4/F7 it costs two extra erase sectors (64-128 KB each); elsewhere 8-16 KB.

C macro: `MB_FEAT_CFG_FILE`

### `GRUB`: GRUB-style menuentry syntax

default **on**; needs `CFG_FILE`. (full core)

C macro: `MB_FEAT_GRUB`

### `MENU_SECS`: Boot menu countdown (s)

default **10**; 1..600; needs `CONSOLE`. (full core)

How long the menu waits before booting the default entry, unless the config file says otherwise.

C macro: `MB_MENU_SECS`

### `BREAK_IN_MS`: UART break-in window after reset (ms)

default **300**; 0..5000; needs `CONSOLE`. (full core; builds: STM32/nRF/SAMD)

Any key on the console UART within this window opens the menu (like U-Boot's autoboot delay). 0: only the button / OS requests open it, and boots don't wait at all.

C macro: `MB_BREAK_IN_MS`

## Handoff and OS hooks

What the started image gets from the bootloader and how a running OS can talk back: the handoff block, reboot requests, wiping the bootloader's RAM before the handover.

### `HANDOFF`: Boot handoff (slot, entry, args, reset cause -> the image's RAM)

default **on**; cost ~368 B on nucleo-f411re. (full core)

A checksummed block the image finds at the address its header names: which slot and entry it was started from, the args, why the chip reset.

C macro: `MB_FEAT_HANDOFF`

### `CONTROL`: OS control service (reboot into menu / entry / slot / flash mode)

default **on**; cost ~608 B on nucleo-f411re. (full core)

Lets a running OS queue a versioned request (mb_client_request) that the bootloader consumes on the next boot.

C macro: `MB_FEAT_CONTROL`

### `SCRUB_RAM`: Wipe the bootloader's RAM before handing over

default **off**; cost ~32 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

On the way out the bootloader zeroes its own RAM region (its data, boot log copy, config text, stack) from registers only, then jumps: the image starts with nothing of the bootloader left in RAM. The handoff block lives in the image's RAM and survives. Costs a few microseconds.

C macro: `MB_FEAT_SCRUB_RAM`

## Board hardware

Console speed and whether the bootloader uses the board's LED and button.

### `BAUD`: Console / upload baud rate

default **115200**; 9600..1000000. (builds: STM32/nRF/SAMD, AVR)

C macro: `MB_UART_BAUD`

### `BOARD_LED`: Use the board LED (lit while the bootloader waits for a key)

default **on**; cost ~64 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

Off: the bootloader never touches the LED pin.

C macro: `MB_FEAT_LED`

### `BOARD_BUTTON`: Board button opens the menu

default **on**; cost ~112 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

Off: the bootloader never reads the button pin (the UART break-in and OS requests still work).

C macro: `MB_FEAT_BUTTON`

## Bootloader region

How much flash the bootloader keeps for itself; the slots start after it. `Show the flash map` on the home screen shows the result.

### `BOOT_SIZE`: Bootloader region size (chip / auto / e.g. 32K)

default **chip**. (full core; builds: STM32/nRF/SAMD)

chip: the chip's default from targets.toml (stable slot addresses across rebuilds).

auto: the smallest sector-aligned region the build fits in (slot addresses change when features change, so apps must be relinked).

32K / 48K ...: a fixed size.

## AVR bootloader (Lite core)

The small AVR core: STK500 uploads (Arduino IDE / avrdude), an app check, app requests, trial boots, a flash-write service, staged updates.

### `STK500`: Serial upload (STK500v1: avrdude -c arduino, Arduino IDE)

default **on**; cost ~1012 B on uno. (AVR Lite)

Speaks the protocol of Arduino's own bootloader, so the IDE / avrdude upload unchanged.

C macro: `MU_FEAT_STK500`

### `EEPROM_RW`: EEPROM read/write over STK500 (avrdude -U eeprom:...)

default **on**; needs `STK500`; cost ~60 B on uno. (AVR Lite)

C macro: `MU_FEAT_EEPROM`

### `ENTRY`: When to listen for an upload

default **reset-pin**; one of `reset-pin`, `every-reset`; needs `STK500`. (AVR Lite)

reset-pin: only after an external reset (reset button, or the IDE pulsing DTR). Power-on and watchdog resets start the app at once.

every-reset: every reset waits the timeout first.

C macro: `MU_ENTRY`

### `TIMEOUT_MS`: Upload wait (ms, a watchdog period)

default **1000**; one of `250`, `500`, `1000`, `2000`, `4000`, `8000`; needs `STK500`. (AVR Lite)

C macro: `MU_TIMEOUT_MS`

### `VERIFY`: Check the app before starting it

default **crc32**; one of `none`, `crc32`; `none` -466 B on uno. (AVR Lite)

crc32: at the end of every upload the bootloader records the app's length and CRC-32 (top of EEPROM) and checks them on every boot; a damaged app is not started (the loader waits for an upload instead).

Apps flashed some other way (ISP) have no record and start as before.

none: no check, smallest build.

C macro: `MU_VERIFY`

### `NOAPP_STAY`: No (valid) app: stay in the bootloader

default **on**; needs `STK500`; cost ~-72 B on uno. (AVR Lite)

C macro: `MU_FEAT_NOAPP_STAY`

### `APP_REQUEST`: Apps can reboot into the bootloader (mu_enter_bootloader())

default **on**; needs `STK500`; cost ~20 B on uno. (AVR Lite)

C macro: `MU_FEAT_APP_REQUEST`

### `LITE_HANDOFF`: Boot handoff (reset cause in r2 + GPIOR0-2)

default **on**. (AVR Lite)

MCUSR in r2 (Optiboot convention) and MimiBoot flags in GPIOR0..2; read with mu_handoff().

C macro: `MU_FEAT_HANDOFF`

### `LITE_TRIAL`: Trial boots: a new upload must call mu_confirm()

default **off**; needs `VERIFY=crc32`; cost ~78 B on uno. (AVR Lite)

After an upload the app runs under the watchdog; if it resets MU_TRIAL_TRIES times without calling mu_confirm(), the bootloader stops starting it and waits for a new upload.

Off by default: ordinary sketches never confirm.

C macro: `MU_FEAT_TRIAL`

### `LITE_TRIES`: Trial boots before giving up

default **3**; 1..15; needs `LITE_TRIAL`. (AVR Lite)

C macro: `MU_TRIAL_TRIES`

### `SPM_API`: Flash-write service for apps (mu_spm(): OTA, data in flash)

default **off**; cost ~96 B on uno. (AVR Lite)

A fixed jump table at the end of flash: apps call the bootloader's SPM routine to erase/write their own flash pages (AVR only allows SPM from the boot section).

C macro: `MU_FEAT_SPM_API`

### `STAGED_UPDATE`: Staged updates (app writes a new image to upper flash, bootloader installs it)

default **off**; needs `SPM_API`, `VERIFY=crc32`. (AVR Lite)

The running app stores a new image in the top half of the app area (mu_spm), then calls mu_stage_commit(len, crc32) and reboots.

The bootloader checks the CRC, copies it over the app (resumes after a power cut) and records it.

C macro: `MU_FEAT_STAGED`

### `LED`: Blink the board LED while the bootloader listens

default **on**; cost ~18 B on uno. (AVR Lite)

C macro: `MU_FEAT_LED`

## Build output

Where `Build` puts the results, and whether to also export a self-contained source tree you can build without mimiconf.

### `OUTPUT_DIR`: Output folder (each board gets a subfolder)

default **~/MimiBoot**.

Where builds go: <folder>/<board>/. The default is MimiBoot in your home folder.

Type any path, with or without quotes ("D:/firmware/boot" or ~/projects/boot). `mimiconf.py build -o DIR` overrides it for one build.

### `EXPORT_SOURCE`: Also export the configured source tree (with a Makefile)

default **off**.

Copies exactly the sources this configuration compiles, the generated config header and linker script, and a Makefile into <output>/source/, so the bootloader can be rebuilt (or audited) without mimiconf. RP boards get the CMake project and the build command instead.
