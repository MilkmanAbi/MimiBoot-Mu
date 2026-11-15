# MimiBoot-Mu options

Generated from `config/features.toml` by `python muconfigurator.py docs`; don't edit by hand.
Set options in the TUI (`python muconfigurator.py`) or with `python muconfigurator.py set ID=value`.

**Cost** is the flash a feature adds when it is on, measured by building a reference board with its defaults and again with that one option flipped: nucleo-f411re (mcu, default build 38.6 KB), uno (avr, default build 1.6 KB). Other chips differ a little (Cortex-M0 code is larger).

## Presets

| preset | what you get |
|---|---|
| `minimal` | **Minimal: just boot the app**. The smallest bootloader that still checks what it starts. No console, no uploads, one slot, no OS hooks. Flash it, link your firmware for the slot, done. |
| `hobby` | **Hobby: console, uploads, no ceremony**. Everything handy on the bench: boot menu, command line with diagnostics, uploads over the console, A/B slots without trials (new images just boot), Zephyr and raw firmware accepted. No signatures. |
| `product` | **Product: safe field updates**. A/B + golden recovery, updates must confirm or roll back, watchdog on trial boots, crash-loop guard, anti-rollback, OS hooks. Signatures are checked when present. Diagnostics off. |
| `secure` | **Secure boot: signed images only**. Only images signed with your keys start (set KEYS: mbtool keygen). Hash on every boot, anti-rollback, no raw/RAM images, no diagnostics, the bootloader's RAM is wiped before the handover. Where the chip can (nRF), the bootloader's flash is locked before an image starts and the rollback floors are kept in the locked region. Console commands that change anything need a signed unlock (mbtool --unlock-key). The debug port is left alone: close it (DEBUG_LOCK, or mbtool provision) once the product is final. |

`python muconfigurator.py preset <name>` (or Presets in the TUI): every option back to its default, then the preset's values. On small chips a preset doesn't turn back on what the chip's defaults trim to fit.

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

default **on**; off on STM32/nRF/SAMD; needs `LAYOUT!=single`. (full core)

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

default **on**; needs `LAYOUT!=single`; cost ~160 B on nucleo-f411re. (full core)

After several watchdog resets in a row of a confirmed image, boot the other good image (or golden) instead. Needs somewhere to fall back to, so not with a single slot.

C macro: `MB_FEAT_CRASH_GUARD`

### `ANTI_ROLLBACK`: Anti-rollback (security version floor)

default **on**; cost ~284 B on nucleo-f411re. (full core)

Once an image with security version N is confirmed, A/B images below N are refused, so nobody can reinstall an old vulnerable build.

C macro: `MB_FEAT_ANTI_ROLLBACK`

## Image formats

What a slot may contain: MimiBoot's own images, Zephyr / MCUboot images, plain firmware binaries, images that run from RAM.

### `IMG_NATIVE`: MimiBoot images (mbtool pack)

default **on**. (full core)

The MIMG header: name, version, SHA-256, optional Ed25519 signature, anti-rollback counter, handoff address. The full-featured format.

C macro: `MB_FEAT_IMG_NATIVE`

### `IMG_MCUBOOT`: Zephyr / MCUboot images (imgtool, west sign)

default **off**; cost ~1.2 KB on nucleo-f411re. (full core; builds: STM32/nRF/SAMD, RP2040/RP2350)

Boot images in MCUboot format: what Zephyr builds with CONFIG_BOOTLOADER_MCUBOOT=y and signs with imgtool / west sign.

The SHA-256 TLV is checked like any image hash; an ED25519 TLV is checked against the build's keys (sign with: imgtool keygen -t ed25519).

MuConfigurator writes a devicetree overlay (zephyr-partitions.overlay) so the Zephyr app links at the right slot.

A Zephyr app confirms itself MCUboot's way (boot_write_img_confirmed(), the image_ok flag in the slot's trailer): MimiBoot honours that. Not supported: encrypted images, 'pure' signatures, MCUboot swap modes, mcumgr uploads.

C macro: `MB_FEAT_IMG_MCUBOOT`

### `IMG_RAW`: Raw firmware (FreeRTOS, bare metal, Arduino .bin)

default **off**; cost ~340 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

Boot a plain .bin whose vector table sits at the very start of a slot (link the firmware at the slot address).

No metadata means no integrity check: the bootloader only sanity-checks the stack pointer and reset vector.

Prefer wrapping it (mbtool pack, link at slot + 0x1000) when you can.

C macro: `MB_FEAT_IMG_RAW`

### `RAM_IMAGES`: RAM images

default **on**; cost ~544 B on nucleo-f411re. (full core)

Images that are copied to RAM, checked there and started there, and the console's 'ramboot' (try an image without touching flash). The RP2040 port needs this (it can't remap XIP slots).

C macro: `MB_FEAT_RAM_IMAGES`

## Checks and security

What the bootloader checks before it starts an image: the payload hash (every boot, once, or never), Ed25519 signatures, the trusted keys.

### `BOOT_VERIFY`: Check the image hash: every boot / once / never

default **every-boot**; one of `every-boot`, `once`, `never`; `once` -96 B on nucleo-f411re; `never` -136 B on nucleo-f411re. (full core)

every-boot: SHA-256 of the whole payload before every start (catches flash corruption; roughly 10-100 ms per 100 KB at reset clocks).

once: the first boot of a new image hashes it and records that in the boot log; later boots only check the header. Faster boots; corruption that happens later goes unnoticed.

never: header checks only. Images uploaded through MimiBoot (mbtool, the client library) are still hashed before their header is written; images written with a debugger are never checked. Fastest; for when something else guarantees the flash.

'Refuse unsigned images' needs every-boot.

C macro: `MB_BOOT_VERIFY`

### `SIGNATURES`: Ed25519 signatures

default **on**; cost ~5.5 KB on nucleo-f411re. (full core)

Verify image signatures against the public keys compiled in (KEYS). About 6 KB of code; checks take ~100-500 ms on a Cortex-M at reset clocks.

C macro: `MB_FEAT_SIGNATURES`

### `ECDSA`: ECDSA P-256 signatures as well

default **off**; needs `SIGNATURES`; cost ~3.7 KB on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

Also accept images signed with ECDSA P-256: MimiBoot images signed with a P-256 key (mbtool keygen --type p256, then pack --key) and Zephyr/MCUboot images signed by imgtool with an ecdsa-p256 key (the ECDSA_SIG TLV). P-256 is on the EU's agreed-mechanisms list; Ed25519 isn't (it is recommended by ETSI TS 119 312).

Put the P-256 public keys (128 hex digits) in the KEYS file next to any Ed25519 ones. The arithmetic is micro-ecc v1.2 (BSD), about 5 KB; a check takes longer than Ed25519 on the small cores.

C macro: `MB_FEAT_ECDSA`

### `LMS`: LMS signatures (hash-based, post-quantum)

default **off**; cost ~1.9 KB on nucleo-f411re. (full core)

Accept images signed with LMS (RFC 8554, NIST SP 800-208): a signature scheme built on SHA-256 alone, so a quantum computer doesn't break it. CNSA 2.0 names it for firmware signing, and the EU's agreed-mechanisms list has it. Keys: 'mbtool keygen --type lms' (1024 signatures with the default H10, then a new key is needed); put the public key in the KEYS file, Ed25519 off if you want nothing a quantum computer could forge.

LMS keys are stateful: each signature uses up one of the key's one-time keys. mbtool keeps count in the key file and saves it before a signature leaves; never copy that file or sign from two machines with it. The board side only verifies: about 2 KB of code (no Ed25519 needed), no extra RAM at boot (the signature is read from flash as it is checked), plus one signature-sized buffer (1.3-3 KB) for uploads. A check is ~600 SHA-256 blocks with W4 keys (the default), ~4400 with W8. Console unlock, signed configs and revocation statements stay Ed25519.

C macro: `MB_FEAT_LMS`

### `REQUIRE_SIGNATURE`: Refuse unsigned images (secure boot)

default **off**; needs `SIGNATURES` or `LMS`. (full core)

Only images signed by one of KEYS boot. Needs KEYS, and the hash on every boot.

C macro: `MB_REQUIRE_SIGNATURE`

### `KEYS`: Trusted public keys file

default ****; needs `SIGNATURES` or `LMS`. (full core)

A text file with one public key per line: Ed25519 (64 hex digits, what mbtool keygen writes to keys/mimiboot.pub), P-256 (128, with ECDSA on) or LMS (112, with LMS on). Enter a path; quotes are fine.

### `REVOKE_KEYS`: Key revocation keys file (who may revoke a signing key)

default ****; needs `SIGNATURES`. (full core; builds: STM32/nRF/SAMD)

Ed25519 public keys (one per line) whose statements make the board stop trusting one of its signing keys: 'mbtool revoke --key <revocation key> --keyid <id>'. Keep these keys offline and apart from KEYS: a leaked image key must not be able to revoke the good ones. The revocation is kept in the protected store, so it needs one: nRF with PROTECTED_FLOOR, or a two-stage build. A board never revokes the last key of a kind. Images signed only by a revoked key stop booting when signatures are required: re-sign them first.

### `ENCRYPTED_IMAGES`: Take encrypted images (AES-CTR + X25519, MCUboot's scheme)

default **off**; needs `RECV`. (full core; builds: STM32/nRF/SAMD)

Images can travel encrypted: 'mbtool pack --encrypt <board.pub>' (or imgtool's ECIES-X25519 key envelope, the same format) encrypts the payload with a fresh AES key and wraps that key for the board. MimiBoot decrypts while the image comes in over the console or SMP, so slots hold plaintext, as MCUboot's primary slot does: this keeps update files and the link private, not the chip's flash. The hash and signature cover the plaintext. Apps can't install encrypted images through the client library (the key stays in the bootloader).

The decryption key is compiled in (ENC_KEY): every board built from the binary shares it, and it is only as safe as the bootloader's flash. Lock the debug port (DEBUG_LOCK on nRF, read protection from 'mbtool provision' elsewhere), and don't leave the 'md' memory dump open to anyone (SHELL_DIAG needs CONSOLE_AUTH here). On a Cortex-M3 (STM32F1/F2) the key check's timing depends on the key (its multiplies end early on small numbers), so there CONSOLE_AUTH is required. About 3.5 KB of code (AES, X25519, HMAC/HKDF), 0.5 KB of RAM.

C macro: `MB_FEAT_ENC`

### `BOOT_RECORD`: Boot record for the app (measured boot)

default **off**; cost ~372 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

Right before starting an image that asks for it (an MB_BOOT_RECORD_BUFFER in its RAM, see mimiboot/mb_record.h), MimiBoot writes what held on this boot: signature verified and with which key, payload hashed, trial or not, the rollback floor, the payload hash, the SHA-256 of the bootloader's own image and a measurement binding the two with the image header. A server that knows both builds can recompute the measurement. It is a report the image can pass on, not attestation: nothing in it is signed by the device. Costs about 0.4 KB, and hashing the bootloader takes a few milliseconds on each boot of an image that asks.

C macro: `MB_FEAT_BOOT_RECORD`

### `ENC_KEY`: Decryption key file (mbtool keygen --type x25519)

default ****; needs `ENCRYPTED_IMAGES`. (full core; builds: STM32/nRF/SAMD)

The board's X25519 private key, 64 hex digits ('mbtool keygen --type x25519 --out keys/board' writes board.key, this file, and board.pub, which 'mbtool pack --encrypt' takes). It ends up in the generated config header and the binary: keep the build folder as private as the key.

### `CFG_SIGNED`: Only use a boot config signed with your keys

default **off**; needs `CFG_FILE`, `SIGNATURES`. (full core)

The boot config decides what boots and with which arguments, so on a locked-down product it shouldn't be something anyone with flash access can rewrite. With this on, a config counts only if it carries an Ed25519 signature from one of KEYS over its text, the target and a version number; anything else is ignored and the built-in entries apply. mbtool cfg push <file> --key <secret> signs it (version: the current time unless --cfg-version).

On chips with the protected floor store (nRF, PROTECTED_FLOOR) an older signed config can't come back once a newer one was used. The console's 'default' command and the app library can't change a signed config; 'cfg reset' goes back to the built-in entries.

C macro: `MB_FEAT_CFG_SIGNED`

### `FAULT_HARDENING`: Harden the boot decision against glitches

default **on**; cost ~224 B on nucleo-f411re. (full core)

Makes a voltage or clock glitch that skips one instruction much less likely to start an image that failed its checks. The hash and the final signature comparison run in constant time and twice; each check leaves a multi-bit token only when it really passes; right before jumping, the tokens and the rollback floor are checked again, from a different place in the code. A glitch now has to hit two independent spots.

It doesn't make the chip glitch-proof (that takes hardware countermeasures), and costs a few hundred bytes.

C macro: `MB_FEAT_FAULT_HARDENING`

### `CONSOLE_AUTH`: Console commands that change things need a signed unlock

default **off**; needs `SHELL`, `SIGNATURES`. (full core; builds: STM32/nRF/SAMD)

Until someone answers the 'unlock' challenge with a key from UNLOCK_KEYS, the console only lets you look (ls, info, verify, log...) and boot an entry as configured. Uploads, confirm/reject/erase, config changes, 'boot ... force', edited args, requests and the ROM loader all need the unlock. mbtool does it for you with --unlock-key.

Five wrong answers lock the console until the next reset. On nRF the challenge comes from the hardware RNG; on other chips it is derived from the boot count and the clock (weaker: see docs/SECURITY.md).

C macro: `MB_FEAT_CONSOLE_AUTH`

### `UNLOCK_KEYS`: Console unlock keys file

default ****; needs `CONSOLE_AUTH`. (full core; builds: STM32/nRF/SAMD)

Public keys (one per line, 64 hex digits; mbtool keygen) allowed to unlock the console. Empty: the image keys (KEYS). A separate key is better: whoever holds it can install images over the console, but not sign them.

### `BOOT_LOCK`: Lock the bootloader's flash before starting an image

default **off**. (full core; builds: STM32/nRF/SAMD)

Right before it jumps, the bootloader write-protects its own region until the next reset (nRF51: MPU PROTENSET, nRF52805/810/811/832: BPROT, nRF52820/833/840: ACL). The started image can't erase or rewrite the bootloader or its keys; it can still write its slots, the boot log and the config.

Protection also holds while a debugger is attached (DISABLEINDEBUG cleared); flashing with a debugger still works because it resets the chip first.

Other chips lock their bootloader with persistent fuses or option bytes instead: mbtool provision prints the commands.

C macro: `MB_FEAT_BOOT_LOCK`

### `LOCK_GOLDEN`: Lock the golden (recovery) slot too

default **on**; needs `BOOT_LOCK`, `LAYOUT=ab+golden`. (full core; builds: STM32/nRF/SAMD)

With the bootloader's flash lock on, also write-protect the golden slot until reset, so a compromised app can't erase or replace the image the board falls back to. A new golden image is still installed through MimiBoot itself (console 'recv g force', mbtool), which runs before the lock; the app library can no longer write it.

C macro: `MB_FEAT_LOCK_GOLDEN`

### `PROTECTED_FLOOR`: Keep the rollback floors in the locked region

default **off**; needs `BOOT_LOCK`. (full core; builds: STM32/nRF/SAMD)

The anti-rollback floor and the newest golden version are kept in the last 4 KB of the bootloader region as well as in the boot log. The log is ordinary flash an app can rewrite; the copy in the locked region isn't, so a compromised app can't lower the floor and reinstall an old signed image.

Costs one 4 KB page of the bootloader region (room for 256 raises).

C macro: `MB_FEAT_PROTECTED_FLOOR`

### `DEBUG_LOCK`: Keep the debug port closed

default **off**. (full core; builds: STM32/nRF/SAMD)

On nRF52 parts with the newer APPROTECT (most built since 2021), debug access is closed at reset and firmware opens it only if UICR says so. On: the bootloader never opens it and forces it closed until the next reset (APPROTECT.FORCEPROTECT), so neither it nor the app it starts can be debugged. Off: the bootloader opens it when UICR.APPROTECT is 0x5A, as Nordic's startup code does.

Recovering a locked chip takes a full erase (nrfjprog --recover), which also removes the bootloader. Older nRF52 silicon and the nRF51 are locked with UICR alone: mbtool provision prints the command.

C macro: `MB_FEAT_DEBUG_LOCK`

## Console, menu and upload

The text console on USB (RP) or a UART: boot menu, command line, diagnostic commands, image upload with mbtool, the boot config file.

### `CONSOLE`: Console with boot menu

default **on**; cost ~16.7 KB on nucleo-f411re. (full core)

USB (RP) or UART (STM32, nRF, SAMD) text console with the boot menu. Without it, a board with nothing bootable falls back to the chip's ROM loader (RP, STM32; nRF and SAMD have none and wait for a debugger).

C macro: `MB_FEAT_CONSOLE`

### `SHELL`: Command line (ls, boot, confirm, recv, erase, cfg ...)

default **on**; needs `CONSOLE`; cost ~13.3 KB on nucleo-f411re. (full core)

The console's command line ('c' in the menu). Off: the menu alone (pick an entry, edit its args, reboot). Uploads need it.

C macro: `MB_FEAT_SHELL`

### `SHELL_DIAG`: Diagnostic commands (md memory dump, sha, log, layout, keys)

default **on**; needs `SHELL`; cost ~2.3 KB on nucleo-f411re. (full core)

Handy on the bench. Turn off for products: 'md' reads any flash or RAM the bootloader can see.

C macro: `MB_FEAT_SHELL_DIAG`

### `RECV`: Image upload over the console (mbtool install / ota / ramboot)

default **on**; needs `SHELL`; cost ~1.8 KB on nucleo-f411re. (full core)

Receive images in CRC-checked frames and write them to a slot.

C macro: `MB_FEAT_RECV`

### `CONSOLE_USB`: Console over native USB (CDC serial port) instead of the UART

default **off**; needs `CONSOLE`. (full core; builds: STM32/nRF/SAMD)

The menu, command line, uploads and SMP over the chip's own USB port, as a serial port the host sees with no driver: for boards whose only connection is USB (Feather M0/M4, Trinket M0, XIAO). TinyUSB (MIT, vendored unmodified) does the USB; the 48 MHz it needs comes from the DFLL locked to the host (no crystal). USB comes up only when the console is wanted: the button, nothing bootable, or the app asking for the menu (there's no key-at-reset break-in over USB), and is taken down completely before an image starts. About 8 KB. Built only: not run on a board yet.

C macro: `MB_CONSOLE_USB`

### `USB_VID`: USB vendor ID (decimal; 4617 = 0x1209, pid.codes)

default **4617**; 1..65535; needs `CONSOLE_USB`. (full core; builds: STM32/nRF/SAMD)

With USB_PID the identity the host sees. The default 0x1209:0x0001 is pid.codes' test ID: fine on the bench, not for a product (pid.codes gives open-source projects their own PID for free).

C macro: `MB_USB_VID`

### `USB_PID`: USB product ID (decimal)

default **1**; 1..65535; needs `CONSOLE_USB`. (full core; builds: STM32/nRF/SAMD)

See USB_VID.

C macro: `MB_USB_PID`

### `SMP`: mcumgr / SMP on the console (Zephyr's update tools)

default **off**; needs `RECV`; cost ~5.9 KB on nucleo-f411re. (full core)

Speak the Simple Management Protocol on the console's UART, the subset MCUboot's serial recovery offers: image list, upload, test/confirm, erase, reset, echo, MCUmgr parameters. mcumgr, smpmgr, AuTerm and smpclient can then update the board: MimiBoot images and imgtool-signed Zephyr images alike. Open the console first (button, a key right after reset, or the app's request); SMP lines and the menu share the UART.

"image" 0 means the A/B slot an update goes to, "image" N the Nth slot (as in MCUboot's direct upload). Golden is never written over SMP. With CONSOLE_AUTH, writes need the console unlocked. About 4 KB of code and SMP_BUF + 1.5 KB of RAM.

C macro: `MB_FEAT_SMP`

### `SMP_BUF`: SMP packet buffer (bytes)

default **1024**; 256..4096; needs `SMP`. (full core)

The largest SMP message the board takes (told to clients as buf_size). Bigger uploads faster, costs RAM.

C macro: `MB_SMP_BUF`

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

default **on**; cost ~1.7 KB on nucleo-f411re. (full core)

A checksummed block the image finds at the address its header names: which slot and entry it was started from, the args, why the chip reset.

C macro: `MB_FEAT_HANDOFF`

### `CONTROL`: OS control service (reboot into menu / entry / slot / flash mode)

default **on**; cost ~704 B on nucleo-f411re. (full core)

Lets a running OS queue a versioned request (mb_client_request) that the bootloader consumes on the next boot.

C macro: `MB_FEAT_CONTROL`

### `OS_HOOKS`: OS hooks: how the last run ended, the RAM mailbox, handoff v2

default **on**; needs `HANDOFF`; cost ~1.3 KB on nucleo-f411re. (full core)

The started image gets more in its handoff (v2): what this bootloader was built with, how the previous run ended (a reboot, an update, a power-off, a panic with its message and address, the watchdog), trial state, how long the boot took, and random bytes for its RNG where the chip has one.

And before it resets, the running OS can leave a note in its handoff buffer: why it is resetting (a reboot, an update, a power-off, a panic with a message and an address) and what to boot next (the menu, an entry, a slot, flash mode). MimiBoot reads it first thing, uses it once, and hands "how the last run ended" to the next boot. Nothing is written to flash, so an OS can reboot into the menu as often as it likes. A panic noted here counts as a crash for the crash-loop guard.

RAM survives a reset but not a power cut: a lost note means a normal boot, and requests that must survive power loss go to the boot log in flash (the client library picks). Needs the image's handoff buffer at its full size (images built with this MimiBoot's headers have it).

C macro: `MB_FEAT_OS_HOOKS`

### `SCRUB_RAM`: Wipe the bootloader's RAM before handing over

default **off**; cost ~16 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

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

With TWO_STAGE this is stage 0's region (stage 0 + the store); chip means auto there.

### `TWO_STAGE`: Two-stage bootloader (updatable in the field)

default **off**; cost ~172 B on nucleo-f411re. (full core; builds: STM32/nRF/SAMD)

Split MimiBoot in two. Stage 0 is small and never changes: it checks the two stage-1 copies (s1a, s1b) and starts the best one. Stage 1 is the whole bootloader (console, uploads, A/B, everything), and is updated like an app: upload a new one into the copy that isn't running (mbtool loader), reboot. A new stage 1 is on trial until it gets as far as starting an image; after 3 boots that don't, stage 0 goes back to the old copy.

The build makes stage0.bin, stage1-s1a.img, stage1-s1b.img and mimiboot.bin (stage 0 + stage 1 in s1a: what goes on a new board). Stage-1 images are signed with STAGE1_SIGN_KEY and checked against S1_KEYS, separate from the app keys.

C macro: `MB_FEAT_TWO_STAGE`

### `STAGE1_SIZE`: Size of each stage-1 copy (auto / e.g. 64K)

default **auto**; needs `TWO_STAGE`. (full core; builds: STM32/nRF/SAMD)

auto: the measured stage 1 plus a quarter for later versions, plus its 4 KB header, rounded up to sectors. A later stage 1 must fit, so leave room.

### `STAGE1_VERSION`: Stage-1 version (x.y.z)

default **1.0.0**; needs `TWO_STAGE`. (full core; builds: STM32/nRF/SAMD)

Put in the stage-1 images. Between two working copies stage 0 starts the higher version; raise it with every release.

### `STAGE1_SECURITY`: Stage-1 security version (anti-rollback)

default **0**; 0..1000000; needs `TWO_STAGE`. (full core; builds: STM32/nRF/SAMD)

Once a stage 1 with this security version has worked, stage 0 never starts one below it again. Raise it when a release fixes a security hole.

### `S1_KEYS`: Stage-1 public keys file

default ****; needs `TWO_STAGE`, `SIGNATURES` or `LMS`. (full core; builds: STM32/nRF/SAMD)

The keys stage 0 accepts a stage 1 from (Ed25519, P-256 with ECDSA on, or LMS with LMS on), one per line. LMS keys here make the bootloader update path post-quantum; prefer W4 keys (stage 0 checks both copies on every boot). Keep them apart from KEYS: a leaked app key must not be enough to replace the bootloader. Required with REQUIRE_SIGNATURE.

### `STAGE1_SIGN_KEY`: Sign stage-1 images with (secret key file)

default ****; needs `TWO_STAGE`, `SIGNATURES` or `LMS`. (full core; builds: STM32/nRF/SAMD)

mbtool keygen's .key file, used by the build to sign stage1-s1a.img and stage1-s1b.img. Empty: they are built unsigned (sign them later with mbtool sign --key).

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

Where `Build` puts the results, and whether to also export a self-contained source tree you can build without MuConfigurator.

### `OUTPUT_DIR`: Output folder (each board gets a subfolder)

default **~/MimiBoot**.

Where builds go: <folder>/<board>/. The default is MimiBoot in your home folder.

Type any path, with or without quotes ("D:/firmware/boot" or ~/projects/boot). `muconfigurator.py build -o DIR` overrides it for one build.

### `EXPORT_SOURCE`: Also export the configured source tree (with a Makefile)

default **off**.

Copies exactly the sources this configuration compiles, the generated config header and linker script, and a Makefile into <output>/source/, so the bootloader can be rebuilt (or audited) without MuConfigurator. RP boards get the CMake project and the build command instead.
