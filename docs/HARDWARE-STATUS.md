# What has been tested, and how

Read this before flashing a board.

> **STM32: keep an ST-Link on SWD while you try a board.** STM32 flash writes
> have run on one board so far, a Nucleo-F103RB (the F0/F1/F3 driver). The
> F2/F4/F7 and L4/G0/G4 flash drivers, and every other family's clocks, pins and
> watchdog, have never run on a chip: QEMU has no STM32 flash controller.
> Uploads, the boot log, confirming an image and the rollback floors all write
> flash. Check that STM32CubeProgrammer can connect under reset and mass-erase
> the board before you start, and leave readout protection alone (RDP level 2
> can't be undone).

Labels mean exactly this:

| label | meaning |
|---|---|
| **hardware** | ran on a real board |
| **emulator** | the real build booted in QEMU (STM32, nRF51) or simavr (AVR), checks listed below |
| **model** | the real driver source ran on a PC against a register model written from the datasheet |
| **built** | compiles and links with its default configuration; never executed |
| **host** | the logic is covered by host tests (simulated flash), not on any chip |

The core logic (boot policy, A/B trials, rollback, boot log, power cuts at every
flash operation, signatures, config, rollback floors, the console lock) is
host-tested for every target: the checks in `tests/run.py` (two test programs:
one built with the console lock), plus every feature profile in
`tests/test_profiles.py`.
`tests/test_muconfigurator.py --build-all` compiles every board, and every chip has a board.

## MimiBoot-Mu targets (13 November 2026)

| target | label | evidence |
|---|---|---|
| RP2040 (Pico) | hardware (an earlier build) | Through `muconfigurator.py build` the default config builds to 63.7 KB (the 2.0 baseline was 63.6 KB); configured variants have not been flashed |
| RP2350 (Pico 2 / Waveshare RP2350-LCD) | hardware (an earlier build) | as above; universal (Arm + RISC-V) image builds at 147 KB default, 90 KB with console and signatures off; configured variants not flashed |
| STM32F405 (`netduinoplus2`) | emulator | `tests/qemu/test_qemu.py`: signed MIMG image boots from golden, VTOR at the image, PRIMASK 0 at entry, corrupted / untrusted-key images refused, UART break-in opens the menu, raw (FreeRTOS-style) image boots, imgtool-signed Ed25519 MCUboot image boots with signatures required, tampered / unsigned MCUboot images refused, an app linked with the client library finds its slot and validates the handoff |
| STM32F100 (`stm32vldiscovery`) | emulator | same tests for the lean profile (no signatures) |
| STM32F103RB (Nucleo-F103RB) | hardware | MimiBoot-Mu 3.0.0, 16 November 2026: uploads, the boot log, A/B, trials and the IWDG, the mailbox and `mbctl`, the floor, signatures with check times. See "Nucleo-F103RB" below |
| every other STM32 board in `config/targets.toml` | built | `tests/test_muconfigurator.py --build-all`. The F0 and F3 boards share the F103's flash driver; nothing else of theirs has run |
| nRF51822 (`microbit`, QEMU microbit) | emulator | `tests/qemu/test_qemu.py`: with nothing installed the console comes up (UART + TIMER0 time base); an image in golden boots with exceptions and an NVIC interrupt relayed to its handlers (no VTOR); PRIMASK 0 at entry; an image uploaded with mbtool's protocol over the UART is erased/written/read back through the NVMC driver, verifies and boots from slot a. QEMU's NVMC model ignores writes without WEN (checked), so a sequencing slip would have failed |
| nRF52832 / 833 / 840 / 810 / 811 / 820 boards | built | every board compiles and fits (`--build-all`; the 52810/811 builds use the UARTE console and fit 28 KB of a 32 KB region with signatures off). Same NVMC + UART + TIMER code as the nRF51 run, except the UARTE path, the HF crystal start, APPROTECT, the watchdog, GPIO port 1 and VTOR: none of that has run |
| SAM D21 / D51 boards (every chip in targets.toml has a board and compiles) | built + model | `tests/test_sim_flash.py`: `port/samd/samd_flash.c` against a model of each NVM controller (D21 word ADDR, page buffer, manual writes, one write per page; D51 8 KB blocks, ECC quad-words written once, cache off during commands, lock errors). The model encodes the same reading of the datasheet as the driver, so it catches coding slips, not misreadings. Clocks, SERCOM, PORT and watchdog code never ran |
| ATmega328P (Uno/Nano/Pro Mini) | emulator | `tests/avr/test_avr.py`: real avrdude 7.1 uploads + verifies through the bootloader, app gets uploaded/verified flags, app-requested bootloader entry, CRC record damage refused and repaired by an upload, trial boots (tries run out / confirm), staged update written through the flash service and installed by the bootloader |
| ATmega168 / 644P / 1284P / 2560 | built | same source; the large-flash paths (RAMPZ/ELPM on 1284P/2560) never executed |

The AVR emulator runs used `ENTRY=every-reset` with a 2 s wait (simavr can't pulse
the reset pin from avrdude's DTR). The default `reset-pin` entry and the 8 MHz Pro
Mini build have not run anywhere.

## Nucleo-F103RB (16 November 2026)

The first STM32 board: MimiBoot-Mu 3.0.0 (with the fixes this run found) on a
Nucleo-F103RB, loaded over the on-board ST-Link. The bootloader runs on the 8 MHz
HSI. Option bytes, readout and write protection were never touched.

| what | what happened |
|---|---|
| boot and console | menu and command line on USART2 (the ST-Link's serial port) at 115200; UART break-in; "nothing bootable" on an empty board |
| flash writes (F0/F1/F3 driver) | `mbtool install` over the UART into both slots; slot a read back over SWD matched the image byte for byte. The boot log is written on every change and rotated between its two 2 KB pages by itself |
| A/B, handoff | the newest image boots, VTOR at its vector table in either slot, handoff v2 arrives |
| app side (`mbctl`, client library) | status, slots, info, last, entries; requests through the RAM mailbox (the menu, a slot once with args, a reboot reason) and through the log (`--flash`, the app writing flash itself); rollback and `active`; confirm; an OTA with `mb_client_recv` into the other slot while running |
| crash guard, faults | four `mb_client_panic` in a row moved the board to the other image; a real HardFault reported its pc, lr and CFSR to the next run |
| rollback floor | an image with security 2 raised it; rollback, `active` and `next slot` to a security-0 image were refused |
| `AB_TRIAL`, `TRIAL_WATCHDOG` | an unconfirmed image got 3 trial boots, then the previous one booted; the IWDG reset a hung trial 8.3 s into an 8 s trial and the next run saw "watchdog"; confirm ended a trial |
| signatures (48 KB bootloader) | an unsigned image refused at the header with signatures required. Check times at 8 MHz: Ed25519 13.2 s, P-256 2.5 s, LMS (H10, W4) 0.36 s; the SHA-256 of a 32 KB image 0.29 s |
| ROM loader | `u` in the menu left the CPU in system memory (0x1ffff3b6) |

Not tried there: the button and LED, a real power cycle (only pin resets), RDP/WRP,
MCUboot and raw images, `ramboot`, SMP, encrypted images, two-stage, the boot config
file. The run found six problems, fixed before this was written: `mbtool pack` on
a slot whose address isn't 4 KB aligned (two bugs), images within 4 KB of a slot's
end refused, the handoff buffer's placement not documented, the menu calling the ROM
loader "USB", and bare error codes from mbtool.

### The configurable parts (options beyond the original RP bootloader)

| option | evidence |
|---|---|
| `BOOT_VERIFY` every-boot / once / never | host: `tests/test_profiles.py` profiles verify-once, verify-never, verify-once+mcuboot (a known image boots on its header; a new corrupt image is refused by "once" and booted by "never", as documented); "required signatures + not every boot" refuses to compile |
| `SHELL` off (menu only), `SHELL_DIAG` off | host profiles menu-only / no-diagnostics (-Werror); QEMU microbit: menu-only console offers no command line and 'c' opens none |
| `SCRUB_RAM` | QEMU microbit: with it the bootloader's RAM region is all zero when the image starts and the handoff is intact; without it the same check finds data there |
| `BOARD_LED` / `BOARD_BUTTON` off, `MENU_SECS` | compile-tested (the pins simply aren't generated) |
| menuconfig (TUI) | Linux only: `tests/tui_smoke.py` drives it in a pseudo-terminal at 120 and 80 columns (picker, menus, toggles, save), and its screens were rendered and read through a terminal emulator. Not run on Windows (windows-curses: `pip install windows-curses`); it falls back to ASCII when the terminal isn't UTF-8 |
| presets, output folder, source export | `tests/test_muconfigurator.py`; every preset builds on STM32F411, SAM D21, nRF52840, nRF51, the Uno, Pico and Pico 2 (minimal and hobby). The exported Makefiles for nucleo-f411re and arduino-zero build with GNU make in WSL (Ubuntu's arm-none-eabi-gcc makes a 36.9 / 37.1 KB image where the Windows Arm toolchain makes 34.1 / 35.0 KB: a different compiler version). The AVR export's Makefile commands (`make -n`) run with the Arduino avr-gcc give the identical hex. The RP2040 export's BUILD.txt command builds the same-size image (58,904 B) through the Pico SDK. Every preset also built for pico and pico2 (RP2350 universal) |

### Security features (added 14 November 2026)

| feature | evidence |
|---|---|
| protected rollback floors (core) | host: `test_protected_floors` in `tests/run.py`: a forged log floor, a wiped log, `boot force`, `ramboot`, an older golden after a log wipe, a full store, a power cut in the middle of a raise, a store that can't be written, a port without one |
| `PROTECTED_FLOOR` on nRF | emulator (nRF51): booting golden 1.2.3 writes the floor entry through the real NVMC driver and it reads back as expected. Not run on nRF52 |
| `BOOT_LOCK` (MPU PROTENSET / BPROT / ACL) | built: every nRF board compiles with it; the register addresses were checked in the disassembly against Nordic's MDK. QEMU doesn't model block protection, so the lock itself has never been seen to hold |
| `DEBUG_LOCK` (APPROTECT.FORCEPROTECT) | built only |
| `LOCK_GOLDEN` (the golden slot locked with the bootloader) | built only (same lock code as `BOOT_LOCK`, a second region) |
| `CONSOLE_AUTH` | host: `tests/test_auth.c` (what a locked console refuses and allows, menu keys, bad answers, the lockout). Emulator (nRF51): mbtool answers a challenge from the emulated hardware RNG with the unlock key, a locked `reject` is refused before and runs after, a stranger's key is refused. The nRF52 RNG path has not run |
| fault reset + breadcrumb | host: a reported fault marks the slot bad and the next one boots. The Cortex-M handler and its `.noinit` note have not been triggered on a chip or in QEMU |
| MCUboot trailer confirmation (direct-xip `image_ok`) | host: `tests/test_profile.c` in the MCUboot profiles: a trial confirmed by its trailer, an unset `image_ok`, the align-32 magic, a damaged magic. Not run with a real Zephyr app |
| `FAULT_HARDENING` (proof tokens, launch recheck) | host: a real boot decision with one token removed (hash, signature), a token with a bit flipped, an image below the floor, and an "unsigned" token with required signatures: all refused at launch; every feature profile still boots. No glitching hardware here: whether it holds against a real glitch is untested |
| `CFG_SIGNED` (signed boot config) | host (`tests/test_auth.c`, built with it): unsigned writes refused, a bad signature, another key, a changed version, the config in force and booted by, the version recorded as the floor, an older signed config refused, tampered text ignored, `default` can't rewrite it, reset to built-in. Signatures made by mbtool's own code |
| `ECDSA` (P-256, micro-ecc) | host: Wycheproof's 262 P-256 vectors (two known false rejects, pinned), mbtool-signed MimiBoot images (good, untrusted key, field changed, algorithm flag flipped, no P-256 keys), an MCUboot image with a DER ECDSA_SIG TLV (good, damaged). Emulator (STM32F405): a mbtool P-256 image boots with signatures required, an untrusted P-256 key is refused, an imgtool `ecdsa-p256` Zephyr image boots. Nucleo-F103RB: a P-256 image checked in 2.5 s at 8 MHz and booted with signatures required |
| Ed25519 against Wycheproof | host: all 210 vectors (`tests/test_crypto.c`). Nucleo-F103RB: an Ed25519 image checked in 13.2 s at the 8 MHz reset clock, on every boot: too slow to use there (the configurator warns) |
| `TWO_STAGE` (stage 0 + two stage-1 copies) | host (`tests/test_mimiboot.c`, 48 checks): which copy stage 0 picks, trials counted and passed over after 3, a copy that confirms wins, never bricked by its records (every copy failed, store unwritable, store full), what makes a copy unusable (header for the other slot, reset vector elsewhere, bad hash, an app image, a fault while checking it), the stage-1 floor, signatures from the stage-1 keys only, the guards in stage 1 (no booting a copy, no stage 1 in an app slot, no RAM boot, console and config refusals, uploads). Emulator (nRF51, both stages for real, two vector relays): a new board boots an app and stage 1 records itself; `mbtool loader` puts a new stage 1 into the copy that isn't running and it is tried after a power cycle; one that hangs is started on 3 power cycles and then passed over; damaged copies ignored; with signatures, a stage 1 signed with the app key is ignored. Built, default and `secure` preset, for nRF51/52832/52840/52820/52810, SAM D21/D51, STM32 G4/L4; STM32 F4/F7 build with A/B only (their 64 to 256 KB sectors leave no room for golden next to two stage-1 copies). Emulator (STM32F405): stage 0 starts stage 1 through VTOR and it boots an app. Not run on a board; the protected store has never been written on an STM32 |
| Store compaction (two erase units, PROTECTED_FLOOR / TWO_STAGE) | host: 1000 floor raises through 128-entry units with floors, revoked keys and the installed stage-1 copies' records intact and gone copies' records dropped; a power cut at each of the 12 flash operations of a compaction, each leaving the old or the new unit in force and the next raise working; the one-unit (append-only) store unchanged; fuzzed (a full unit of fuzzer bytes, then a raise and an append: a floor never drops). Built for nRF51/52, SAM D21/D51, STM32 L4 (stage 0 still fits: 11.9 KB of 12 KB on the nRF51). The erase of a store unit has never run on any chip |
| `SMP` (mcumgr over the console UART) | host (`tests/test_mimiboot.c`, requests made by the independent `smp` package, replies decoded and CRC-checked): echo in v1 and v2, parameters, bootloader info, list, an unsupported command, a MimiBoot image uploaded in odd-sized chunks with an out-of-step chunk resynced, the sha matched, booted as a trial, confirmed by hash; golden refused, a damaged image and a cut upload leave the slot empty, erase (the active good slot refused), reset after the reply. `tests/test_auth.c`: with the console locked every write is denied, reads answered. Emulator (nRF51, through the real NVMC): parameters, echo, bootloader info, list, a MimiBoot image and an imgtool (MCUboot) image uploaded and booted after a power cycle, golden refused. Not run on a board; no mcumgr CLI has talked to it, only the `smp` library it uses |
| `REVOKE_KEYS` (key revocation) | host: a statement by an image key, a damaged one, one for another key and one for an unknown key refused; the revocation recorded once; an image signed with the revoked key refused at boot while the other key's image boots; the last key of a kind can't be revoked; `keys` shows it; a build without `REVOKE_KEYS` ignores the entry. Emulator (nRF51, through the NVMC into the protected store, mbtool's own code on the console): a statement by an image key refused, the revocation key's taken, after a power cycle an image signed with the revoked key refused and one signed with the other key boots. Not run on a board |
| `ENCRYPTED_IMAGES` (AES-CTR + ECIES-X25519, MCUboot's scheme) | host: AES, CTR, HMAC, HKDF and X25519 against FIPS-197, SP 800-38A, RFC 4231, RFC 5869 and RFC 7748 vectors; envelopes made by imgtool (AES-128 and -256) and by mbtool open, every flipped envelope byte and another board's envelope refused; `recv` and SMP uploads decrypt into a slot (plaintext, nothing written past the payload), a bad envelope refused before the erase, tampered ciphertext fails the hash with the slot left empty, encrypted `ramboot`, the client library refusing them; fuzzed through `recv` and SMP; built for nRF51/52, STM32 and SAM D (about 3.4 KB of flash, 0.5 KB of RAM). QEMU nRF51 (signed and encrypted, signatures required): installed with `mbtool install` and over SMP with the `smp` package, one for another board refused, each booted after a power cycle. Timing of X25519/AES not measured on silicon. On Cortex-M3 the X25519 multiplies (`UMULL`/`UMLAL`, seen in the disassembly) end early on small operands, so there the configurator requires CONSOLE_AUTH |
| `BOOT_RECORD` (measured boot) | host: a signed image gets a record (signed, hashed, trial, key id, versions, floor) whose loader hash and measurement recompute; unsigned images say so; a record address in loader RAM is skipped; none without an address; profiles with and without the rest of the features. QEMU nRF51: the app prints its record, the loader hash equals SHA-256 of mimiboot.bin and the measurement recomputes from that and the image header. About 0.4 KB; the bootloader hash costs a few ms per boot of an image that asks (not timed on silicon) |
| `LMS` (post-quantum signatures, RFC 8554) | host: RFC 8554's test cases (each level), NIST ACVP-Server sigVer (positive and negative) and sigGen vectors, pyhsslms signatures for W1/W2/W4/W8 and H10; every good vector broken eight ways and refused; key generation matches the RFC's and ACVP's keyGen vectors; mbtool's signatures verify in pyhsslms. Simulator: LMS images boot from the slot's header sector, refused with a foreign key, a flipped signature bit, no signature, a changed field, the LMS flag dropped; console upload with the `S` frame (a bad signature refused before the erase), client `install_sig`, SMP (signature from the header sector), revocation by key id, stage 0 taking an LMS stage 1 with the stage-1 key only; fuzzed through `recv`, SMP and flash. Measured cost: ~550 to 620 SHA-256 blocks per check with W4, ~4400 with W8. QEMU nRF51, LMS-only build (no Ed25519, signatures required): a W8 image written into flash boots, one with a flipped signature bit is refused, one uploaded with `mbtool install` boots after a power cycle. Built LMS-only for every bare-metal board; about 4 KB smaller than the Ed25519 build. Nucleo-F103RB (Cortex-M3, 8 MHz): an H10/W4 signature checks in 0.36 s |
| `OS_HOOKS` (handoff v2, RAM mailbox, `mbctl`) | host: v1 and v2 handoffs both ways (a v1 buffer never gets more than 160 bytes), the mailbox (menu with no flash write, a slot once with args, stale / damaged / bad requests, a request in the log wins), panic and fault loops ending in a fallback with and without a mailbox (the watchdog path), rollback refused below the floor, entries, the console's `last`, `mbctl` output; profiles with it off and with everything else off; the mailbox fuzzed through the boot decision. QEMU STM32F405: the client app asks through RAM for the recovery entry with new args and says why; after a real reset in the emulator the next run gets both. Nucleo-F103RB: an app's `mbctl` asked for the menu, a slot once with args and gave reboot reasons through RAM, the same through the log, and a panic and a real HardFault reached the next run. About 0.8 to 1.4 KB of flash and 0.2 KB of RAM (32 KB parts default to SHELL_DIAG off to make room; 8 KB-RAM parts default to OS_HOOKS off). nRF System OFF (`mb_client_poweroff`) and the RP watchdog fallback have not run anywhere; the RP ports don't offer the mailbox yet |
| Client installs (`mb_client_install_*`, `vacate`) | host: odd-sized chunks with a resend on flash that fails any second write to a page (as ECC flash does), out-of-order and short installs refused with the slot left empty, abort, vacate (and its refusals) |
| `CONSOLE_USB` (SAM D21/D51 native USB, TinyUSB) | built for every SAM D board (D21 about 47 KB of the 48 KB region, D51 about 46.5 KB); the USB descriptors linked into each binary are checked (lengths, interface association, two interfaces, three endpoints of the right type and size); the vector table checked by hand (IRQ 7 on D21 to the USB handler, the rest to the fault handler). **Never enumerated**: no SAM D board here. The clock bring-up (DFLL in USB recovery mode, the D21's move to 48 MHz) and its teardown before the app are written from the datasheets and cross-checked against Adafruit's UF2 bootloader; nothing of it has run |
| `mbtool provision` | prints steps (run for nRF52840, nRF51, STM32F411, STM32L476, SAM D21, Uno); none of the printed commands has been run by us |

### Not done / not claimed

- **STM32 flash: only the F0/F1/F3 driver has run, on an F103.** The F2/F4/F7 and
  L4/G0/G4 drivers are written from the reference manuals and only compiled (QEMU
  has no STM32 flash controller). Every erase is blank-checked and every program
  read back, so a driver that doesn't work fails with MB_E_IO instead of corrupting
  anything, but on those families treat the boot log, trials and uploads as
  untested. Test on a board you can recover with ST-LINK first.
- STM32 pins, clock, USART, IWDG, reset-cause flags and the ROM loader jump ran on
  the F103 only. The L4 HSI16 switch, LPUART and the other families' GPIO and
  USART layouts: never on hardware.
- STM32F0 (Cortex-M0, no VTOR) SRAM remap path: never executed.
- `mbtool install` over a real UART: ran on the Nucleo-F103RB (and in QEMU on the
  nRF51).
- nRF52: nothing has run on silicon or in an emulator (QEMU has no nRF52). The UARTE
  one-byte DMA receive (52810/811/820) follows Zephyr's poll_in; its behaviour at 115200
  with mbtool's 1 KB frames is untested. Debug access on new-APPROTECT silicon is
  re-opened only when UICR.APPROTECT reads HwDisabled, like Nordic's SystemInit, and
  only on parts Nordic's errata header lists as having those registers.
- SAMD: the D21 OSC8M / D51 DFLL are internal oscillators (about +-2 %); fine for
  115200 on the bench, not checked over temperature. The D21 watchdog uses generic clock
  generator 2 (set to OSCULP32K / 32) during trials.
- nRF and SAMD replace the factory bootloader at 0x0: SWD flashing, BOOTPROT on SAMD,
  no SoftDevice on nRF52 (see the README).
- STM32 app side (client library): status, confirm, requests, rollback and an OTA
  install ran on the F103; on the other families only status and handoff ran (QEMU).
- MCUboot compatibility covers booting and verifying imgtool images and the
  direct-xip confirm flag in the trailer (`boot_write_img_confirmed()`). MCUboot's
  swap modes and mcumgr DFU (SMP) are not implemented. A real Zephyr application has
  not been built against the generated overlay (no Zephyr SDK here).
- AVR: fuse values are computed from the datasheets; writing them needs an ISP
  programmer and has not been done. The flash service isn't available on >128 KB
  parts (ATmega2560: the call needs EIND). ATmega32u4 (USB) isn't supported.
