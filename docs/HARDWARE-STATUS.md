# What has been tested, and how

Read this before flashing a board. Labels mean exactly this:

| label | meaning |
|---|---|
| **hardware** | ran on a real board |
| **emulator** | the real build booted in QEMU (STM32, nRF51) or simavr (AVR), checks listed below |
| **model** | the real driver source ran on a PC against a register model written from the datasheet |
| **built** | compiles and links with its default configuration; never executed |
| **host** | the logic is covered by host tests (simulated flash), not on any chip |

The core logic (boot policy, A/B trials, rollback, boot log, power cuts at every
flash operation, signatures, config) is host-tested for every target: 312 checks
in `tests/run.py`, plus every feature profile in `tests/test_profiles.py`.
`tests/test_mimiconf.py --build-all` compiles every board, and every chip has a board.

## MimiBoot-Mu targets (13 November 2026)

| target | label | evidence |
|---|---|---|
| RP2040 (Pico) | hardware (an earlier build) | Through `mimiconf.py build` the default config builds to 63.7 KB (the 2.0 baseline was 63.6 KB); configured variants have not been flashed |
| RP2350 (Pico 2 / Waveshare RP2350-LCD) | hardware (an earlier build) | as above; universal (Arm + RISC-V) image builds at 147 KB default, 90 KB with console and signatures off; configured variants not flashed |
| STM32F405 (`netduinoplus2`) | emulator | `tests/qemu/test_qemu.py`: signed MIMG image boots from golden, VTOR at the image, PRIMASK 0 at entry, corrupted / untrusted-key images refused, UART break-in opens the menu, raw (FreeRTOS-style) image boots, imgtool-signed Ed25519 MCUboot image boots with signatures required, tampered / unsigned MCUboot images refused, an app linked with the client library finds its slot and validates the handoff |
| STM32F100 (`stm32vldiscovery`) | emulator | same tests for the lean profile (no signatures) |
| every other STM32 board in `config/targets.toml` | built | `tests/test_mimiconf.py --build-all` |
| nRF51822 (`microbit`, QEMU microbit) | emulator | `tests/qemu/test_qemu.py`: with nothing installed the console comes up (UART + TIMER0 time base); an image in golden boots with exceptions and an NVIC interrupt relayed to its handlers (no VTOR); PRIMASK 0 at entry; an image uploaded with mbtool's protocol over the UART is erased/written/read back through the NVMC driver, verifies and boots from slot a. QEMU's NVMC model ignores writes without WEN (checked), so a sequencing slip would have failed |
| nRF52832 / 833 / 840 / 810 / 811 / 820 boards | built | every board compiles and fits (`--build-all`; the 52810/811 builds use the UARTE console and fit 28 KB of a 32 KB region with signatures off). Same NVMC + UART + TIMER code as the nRF51 run, except the UARTE path, the HF crystal start, APPROTECT, the watchdog, GPIO port 1 and VTOR: none of that has run |
| SAM D21 / D51 boards (every chip in targets.toml has a board and compiles) | built + model | `tests/test_sim_flash.py`: `port/samd/samd_flash.c` against a model of each NVM controller (D21 word ADDR, page buffer, manual writes, one write per page; D51 8 KB blocks, ECC quad-words written once, cache off during commands, lock errors). The model encodes the same reading of the datasheet as the driver, so it catches coding slips, not misreadings. Clocks, SERCOM, PORT and watchdog code never ran |
| ATmega328P (Uno/Nano/Pro Mini) | emulator | `tests/avr/test_avr.py`: real avrdude 7.1 uploads + verifies through the bootloader, app gets uploaded/verified flags, app-requested bootloader entry, CRC record damage refused and repaired by an upload, trial boots (tries run out / confirm), staged update written through the flash service and installed by the bootloader |
| ATmega168 / 644P / 1284P / 2560 | built | same source; the large-flash paths (RAMPZ/ELPM on 1284P/2560) never executed |

The AVR emulator runs used `ENTRY=every-reset` with a 2 s wait (simavr can't pulse
the reset pin from avrdude's DTR). The default `reset-pin` entry and the 8 MHz Pro
Mini build have not run anywhere.

### The configurable parts (options beyond the original RP bootloader)

| option | evidence |
|---|---|
| `BOOT_VERIFY` every-boot / once / never | host: `tests/test_profiles.py` profiles verify-once, verify-never, verify-once+mcuboot (a known image boots on its header; a new corrupt image is refused by "once" and booted by "never", as documented); "required signatures + not every boot" refuses to compile |
| `SHELL` off (menu only), `SHELL_DIAG` off | host profiles menu-only / no-diagnostics (-Werror); QEMU microbit: menu-only console offers no command line and 'c' opens none |
| `SCRUB_RAM` | QEMU microbit: with it the bootloader's RAM region is all zero when the image starts and the handoff is intact; without it the same check finds data there |
| `BOARD_LED` / `BOARD_BUTTON` off, `MENU_SECS` | compile-tested (the pins simply aren't generated) |
| menuconfig (TUI) | Linux only: `tests/tui_smoke.py` drives it in a pseudo-terminal at 120 and 80 columns (picker, menus, toggles, save), and its screens were rendered and read through a terminal emulator. Not run on Windows (windows-curses: `pip install windows-curses`); it falls back to ASCII when the terminal isn't UTF-8 |
| presets, output folder, source export | `tests/test_mimiconf.py`; every preset builds on STM32F411, SAM D21, nRF52840, nRF51, the Uno, Pico and Pico 2 (minimal and hobby). The exported Makefiles for nucleo-f411re and arduino-zero build with GNU make in WSL (Ubuntu's arm-none-eabi-gcc makes a 36.9 / 37.1 KB image where the Windows Arm toolchain makes 34.1 / 35.0 KB: a different compiler version). The AVR export's Makefile commands (`make -n`) run with the Arduino avr-gcc give the identical hex. The RP2040 export's BUILD.txt command builds the same-size image (58,904 B) through the Pico SDK. Every preset also built for pico and pico2 (RP2350 universal) |

### Not done / not claimed

- **No STM32 flash write has ever run.** QEMU has no STM32 flash controller, so the
  drivers (F0/F1/F3, F2/F4/F7, L4/G0/G4) are written from the reference manuals and
  only compiled. Every erase is blank-checked and every program read back, so a
  driver that doesn't work fails with MB_E_IO instead of corrupting anything, but
  until a board has run an A/B update, treat the boot log, trials and uploads on
  STM32 as untested. Test on a board you can recover with ST-LINK first.
- STM32 pin muxing, clocks, the L4 HSI16 switch, LPUART, IWDG, reset-cause flags and
  the system-memory (ROM loader) jump: never on hardware (QEMU doesn't model them).
- STM32F0 (Cortex-M0, no VTOR) SRAM remap path: never executed.
- `mbtool install` over a real UART: not run on a board (RP's USB path is the tested one;
  the UART path ran in QEMU on the nRF51).
- nRF52: nothing has run on silicon or in an emulator (QEMU has no nRF52). The UARTE
  one-byte DMA receive (52810/811/820) follows Zephyr's poll_in; its behaviour at 115200
  with mbtool's 1 KB frames is untested. Debug access on new-APPROTECT silicon is
  re-opened only when UICR.APPROTECT reads HwDisabled, like Nordic's SystemInit.
- SAMD: the D21 OSC8M / D51 DFLL are internal oscillators (about +-2 %); fine for
  115200 on the bench, not checked over temperature. The D21 watchdog uses generic clock
  generator 2 (set to OSCULP32K / 32) during trials.
- nRF and SAMD replace the factory bootloader at 0x0: SWD flashing, BOOTPROT on SAMD,
  no SoftDevice on nRF52 (see the README).
- STM32 app side (client library): status and handoff ran in QEMU; confirm, requests and
  A/B install write flash, so they have not run (see the first point).
- MCUboot compatibility covers booting and verifying imgtool images. MCUboot's
  swap/trailer protocol (Zephyr's `boot_write_img_confirmed()`, mcumgr DFU) is not
  implemented. A real Zephyr application has not been built against the generated
  overlay (no Zephyr SDK here).
- AVR: fuse values are computed from the datasheets; writing them needs an ISP
  programmer and has not been done. The flash service isn't available on >128 KB
  parts (ATmega2560: the call needs EIND). ATmega32u4 (USB) isn't supported.
