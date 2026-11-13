# Booting Zephyr and FreeRTOS firmware

MimiBoot-Mu boots what those projects already produce, on STM32, nRF and SAM D.
Status: both paths ran in QEMU on an STM32F405 build (see HARDWARE-STATUS.md);
neither has run on a board, and no real Zephyr application has been built here.

## Zephyr (MCUboot image format)

Enable **Zephyr / MCUboot images** (`IMG_MCUBOOT=y`). For apps that won't call
MimiBoot's confirm, also turn off **Updates must confirm** (`AB_TRIAL=n`).

1. Build MimiBoot. `build/<board>/zephyr-partitions.overlay` puts Zephyr's
   `boot_partition`/`slot0_partition` where MimiBoot's bootloader and slot A are.
2. Build the app for MCUboot:

   ```
   west build -b <board> app -- -DCONFIG_BOOTLOADER_MCUBOOT=y \
       -DDTC_OVERLAY_FILE=path/to/zephyr-partitions.overlay
   ```

   Zephyr then links at slot0 + 0x200 (`CONFIG_ROM_START_OFFSET`). SAM D51 needs
   `-DCONFIG_ROM_START_OFFSET=0x400` and `--header-size 0x400` below: its vector table
   must be 1 KB aligned. `layout.txt` gives the value for your board.

   The overlay replaces the board's whole partition table. If the board file points
   something else at a partition label (`storage_partition` for settings, say), add
   that partition back outside MimiBoot's log/config range (the overlay's comment
   gives the range).
3. Sign. With signature checks, use an Ed25519 key and give MimiBoot its public half:

   ```
   imgtool keygen -k key.pem -t ed25519
   imgtool sign --header-size 0x200 --pad-header --align 8 --version 1.0.0 \
       --slot-size <slot size from layout.txt> --key key.pem zephyr.bin app.signed.bin
   ```

   Public key for `KEYS` (one hex line):

   ```
   python -c "from cryptography.hazmat.primitives import serialization as s;\
   k=s.load_pem_private_key(open('key.pem','rb').read(),None);\
   print(k.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw).hex())" > zephyr.pub
   ```

4. Flash `app.signed.bin` at slot A's address.

What MimiBoot checks: the image header, the SHA-256 TLV over header + image +
protected TLVs (every boot), the ED25519 TLV (imgtool's default mode signs the
digest), the security counter TLV for anti-rollback. Refused: encrypted images and
"pure" signatures. RSA/ECDSA signatures aren't checked: such an image counts as
unsigned, so it boots only while signatures are optional.

Not supported: MCUboot's swap trailer. Zephyr's `boot_write_img_confirmed()` and
mcumgr image upload talk to MCUboot's trailer, which MimiBoot doesn't read. Use
`AB_TRIAL=n`, or call MimiBoot's client to confirm.

## FreeRTOS, bare metal, Arduino-STM32

Two options:

- **Raw firmware** (`IMG_RAW=y`): link the firmware at a slot address and flash
  the plain `.bin` there. MimiBoot checks the initial stack pointer and reset
  vector look sane and starts it. There is no integrity check.
- **Wrapped**: link at slot + 0x1000 and `python tools/mbtool.py pack fw.elf --target <chip>`.
  You get SHA-256, optional signatures, versions and the handoff.

What the firmware gets either way: VTOR pointing at its vector table, MSP from its
table, interrupts masked in the NVIC and cleared, SysTick stopped, the console UART
and pins back at reset state, the reset clock (STM32 HSI/MSI, nRF HFINT with the
crystal stopped and TIMER0 reset, SAM D21 OSC8M /8, SAM D51 DFLL 48 MHz), and
PRIMASK clear (interrupts enabled), which is what STM32Cube's `HAL_Init()`, nrfx /
ASF `SystemInit()` and FreeRTOS's port expect. FreeRTOS reads MSP from `VTOR[0]` when it starts the scheduler, so VTOR
must be right; it is.

If trial boots with the watchdog are on (`TRIAL_WATCHDOG=y`), the STM32 and nRF
watchdogs keep running in the app (they can't be stopped): refresh them, or keep that
option off (the default on bare-metal MCUs). On SAM D it keeps running too, but the
app may switch it off (clear WDT CTRL.ENABLE) once it is up.
