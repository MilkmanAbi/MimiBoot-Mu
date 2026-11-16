# Talking to MimiBoot from your OS

A bootloader that only starts images is half the job. The other half is the
running system being able to ask it for things: reboot into the menu, try the
other image once, go back to the previous release, say that it crashed and
why. On a PC that is what `grub-reboot`, `grub-set-default` and `bootctl` do.
This is the same for a microcontroller: a C library, a set of shell commands
built on it, and a small amount of state that passes between the bootloader
and whatever it started.

It works the same with or without an OS. "The OS" here means whatever the
bootloader started: a FreeRTOS application, a Zephyr app, a bare-metal loop,
your own kernel.

Everything here is in the 32-bit core (RP2040/RP2350, STM32, nRF, SAM D). The
AVR Lite core has its own, much smaller set (see the end).

## Setting it up

Three lines in the app, and nothing in the build beyond linking the client
library (`client/mb_client.c`, plus `client/mb_ctl.c` for the shell commands):

```c
#include "client/mb_client.h"
#include "mimiboot/mb_handoff.h"

MB_HANDOFF_BUFFER;                       // 320 bytes the C runtime leaves alone

int main(void) {
    mb_client_init(&mb_mcu_port);        // mb_rp2040_port / mb_rp2350_port on the Pico
    mb_client_set_handoff(&mb_handoff);  // before anything else touches that RAM
    ...
}
```

`MB_HANDOFF_BUFFER` puts the buffer in a section the startup code doesn't
clear (`.uninitialized_data` on the Pico SDK; give it a `NOLOAD` section in
your own linker script). `mbtool pack` finds the symbol in the ELF and writes
its address and size into the image header, so there is nothing to configure.

On the bootloader side the `OS_HOOKS` option (in MuConfigurator's "Handoff and OS
hooks" menu) turns all of this on. It is on by default nearly everywhere. Where
the bootloader region is tight (F103RB/CB, F401CC, G431RB, nRF52810/811) the
diagnostic shell commands are off by default to make room for it, and on parts
with 8 KB of RAM (F100RB, F030R8, G031K8) `OS_HOOKS` itself is off by default.

## What the OS learns at boot

`mb_client_handoff()` returns what the bootloader wrote into the buffer just
before it jumped, checked (CRC, and the image id must be this image's own) and
already copied out, so the buffer can be reused. A handoff is cleared once
read, so one left over in RAM from an earlier boot is never taken for a new
one.

| field | what it says |
|---|---|
| `slot`, `slot_name`, `kind` | where this image runs from and how it was picked: normal, trial, once, fallback, golden, from the menu |
| `entry_name`, `args` | the boot config entry and its command line |
| `prev` | how the previous run ended: power-on, reboot, update, power-off, panic, fault, watchdog; a message and an address when the OS left them |
| `hflags`, `tries_left`, `trial_ms` | a trial boot: how many boots are left and the watchdog period; confirm with `mb_client_confirm()` |
| `strikes` | crashes in a row of this image |
| `min_security` | the rollback floor in force |
| `features`, `caps` | what the bootloader was built with, and what the image may ask of it |
| `boot_ms` | time spent in the bootloader |
| `seed` | 32 random bytes from the chip's RNG, when it has one (`MB_HO_SEED`) |

`mb_client_status()` gives the same picture with what the boot log in flash
adds, and works without a handoff too.

## Asking for the next boot

```c
mb_client_next(MB_CONTROL_MENU, NULL, NULL, MB_VIA_AUTO);            // stop in the boot menu
mb_client_next(MB_CONTROL_ENTRY, "recovery", "safe=1", MB_VIA_AUTO); // that entry, with these args
mb_client_next(MB_CONTROL_SLOT, "b", NULL, MB_VIA_AUTO);             // the other image, once
mb_client_next(MB_CONTROL_FLASH, NULL, NULL, MB_VIA_AUTO);           // wait for mbtool
mb_client_next(MB_CONTROL_ROM, NULL, NULL, MB_VIA_AUTO);             // the chip's own loader
mb_client_reboot(MB_END_REBOOT, "user asked");                       // now
```

A request is good for one boot. After that the board goes back to its normal
choice. It travels one of three ways, and `MB_VIA_AUTO` picks:

| how | when | cost |
|---|---|---|
| RAM mailbox | the handoff says the bootloader reads one (`MB_CAP_MAILBOX`) | nothing written to flash. Lost if the power goes before the reset |
| the boot log (control service) | `MB_VIA_FLASH`, or no mailbox | one log record. Survives a power cut |
| the boot log, old requests | an older MimiBoot | menu, entry, slot, flash mode, ROM only |

The return value says which one was used. A mailbox request takes effect with
the next `mb_client_reboot()` (or another reset done through the library). A
log request takes effect at the next reset of any kind. If both are waiting,
the one in the log wins.

The bootloader checks a request the same way whichever way it came: the entry
must exist, the slot must exist, the strings must be terminated. A bad one
stops the board in the menu with the error shown. The args of a request go to
the image of the entry or slot it names, never to a fallback.

Nothing here gets around a check. An image asked for still has to pass its
signature, hash and rollback floor, exactly as on a normal boot.

## Saying why

`mb_client_reboot(reason, msg)` leaves a note for the next boot: the reason
(`MB_END_REBOOT`, `MB_END_UPDATE`, ...) and up to 47 characters. The next
image finds it in `prev`, and so does the bootloader console's `last` command.
A reset without a note shows up as "unknown", a watchdog reset as "watchdog".

The note is written only right before the reset, never earlier, so it can't
end up describing a later crash.

## Crashes

```c
mb_client_panic("heap exhausted");             // from your assert / panic path
mb_client_fault(pc, lr, SCB->CFSR);            // from a fault handler
```

Both reset at once and count as a crash. The crash-loop guard counts crashes
in a row of a confirmed image, and after four the next good image boots
instead (the other A/B image, then golden). The next run of whatever boots
sees the reason, the message and the addresses in `prev`.

Neither writes flash, so both are safe to call from a fault handler. With the
mailbox they leave a note. Without one (an RP board, or an image built with an
older handoff buffer) they reset through the watchdog where the port has one,
which the guard counts as well. A port with neither resets plainly, and that
reset isn't counted.

A Cortex-M HardFault handler that hands the stacked registers over:

```c
__attribute__((naked)) void HardFault_Handler(void) {
    __asm volatile("tst lr, #4 \n ite eq \n mrseq r0, msp \n mrsne r0, psp \n b fault_c");
}
void fault_c(uint32_t *frame) {
    mb_client_fault(frame[6], frame[5], *(volatile uint32_t *)0xE000ED28);  // pc, lr, CFSR
}
```

(Cortex-M0 has no `ite`: test bit 2 of `lr` with a branch instead.)

## Power off

`mb_client_poweroff("low battery")` notes a clean shutdown and turns the chip
off where the port can: on nRF that is System OFF, and the next wake-up starts
in the bootloader with `prev` saying "power-off". Elsewhere it returns
`MB_E_UNSUPP`, and the OS uses its own low-power mode.

## Slots and rollback

```c
mb_client_slot_t s;
mb_client_slot_info(MB_SLOT_B, &s);      // image, version, state, why it went bad, below the floor?
mb_client_rollback();                    // prefer the other confirmed A/B image from the next boot
mb_client_set_active(MB_SLOT_A);         // or a given one
mb_client_reject(MB_SLOT_B);             // never boot that image again
mb_client_vacate(MB_SLOT_B);             // empty the slot
```

A rollback only goes to an image that was confirmed and is at or above the
rollback floor (the protected copy of the floor counts too). An image the
board has moved past can't come back this way.

`mb_client_entries()` lists the boot config's entries. `mb_client_set_default()`
changes the default (when the bootloader allows config changes). To install an
update from the running system, see `mb_client_install_*` and `mb_client_recv`
in `client/mb_client.h`.

## mbctl: all of it from your shell

`client/mb_ctl.c` turns the above into commands, for whatever shell the system
already has:

```c
static void print(void *ctx, const char *s) { uart_puts(s); }
mb_ctl_line(line, print, NULL);          // "status", "reboot menu", "slots" ...
```

```
$ mbctl status
loader    MimiBoot 3.0.0 on nucleo-f411re (stm32f411re), handoff v2
          the boot took 41 ms
running   slot a: "sensor-node" 1.4.0 (security 3), a trial boot
trial     not confirmed: 2 boots left, then the previous image ('mbctl confirm' when it works)
previous  reboot for an update: "ota 1.4.0"
floor     security 3 (nothing older boots)
requests  through RAM (no flash write)

$ mbctl slots
slot     image                            version     sec  state
a   >   sensor-node                      1.4.0         3  trial
b    *  sensor-node                      1.3.2         3  good
g       sensor-node-rescue               1.0.0         1  good, golden
(> running, * preferred A/B image)

$ mbctl reboot entry recovery safe=1 -- field test
```

The full list: `status`, `slots`, `entries`, `info`, `last`, `confirm`,
`reboot [TARGET] [-- why]`, `next TARGET [--flash]`, `rollback`,
`active SLOT`, `reject SLOT`, `vacate SLOT`, `default ENTRY`,
`poweroff [why]`, `help`. TARGET is `menu`, `config`, `flash`, `rom`,
`entry NAME [ARGS]` or `slot S [ARGS]`.

Hooking it up, for example:

- FreeRTOS+CLI: register a command whose callback joins its parameters into
  a line and calls `mb_ctl_line()` with a print function that appends to the
  output buffer.
- Zephyr shell: `SHELL_CMD_ARG_REGISTER(mbctl, NULL, "MimiBoot", cmd, 1, 10)`
  with `cmd` calling `mb_ctl(argc - 1, argv + 1, ...)` and printing through
  `shell_print`.
- A bare UART: read a line, hand it to `mb_ctl_line()`.

## Versions and compatibility

| image built with | bootloader | what happens |
|---|---|---|
| a 320-byte buffer (today's headers) | with OS_HOOKS | v2 handoff, mailbox |
| a 320-byte buffer | without OS_HOOKS, or older | v1 handoff (160 bytes), requests through the log |
| a 160-byte buffer (older headers) | any | v1 handoff, never more than 160 bytes written |
| no buffer | any | no handoff; status, args and requests through flash |

The client library takes a v1 block as well as a v2 one, and everything that
needs v2 says `MB_E_UNSUPP` without it. `mb_client_capabilities()` and
`mb_client_transport()` tell an OS what it can count on before it asks.

## Limits, said plainly

- **RAM is lost on a power cut.** A mailbox request or note that doesn't
  survive just means a normal boot. Use `MB_VIA_FLASH` for a request that
  must survive.
- **Only where RAM survives a reset.** The mailbox is on for STM32, nRF and
  SAM D. The RP ports don't declare it yet (the boot ROM's use of SRAM across
  a watchdog reset hasn't been checked), so there requests go through flash.
- **Hardware: one STM32 so far.** The mailbox, `mbctl`, panics and faults ran on
  a Nucleo-F103RB, and before that in the simulator, in fuzzing and across real
  resets in QEMU (STM32F405). The nRF System OFF path and the RP watchdog
  fallback have not run anywhere.

## The AVR Lite core

The 1-2 KB AVR bootloader keeps its own small interface in `client/mu_avr.h`:
`mu_handoff()` (started by MimiBoot? why did it reset?), `mu_confirm()`,
`mu_enter_bootloader()` (a RAM word asks for the upload mode), `mu_reboot()`,
and the flash service for staged updates. None of the above applies there.
