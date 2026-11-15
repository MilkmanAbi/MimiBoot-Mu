/*
 * mbctl: the bootloader as commands for your own shell (FreeRTOS+CLI, Zephyr's
 * shell, a UART line reader, your OS's /bin). What bootctl and grub-reboot are
 * to a Linux box, for a board running MimiBoot.
 *
 *   mb_client_init(&port); mb_client_set_handoff(&mb_handoff);   // as usual, first
 *   mb_ctl_line(line, print, ctx);        // "mbctl" stripped or not: "reboot menu", "slots" ...
 *   mb_ctl(argc, argv, print, ctx);       // argv[0] is the command ("status", "reboot", ...)
 *
 * Commands (mbctl help prints them):
 *   status                    what runs, from where, how the last run ended, what boots next
 *   slots                     every slot: image, version, state
 *   entries                   the boot config's entries (the default marked)
 *   info                      the bootloader: version, what it was built with, how requests travel
 *   last                      how the previous run ended (reason, message, address)
 *   confirm                   this image works (ends a trial)
 *   reboot [TARGET] [-- why]  reset now; TARGET: menu, config, flash, rom, entry NAME [ARGS], slot S [ARGS]
 *   next TARGET [--flash]     the same, for whenever the next reset happens (--flash: survive a power cut)
 *   rollback | active SLOT    make the other / that confirmed A/B image the preferred one
 *   reject SLOT | vacate SLOT mark another slot bad / empty it
 *   default ENTRY             the boot config's default entry
 *   poweroff [why]            off, where the chip can do it
 * Returns 0, or a negative MB_E_* (and says why through print).
 */
#ifndef MIMIBOOT_CTL_H
#define MIMIBOOT_CTL_H

#include "client/mb_client.h"

typedef void (*mb_ctl_print_t)(void *ctx, const char *text);

int mb_ctl(int argc, char **argv, mb_ctl_print_t print, void *ctx);
int mb_ctl_line(char *line, mb_ctl_print_t print, void *ctx); /* splits line in place */

#endif
