/*
 * MimiBoot-Mu - compile-time feature switches for the Night core
 *
 * mimiconf.py writes a config header (mb_config.h) and passes it with
 * -DMB_CONFIG_HEADER="path". Every switch defaults to what MimiBoot-Night
 * 2.0.0 always had, so a build without a config header is the old full build.
 *
 * Each optional module stays declared in mimiboot.h. When it is switched off
 * its file compiles to small stubs that return MB_E_UNSUPP, so callers don't
 * need #ifs and --gc-sections drops what nothing reaches.
 */
#ifndef MIMIBOOT_FEATURES_H
#define MIMIBOOT_FEATURES_H

#ifdef MB_CONFIG_HEADER
#include MB_CONFIG_HEADER
#endif

/* ---- modules ------------------------------------------------------------- */
#ifndef MB_FEAT_CONSOLE
#define MB_FEAT_CONSOLE         1   /* text console: boot menu + command line */
#endif
#ifndef MB_FEAT_SHELL
#define MB_FEAT_SHELL           1   /* the console's command line (else: boot menu only) */
#endif
#ifndef MB_FEAT_SHELL_DIAG
#define MB_FEAT_SHELL_DIAG      1   /* diagnostic commands: md (memory dump), sha, log, layout, keys */
#endif
#ifndef MB_FEAT_RECV
#define MB_FEAT_RECV            1   /* image upload over the console (mbtool install/ramboot/ota) */
#endif
#ifndef MB_FEAT_CFG_FILE
#define MB_FEAT_CFG_FILE        1   /* boot config text kept in flash (else: built-in entries) */
#endif
#ifndef MB_FEAT_GRUB
#define MB_FEAT_GRUB            1   /* GRUB-style menuentry syntax in the config */
#endif
#ifndef MB_FEAT_CONTROL
#define MB_FEAT_CONTROL         1   /* OS control service: versioned reboot requests from a running OS */
#endif
#ifndef MB_FEAT_SIGNATURES
#define MB_FEAT_SIGNATURES      1   /* Ed25519 image signatures */
#endif
#ifndef MB_FEAT_ANTI_ROLLBACK
#define MB_FEAT_ANTI_ROLLBACK   1   /* security_version floor for A/B images */
#endif
#ifndef MB_FEAT_RAM_IMAGES
#define MB_FEAT_RAM_IMAGES      1   /* copy-to-RAM images (MB_LOAD_RAM), console ramboot */
#endif
#ifndef MB_FEAT_HANDOFF
#define MB_FEAT_HANDOFF         1   /* write the boot handoff struct into the image's RAM */
#endif
#ifndef MB_FEAT_CRASH_GUARD
#define MB_FEAT_CRASH_GUARD     1   /* pass over a GOOD image after repeated watchdog resets */
#endif
#ifndef MB_FEAT_AB_TRIAL
#define MB_FEAT_AB_TRIAL        1   /* new A/B images must be confirmed by the app (else rollback) */
#endif
#ifndef MB_FEAT_TRIAL_WATCHDOG
#define MB_FEAT_TRIAL_WATCHDOG  1   /* arm the watchdog for trial boots */
#endif

/* ---- image formats a slot may hold ------------------------------------------ */
#ifndef MB_FEAT_IMG_NATIVE
#define MB_FEAT_IMG_NATIVE      1   /* MimiBoot "MIMG" header (mbtool pack) */
#endif
#ifndef MB_FEAT_IMG_MCUBOOT
#define MB_FEAT_IMG_MCUBOOT     0   /* MCUboot images (Zephyr CONFIG_BOOTLOADER_MCUBOOT, imgtool sign) */
#endif
#ifndef MB_FEAT_IMG_RAW
#define MB_FEAT_IMG_RAW         0   /* bare Cortex-M vector table at the slot start (FreeRTOS, bare metal) */
#endif

/* ---- boot-time image check --------------------------------------------------------
 *   0 every boot: SHA-256 of the payload (and the signature) on every start
 *   1 once:       hash an image the first time it boots; later boots trust the log's
 *                 "hash checked" flag for that image (header CRC still checked)
 *   2 never:      header checks only (uploads through MimiBoot are still hashed before their
 *                 header is written; images written with a debugger are never checked) */
#ifndef MB_BOOT_VERIFY
#define MB_BOOT_VERIFY          0
#endif
#define MB_BOOT_VERIFY_EVERY    0
#define MB_BOOT_VERIFY_ONCE     1
#define MB_BOOT_VERIFY_NEVER    2

/* ---- port-level switches (ports that can't honour one ignore it) -------------------- */
#ifndef MB_FEAT_SCRUB_RAM
#define MB_FEAT_SCRUB_RAM       0   /* wipe the bootloader's own RAM (data, stack) before starting an image */
#endif
#ifndef MB_FEAT_LED
#define MB_FEAT_LED             1   /* light the board LED while waiting for a key */
#endif
#ifndef MB_FEAT_BUTTON
#define MB_FEAT_BUTTON          1   /* the board button opens the menu */
#endif

/* ---- tunables ------------------------------------------------------------------ */
#ifndef MB_MENU_SECS
#define MB_MENU_SECS            10      /* boot menu countdown when the config doesn't set one */
#endif
#ifndef MB_DEFAULT_TRIES
#define MB_DEFAULT_TRIES        3
#endif
#ifndef MB_DEFAULT_TRIAL_MS
#define MB_DEFAULT_TRIAL_MS     15000
#endif
#ifndef MB_STRIKES_MAX
#define MB_STRIKES_MAX          4       /* watchdog resets in a row before a GOOD image is passed over */
#endif

/* ---- consistency: a hand-edited config can't build something broken -------------- */
#if MB_FEAT_RECV && !MB_FEAT_CONSOLE
#error "MB_FEAT_RECV needs MB_FEAT_CONSOLE (uploads arrive over the console)"
#endif
#if MB_FEAT_RECV && !MB_FEAT_SHELL
#error "MB_FEAT_RECV needs MB_FEAT_SHELL (mbtool drives uploads from the command line)"
#endif
#if MB_FEAT_SHELL && !MB_FEAT_CONSOLE
#error "MB_FEAT_SHELL needs MB_FEAT_CONSOLE"
#endif
#if MB_FEAT_SHELL_DIAG && !MB_FEAT_SHELL
#error "MB_FEAT_SHELL_DIAG needs MB_FEAT_SHELL"
#endif
#if MB_BOOT_VERIFY < 0 || MB_BOOT_VERIFY > 2
#error "MB_BOOT_VERIFY is 0 (every boot), 1 (once) or 2 (never)"
#endif
#if defined(MB_REQUIRE_SIGNATURE) && MB_REQUIRE_SIGNATURE && MB_BOOT_VERIFY != MB_BOOT_VERIFY_EVERY
#error "required signatures need the payload hash on every boot (MB_BOOT_VERIFY 0): a signed header says nothing about a payload nobody hashed"
#endif
#if MB_MENU_SECS < 1 || MB_MENU_SECS > 600
#error "MB_MENU_SECS must be 1..600"
#endif
#if MB_FEAT_GRUB && !MB_FEAT_CFG_FILE
#error "MB_FEAT_GRUB needs MB_FEAT_CFG_FILE"
#endif
#if !MB_FEAT_IMG_NATIVE && !MB_FEAT_IMG_MCUBOOT && !MB_FEAT_IMG_RAW
#error "enable at least one image format (MB_FEAT_IMG_NATIVE / _MCUBOOT / _RAW)"
#endif
#if defined(MB_REQUIRE_SIGNATURE) && MB_REQUIRE_SIGNATURE && !MB_FEAT_SIGNATURES
#error "MB_REQUIRE_SIGNATURE needs MB_FEAT_SIGNATURES"
#endif
#if MB_DEFAULT_TRIES < 1 || MB_DEFAULT_TRIES > 255
#error "MB_DEFAULT_TRIES must be 1..255"
#endif

#endif
