/*
 * MimiBoot-Mu - compile-time feature switches for the Komorebi core
 *
 * muconfigurator.py writes a config header (mb_config.h) and passes it with
 * -DMB_CONFIG_HEADER="path". Every switch defaults to on, so a build without
 * a config header is the full build.
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
#ifndef MB_FEAT_ECDSA
#define MB_FEAT_ECDSA           0   /* ECDSA P-256 signatures (micro-ecc), besides Ed25519 */
#endif
#ifndef MB_FEAT_CFG_SIGNED
#define MB_FEAT_CFG_SIGNED      0   /* only a config signed with a trusted key is used */
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
#ifndef MB_FEAT_BOOT_LOCK
#define MB_FEAT_BOOT_LOCK       0   /* write-protect the bootloader region until reset before starting an image */
#endif
#ifndef MB_CONSOLE_USB
#define MB_CONSOLE_USB          0   /* the console over native USB (SAM D: port/samd/samd_usb.c) */
#endif
#ifndef MB_FEAT_SMP
#define MB_FEAT_SMP             0   /* mcumgr / SMP over the console (core/mb_smp.c) */
#endif
#ifndef MB_FEAT_REVOKE                  /* key revocation (REVOKE_KEYS): on when the build has revocation keys */
#ifdef MB_REVOKE_KEY_COUNT
#define MB_FEAT_REVOKE          1
#else
#define MB_FEAT_REVOKE          0
#endif
#endif
#ifndef MB_FEAT_ENC
#define MB_FEAT_ENC             0   /* take encrypted images (core/mb_enc.c): decrypted as they are installed */
#endif
#ifndef MB_FEAT_OS_HOOKS
#define MB_FEAT_OS_HOOKS        1   /* OS hooks: handoff v2 (how the last run ended, features, seed) + the RAM mailbox (core/mb_mailbox.c) */
#endif
#ifndef MB_FEAT_LMS
#define MB_FEAT_LMS             0   /* LMS (hash-based, post-quantum) image signatures (core/mb_lms.c) */
#endif
#ifndef MB_FEAT_BOOT_RECORD
#define MB_FEAT_BOOT_RECORD     0   /* measured boot: a record of what was checked and run (mimiboot/mb_record.h) */
#endif
#if defined(MB_CM_CLIENT) || defined(MB_RP2040_CLIENT) || defined(MB_RP2350_CLIENT)
#undef MB_FEAT_ENC                  /* an app never decrypts: the key stays in the bootloader */
#define MB_FEAT_ENC             0
#endif
#ifndef MB_FEAT_TWO_STAGE
#define MB_FEAT_TWO_STAGE       0   /* fixed stage 0 + two updatable stage-1 copies (core/mb_stage0.c) */
#endif
#ifndef MB_FEAT_LOCK_GOLDEN
#define MB_FEAT_LOCK_GOLDEN     0   /* with BOOT_LOCK: the golden slot is locked as well */
#endif
#ifndef MB_FEAT_PROTECTED_FLOOR
#define MB_FEAT_PROTECTED_FLOOR 0   /* rollback floors also kept in the (locked) bootloader region */
#endif
#ifndef MB_FEAT_FAULT_HARDENING
#define MB_FEAT_FAULT_HARDENING 1   /* constant-time double compares, proof tokens, recheck before the jump */
#endif
#ifndef MB_FEAT_CONSOLE_AUTH
#define MB_FEAT_CONSOLE_AUTH    0   /* state-changing console commands need a signed challenge ('unlock') */
#endif
#ifndef MB_FEAT_DEBUG_LOCK
#define MB_FEAT_DEBUG_LOCK      0   /* never open the debug port; force it closed until reset where the chip can */
#endif
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
#if MB_FEAT_CONSOLE_AUTH && (!MB_FEAT_SHELL || !MB_FEAT_SIGNATURES)
#error "MB_FEAT_CONSOLE_AUTH needs MB_FEAT_SHELL (the 'unlock' command) and MB_FEAT_SIGNATURES (Ed25519)"
#endif
#if MB_FEAT_PROTECTED_FLOOR && !MB_FEAT_BOOT_LOCK
#error "MB_FEAT_PROTECTED_FLOOR needs MB_FEAT_BOOT_LOCK: an unlocked copy protects nothing"
#endif
#if defined(MB_BOOT_DIAGNOSTICS) && defined(MB_REQUIRE_SIGNATURE) && MB_REQUIRE_SIGNATURE
#error "MB_BOOT_DIAGNOSTICS is a bench-only build (it adds raw register dumps): not with required signatures"
#endif
#if MB_MENU_SECS < 1 || MB_MENU_SECS > 600
#error "MB_MENU_SECS must be 1..600"
#endif
#if MB_FEAT_ENC && !MB_FEAT_RECV
#error "MB_FEAT_ENC needs MB_FEAT_RECV: encrypted images are decrypted as they are uploaded"
#endif
#if MB_FEAT_SMP && (!MB_FEAT_RECV || !MB_FEAT_CONSOLE)
#error "MB_FEAT_SMP needs MB_FEAT_RECV (its uploads write slots the same way) and the console"
#endif
#if MB_FEAT_TWO_STAGE && !MB_FEAT_IMG_NATIVE
#error "MB_FEAT_TWO_STAGE needs MB_FEAT_IMG_NATIVE: stage-1 copies are MimiBoot images"
#endif
#if MB_FEAT_CFG_SIGNED && (!MB_FEAT_CFG_FILE || !MB_FEAT_SIGNATURES)
#error "MB_FEAT_CFG_SIGNED needs MB_FEAT_CFG_FILE and MB_FEAT_SIGNATURES"
#endif
#if MB_FEAT_OS_HOOKS && !MB_FEAT_HANDOFF
#error "MB_FEAT_OS_HOOKS needs MB_FEAT_HANDOFF: they extend the handoff, and the mailbox lives in its buffer"
#endif
#if MB_FEAT_GRUB && !MB_FEAT_CFG_FILE
#error "MB_FEAT_GRUB needs MB_FEAT_CFG_FILE"
#endif
#if !MB_FEAT_IMG_NATIVE && !MB_FEAT_IMG_MCUBOOT && !MB_FEAT_IMG_RAW
#error "enable at least one image format (MB_FEAT_IMG_NATIVE / _MCUBOOT / _RAW)"
#endif
#if defined(MB_REQUIRE_SIGNATURE) && MB_REQUIRE_SIGNATURE && !MB_FEAT_SIGNATURES && !MB_FEAT_LMS
#error "MB_REQUIRE_SIGNATURE needs MB_FEAT_SIGNATURES or MB_FEAT_LMS"
#endif
#if MB_DEFAULT_TRIES < 1 || MB_DEFAULT_TRIES > 255
#error "MB_DEFAULT_TRIES must be 1..255"
#endif

#endif
