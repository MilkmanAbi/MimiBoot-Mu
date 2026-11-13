/*
 * MimiBoot-Mu Lite - app side (AVR). Header only: #include "mu_avr.h"
 * (compile with -I<MimiBoot-Ext>/client -I<MimiBoot-Ext>/lite).
 *
 *   mu_handoff_t h = mu_handoff();     // did MimiBoot start us? why did we reset?
 *   if (h.flags & MU_HF_TRIAL) mu_confirm();   // trial boots: "this build works"
 *   mu_enter_bootloader();             // reboot and wait for an upload
 *   mu_reboot();                       // plain reboot
 *
 * With the flash service built in (SPM_API):
 *   mu_api_present()                   // is it there?
 *   mu_spm(MU_SPM_WRITE, addr, page)   // write one SPM_PAGESIZE page of the app area
 * With staged updates (STAGED_UPDATE): write the new image from
 * MU_STAGE_BASE on (page by page with mu_spm), then
 *   mu_stage_commit(length, mu_crc32_flash(MU_STAGE_BASE, length));   // reboots and installs
 *
 * MU_BOOT_SIZE must match the bootloader's section (mimiconf prints it; 2048 by default).
 */
#ifndef MU_AVR_H
#define MU_AVR_H

#include <avr/eeprom.h>
#include <avr/interrupt.h>
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/wdt.h>
#include <stdint.h>
#include "mu_lite.h"

#ifndef MU_BOOT_SIZE
#define MU_BOOT_SIZE 2048UL
#endif
#define MU_BOOT_START   ((uint32_t)FLASHEND + 1 - MU_BOOT_SIZE)
#define MU_STAGE_BASE   ((MU_BOOT_START / 2) & ~(uint32_t)(SPM_PAGESIZE - 1))
#define MU_STAGE_MAX    (MU_BOOT_START - MU_STAGE_BASE)

typedef struct {
    uint8_t by_mimiboot;    /* 1: started by MimiBoot-Mu */
    uint8_t mcusr;          /* reset cause bits (PORF, EXTRF, BORF, WDRF) */
    uint8_t flags;          /* MU_HF_* */
} mu_handoff_t;

/* Read once, early: nothing in the C runtime touches GPIOR0..2. */
static inline mu_handoff_t mu_handoff(void) {
    mu_handoff_t h;
    h.by_mimiboot = GPIOR0 == MU_HANDOFF_SIG;
    h.mcusr = h.by_mimiboot ? GPIOR1 : 0;
    h.flags = h.by_mimiboot ? GPIOR2 : 0;
    return h;
}

static inline void mu_reboot(void) __attribute__((noreturn));
static inline void mu_reboot(void) {
    cli();
    wdt_disable();              /* a trial's 8 s period may be running: start over at 15 ms */
    wdt_enable(WDTO_15MS);
    for (;;) {}
}

/* Leave a word at the top of RAM (it survives the watchdog reset) and reset. */
static inline void mu_enter_bootloader(void) __attribute__((noreturn));
static inline void mu_enter_bootloader(void) {
    cli();
    *(volatile uint32_t*)MU_REQ_ADDR = MU_REQ_MAGIC;
    wdt_disable();              /* a trial's 8 s period may be running: start over at 15 ms */
    wdt_enable(WDTO_15MS);
    for (;;) {}
}

/* The running build is good: no more trial boots. Also stops the trial watchdog. */
static inline void mu_confirm(void) {
    if (eeprom_read_byte((const uint8_t*)(MU_REC_OFF + 10)) == MU_ST_TRIAL)
        eeprom_update_byte((uint8_t*)(MU_REC_OFF + 10), MU_ST_CONFIRMED);
    wdt_disable();
}

static inline uint8_t mu_in_trial(void) {
    return eeprom_read_byte((const uint8_t*)(MU_REC_OFF + 10)) == MU_ST_TRIAL;
}

/* ---- flash service --------------------------------------------------------- */
#if FLASHEND > 0x1FFFF
/* >128 KB parts (ATmega2560) need EIND for the call: not supported yet. */
#define mu_api_present() 0
#else
static inline uint8_t mu_api_present(void) {
    return pgm_read_byte((uint16_t)MU_API_ADDR) == 'M' && pgm_read_byte((uint16_t)(MU_API_ADDR + 1)) == 'u';
}
typedef void (*mu_spm_fn)(uint8_t op, uint32_t addr, const uint8_t* page);
static inline void mu_spm(uint8_t op, uint32_t addr, const uint8_t* page) {
    ((mu_spm_fn)(uint16_t)(MU_API_ENTRY / 2))(op, addr, page);
}
#endif

static inline uint32_t mu_crc32_flash(uint32_t addr, uint32_t len) {
    uint32_t c = 0xFFFFFFFFUL;
    while (len--) {
#if FLASHEND > 0xFFFF
        c ^= pgm_read_byte_far(addr++);
#else
        c ^= pgm_read_byte((uint16_t)addr++);
#endif
        for (uint8_t k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320UL & -(c & 1));
    }
    return ~c;
}

/* A new image is waiting at MU_STAGE_BASE: record it and reboot into the installer. */
static inline void mu_stage_commit(uint32_t len, uint32_t crc) __attribute__((noreturn));
static inline void mu_stage_commit(uint32_t len, uint32_t crc) {
    eeprom_update_dword((uint32_t*)MU_STAGE_OFF, len);
    eeprom_update_dword((uint32_t*)(MU_STAGE_OFF + 4), crc);
    eeprom_update_byte((uint8_t*)(MU_REC_OFF + 12), MU_STAGE_MAGIC);
    mu_reboot();
}

#endif
