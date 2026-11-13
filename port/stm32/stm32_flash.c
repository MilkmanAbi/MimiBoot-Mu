/*
 * MimiBoot-Mu - STM32 internal flash, three controller families
 *
 *   F0F1    F0, F1, F3: pages, half-word programming; a half-word that isn't
 *           blank can only be written to 0x0000
 *   F2F4    F2, F4, F7: sectors of mixed sizes, word programming (x32: 2.7-3.6 V)
 *   L4G0G4  L4, G0, G4: pages, double-word programming with ECC; a double-word
 *           can be programmed once per erase
 *
 * Every erase is checked blank afterwards and every program is read back, so
 * a controller that silently does nothing (QEMU has no flash interface) or
 * a write that didn't take reports MB_E_IO instead of corrupting the log.
 * Units whose new value is all ones are skipped ("0xFF programs nothing"):
 * that keeps ECC parts writable in the core's page-padded writes.
 */
#include "core/mimiboot.h"
#include "port/stm32/stm32.h"
#include <string.h>

#define F MB_STM32_FLASH_REGS
#define WAIT_LIMIT 20000000u

typedef struct { uint32_t start, size, count; } grp_t;
static const grp_t groups[] = MB_SECTOR_GROUPS;

static bool sector_at(uint32_t off, uint32_t* idx, uint32_t* start, uint32_t* size) {
    uint32_t base_idx = 0;
    for (unsigned g = 0; g < sizeof groups / sizeof groups[0]; g++) {
        const grp_t* s = &groups[g];
        if (off >= s->start && off - s->start < s->size * s->count) {
            uint32_t k = (off - s->start) / s->size;
            *idx = base_idx + k;
            *start = s->start + k * s->size;
            *size = s->size;
            return true;
        }
        base_idx += s->count;
    }
    return false;
}

#if defined(MB_STM32_FLASH_F0F1)
/* FLASH: KEYR 0x04, SR 0x0C, CR 0x10, AR 0x14 */
#define KEYR    (F + 0x04)
#define SR      (F + 0x0C)
#define CR      (F + 0x10)
#define AR      (F + 0x14)
#define SR_BSY  (1u << 0)
#define SR_ERR  ((1u << 2) | (1u << 4))     /* PGERR, WRPRTERR */
#define SR_EOP  (1u << 5)
#define CR_PG   (1u << 0)
#define CR_PER  (1u << 1)
#define CR_STRT (1u << 6)
#define CR_LOCK (1u << 7)
#define UNIT    2u
#elif defined(MB_STM32_FLASH_F2F4)
/* FLASH: KEYR 0x04, SR 0x0C, CR 0x10 */
#define KEYR    (F + 0x04)
#define SR      (F + 0x0C)
#define CR      (F + 0x10)
#define SR_BSY  (1u << 16)
#define SR_ERR  ((1u << 1) | (0xFu << 4))   /* OPERR, WRPERR, PGAERR, PGPERR, PGSERR */
#define SR_EOP  (1u << 0)
#define CR_PG   (1u << 0)
#define CR_SER  (1u << 1)
#define CR_SNB  (0x1Fu << 3)
#define CR_PSIZE (3u << 8)
#define CR_X32  (2u << 8)
#define CR_STRT (1u << 16)
#define CR_LOCK (1u << 31)
#define UNIT    4u
#ifndef MB_STM32_SNB_GAP_AT                 /* 2 MB dual-bank F42x/F43x: bank 2 sectors start at SNB 16 */
#define MB_STM32_SNB_GAP_AT 0
#endif
#elif defined(MB_STM32_FLASH_L4G0G4)
/* FLASH: KEYR 0x08, SR 0x10, CR 0x14 */
#define KEYR    (F + 0x08)
#define SR      (F + 0x10)
#define CR      (F + 0x14)
#define SR_BUSY ((1u << 16) | (1u << 18))   /* BSY(1), CFGBSY (G0; reserved-0 elsewhere) */
#define SR_BSY  SR_BUSY
#define SR_ERR  0xC3FAu                     /* OPERR..FASTERR, RDERR, OPTVERR */
#define SR_EOP  (1u << 0)
#define CR_PG   (1u << 0)
#define CR_PER  (1u << 1)
#define CR_PNB  (0x3FFu << 3)
#define CR_STRT (1u << 16)
#define CR_LOCK (1u << 31)
#define UNIT    8u
#else
#error "no STM32 flash family selected"
#endif

static int wait_idle(void) {
    for (uint32_t n = 0; REG32(SR) & SR_BSY; n++)
        if (n > WAIT_LIMIT) return MB_E_TIMEOUT;
    uint32_t sr = REG32(SR);
    REG32(SR) = sr & (SR_ERR | SR_EOP);     // write-1-to-clear
    return (sr & SR_ERR) ? MB_E_IO : MB_OK;
}

static void unlock(void) {
    if (REG32(CR) & CR_LOCK) {
        REG32(KEYR) = 0x45670123u;
        REG32(KEYR) = 0xCDEF89ABu;
    }
}
static void lock(void) { REG32(CR) |= CR_LOCK; }

static bool blank(uint32_t addr, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 4)
        if (REG32(addr + i) != 0xFFFFFFFFu) return false;
    return true;
}

static int erase_one(uint32_t idx, uint32_t start) {
    int rc = wait_idle();
    if (rc == MB_E_TIMEOUT) return rc;
#if defined(MB_STM32_FLASH_F0F1)
    (void)idx;
    REG32(CR) |= CR_PER;
    REG32(AR) = MB_FLASH_BASE + start;
    REG32(CR) |= CR_STRT;
    rc = wait_idle();
    REG32(CR) &= ~CR_PER;
#elif defined(MB_STM32_FLASH_F2F4)
    (void)start;
    uint32_t snb = idx;
#if MB_STM32_SNB_GAP_AT
    if (snb >= MB_STM32_SNB_GAP_AT) snb += 4;
#endif
    REG32(CR) = (REG32(CR) & ~(CR_SNB | CR_PSIZE)) | CR_SER | (snb << 3) | CR_X32;
    REG32(CR) |= CR_STRT;
    rc = wait_idle();
    REG32(CR) &= ~(CR_SER | CR_SNB);
#else
    (void)start;
    uint32_t page = idx, bker = 0;
#if MB_STM32_BANK_PAGES
    if (page >= MB_STM32_BANK_PAGES) { page -= MB_STM32_BANK_PAGES; bker = 1; }
#endif
    uint32_t bk = MB_STM32_BKER_BIT ? (1u << MB_STM32_BKER_BIT) : 0;
    REG32(CR) = (REG32(CR) & ~(CR_PNB | bk)) | CR_PER | (page << 3) | (bker ? bk : 0);
    REG32(CR) |= CR_STRT;
    rc = wait_idle();
    REG32(CR) &= ~(CR_PER | CR_PNB | bk);
#endif
    return rc;
}

int mcu_flash_erase(uint32_t off, size_t len) {
    if (off >= MB_FLASH_SIZE || len > MB_FLASH_SIZE - off) return MB_E_BADARG;
    int rc = MB_OK;
    uint32_t end = off + (uint32_t)len;
    unlock();
    while (rc == MB_OK && off < end) {
        uint32_t idx, start, size;
        if (!sector_at(off, &idx, &start, &size)) { rc = MB_E_BADARG; break; }
#ifndef MB_CM_CLIENT
        mcu_wdt_feed();                     // big F2/F4/F7 sectors take seconds each
#endif
        rc = erase_one(idx, start);
        if (rc == MB_OK && !blank(MB_FLASH_BASE + start, size)) rc = MB_E_IO;
        off = start + size;
    }
    lock();
    return rc;
}

int mcu_flash_program(uint32_t off, const void* buf, size_t len) {
    if (off >= MB_FLASH_SIZE || len > MB_FLASH_SIZE - off || (off % UNIT) || (len % UNIT)) return MB_E_BADARG;
    const uint8_t* src = buf;
    int rc = MB_OK;
    unlock();
    for (uint32_t i = 0; rc == MB_OK && i < len; i += UNIT) {
        uint32_t addr = MB_FLASH_BASE + off + i;
        uint8_t want[8], old[8], ones[8];
        memcpy(want, src + i, UNIT);
        memcpy(old, (const void*)(uintptr_t)addr, UNIT);
        memset(ones, 0xFF, sizeof ones);
        if (!memcmp(want, ones, UNIT)) continue;        // programs nothing
        if (!memcmp(old, want, UNIT)) continue;         // already holds it
#if defined(MB_STM32_FLASH_L4G0G4)
        if (memcmp(old, ones, UNIT)) { rc = MB_E_IO; break; }   // ECC: one write per erase
#endif
        if ((rc = wait_idle()) != MB_OK) break;
        REG32(CR) |= CR_PG;
#if defined(MB_STM32_FLASH_F0F1)
        uint16_t hw;
        memcpy(&hw, want, 2);
        REG16(addr) = hw;
#elif defined(MB_STM32_FLASH_F2F4)
        REG32(CR) = (REG32(CR) & ~CR_PSIZE) | CR_X32 | CR_PG;
        uint32_t w;
        memcpy(&w, want, 4);
        REG32(addr) = w;
#else
        uint32_t w0, w1;
        memcpy(&w0, want, 4);
        memcpy(&w1, want + 4, 4);
        REG32(addr) = w0;
        __asm volatile("isb" ::: "memory");
        REG32(addr + 4) = w1;
#endif
        __asm volatile("dsb" ::: "memory");
        rc = wait_idle();
        REG32(CR) &= ~CR_PG;
        // read back: NOR semantics, bits only go 1 -> 0
        uint8_t got[8];
        memcpy(got, (const void*)(uintptr_t)addr, UNIT);
        for (unsigned k = 0; rc == MB_OK && k < UNIT; k++)
            if (got[k] != (uint8_t)(old[k] & want[k])) rc = MB_E_IO;
    }
    lock();
    return rc;
}
