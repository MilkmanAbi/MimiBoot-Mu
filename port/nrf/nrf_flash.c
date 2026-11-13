/*
 * MimiBoot-Mu - Nordic nRF51 / nRF52 internal flash (NVMC)
 *
 * Pages: 4 KB on nRF52, 1 KB on nRF51 (MB_NRF_PAGE). The layout works in 4 KB
 * sectors, so an erase walks the pages inside the requested range.
 * Writes are whole 32-bit words with CONFIG = WEN; a word can only be
 * written a few times between erases (n_WRITE), so all-ones words are
 * skipped (the core pads its pages with 0xFF), a word that already holds the
 * value is skipped, and a word that is already programmed with something else
 * is refused rather than written twice.
 *
 * Every erase is checked blank afterwards and every write read back.
 * The CPU stalls while the NVMC works (85 ms per nRF52 page erase).
 */
#include "core/mimiboot.h"
#include "port/cortexm/mcu.h"

#define NVMC            0x4001E000u
#define NVMC_READY      (NVMC + 0x400)
#define NVMC_CONFIG     (NVMC + 0x504)
#define NVMC_ERASEPAGE  (NVMC + 0x508)      /* nRF51: ERASEPCR1, same function */
#define CONFIG_REN      0u
#define CONFIG_WEN      1u
#define CONFIG_EEN      2u
#define WAIT_LIMIT      20000000u

static int ready(void) {
    for (uint32_t n = 0; !(REG32(NVMC_READY) & 1u); n++)
        if (n > WAIT_LIMIT) return MB_E_TIMEOUT;
    return MB_OK;
}

static void config(uint32_t mode) {
    REG32(NVMC_CONFIG) = mode;
    __asm volatile("dsb\n isb" ::: "memory");
    (void)ready();
}

static bool blank(uint32_t addr, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 4)
        if (REG32(addr + i) != 0xFFFFFFFFu) return false;
    return true;
}

int mcu_flash_erase(uint32_t off, size_t len) {
    if (off >= MB_FLASH_SIZE || len > MB_FLASH_SIZE - off) return MB_E_BADARG;
    uint32_t end = off + (uint32_t)len;
    off -= off % MB_NRF_PAGE;                               // whole pages (the layout keeps regions page aligned)
    int rc = MB_OK;
    for (; rc == MB_OK && off < end; off += MB_NRF_PAGE) {
        uint32_t addr = MB_FLASH_BASE + off;
        if (blank(addr, MB_NRF_PAGE)) continue;             // already erased: spare the cycle (and 85 ms)
#ifndef MB_CM_CLIENT
        mcu_wdt_feed();
#endif
        config(CONFIG_EEN);
        REG32(NVMC_ERASEPAGE) = addr;
        __asm volatile("dsb" ::: "memory");
        rc = ready();
        config(CONFIG_REN);
        if (rc == MB_OK && !blank(addr, MB_NRF_PAGE)) rc = MB_E_IO;
    }
    return rc;
}

int mcu_flash_program(uint32_t off, const void* buf, size_t len) {
    if (off >= MB_FLASH_SIZE || len > MB_FLASH_SIZE - off || (off & 3u) || (len & 3u)) return MB_E_BADARG;
    const uint8_t* src = buf;
    int rc = MB_OK;
    bool on = false;
    for (uint32_t i = 0; rc == MB_OK && i < len; i += 4) {
        uint32_t addr = MB_FLASH_BASE + off + i;
        uint32_t want = (uint32_t)src[i] | (uint32_t)src[i + 1] << 8 | (uint32_t)src[i + 2] << 16 | (uint32_t)src[i + 3] << 24;
        uint32_t old = REG32(addr);
        if (want == 0xFFFFFFFFu || old == want) continue;   // programs nothing / already there
        if (old != 0xFFFFFFFFu) { rc = MB_E_IO; break; }    // would be a second write without an erase
        if (!on) { config(CONFIG_WEN); on = true; }
        REG32(addr) = want;
        __asm volatile("dsb" ::: "memory");
        rc = ready();
        if (rc == MB_OK && REG32(addr) != want) rc = MB_E_IO;
    }
    if (on) config(CONFIG_REN);
    return rc;
}
