/*
 * MimiBoot-Mu - Microchip SAM D21 / D51 internal flash (NVMCTRL)
 *
 *   D21  rows of 256 bytes (erase), pages of 64 bytes (write). ADDR takes a
 *        16-bit-word address (byte address / 2). Commands go in CTRLA.
 *        Manual page writes (CTRLB.MANW): clear the page buffer, fill it with
 *        32-bit writes, Write Page. A page is written once per erase.
 *   D51  blocks of 8 KB (erase), quad-words of 16 bytes (write, ECC: once per
 *        erase). ADDR takes a byte address. Commands go in CTRLB.
 *
 * The layout works in 4 KB (D21) / 8 KB (D51) sectors; an erase walks the
 * rows/blocks inside the range. Units whose new value is all ones are skipped
 * (the core pads its pages with 0xFF), units that already hold the value are
 * skipped, and a unit that is already programmed with something else is
 * refused rather than written twice.
 *
 * The NVM read cache is turned off around every command (as Microchip's
 * reference code and OpenOCD do) and restored afterwards. Every erase is
 * checked blank and every write read back.
 *
 * Every register and flash access goes through RD/WR so tests/sim_samd.c can
 * run this file on a PC against a model of the controller.
 */
#include "core/mimiboot.h"
#include "port/cortexm/mcu.h"

#ifdef MB_HOST_SIM
uint32_t sim_rd(uint32_t a, unsigned bits);
void sim_wr(uint32_t a, uint32_t v, unsigned bits);
#define RD(a, b)        sim_rd((a), (b))
#define WR(a, v, b)     sim_wr((a), (v), (b))
#else
#define RD(a, b)        ((b) == 32 ? REG32(a) : (b) == 16 ? REG16(a) : REG8(a))
#define WR(a, v, b)     do { if ((b) == 32) REG32(a) = (uint32_t)(v); else if ((b) == 16) REG16(a) = (uint16_t)(v); \
                             else REG8(a) = (uint8_t)(v); } while (0)
#endif

#define NVM             0x41004000u
#define CMDEX           (0xA5u << 8)
#define WAIT_LIMIT      20000000u

#if MB_SAMD_SERIES == 21
#define N_CTRLA         (NVM + 0x00)    /* 16-bit: CMD 6:0, CMDEX 15:8 */
#define N_CTRLB         (NVM + 0x04)
#define N_INTFLAG       (NVM + 0x14)    /* 8-bit: READY 0, ERROR 1 */
#define N_STATUS        (NVM + 0x18)    /* 16-bit: PROGE 2, LOCKE 3, NVME 4 (write 1 to clear) */
#define N_ADDR          (NVM + 0x1C)
#define CTRLB_MANW      (1u << 7)
#define CTRLB_CACHEDIS  (1u << 18)
#define CMD_ER          0x02u
#define CMD_WP          0x04u
#define CMD_PBC         0x44u
#define STATUS_ERR      0x1Cu
#define UNIT            64u             /* one page */
#else
#define N_CTRLA         (NVM + 0x00)    /* 16-bit: WMODE 5:4, CACHEDIS0/1 14/15 */
#define N_CTRLB         (NVM + 0x04)    /* 16-bit: CMD 6:0, CMDEX 15:8 */
#define N_INTFLAG       (NVM + 0x10)    /* 16-bit: DONE 0, ADDRE 1, PROGE 2, LOCKE 3, ECCSE 4, ECCDE 5, NVME 6 */
#define N_STATUS        (NVM + 0x12)    /* 16-bit: READY 0 */
#define N_ADDR          (NVM + 0x14)
#define CTRLA_WMODE     (3u << 4)
#define CTRLA_CACHEDIS  (3u << 14)
#define CMD_EB          0x01u
#define CMD_WQW         0x04u
#define CMD_PBC         0x15u
#define INTFLAG_ERR     0x4Eu           /* ADDRE, PROGE, LOCKE, NVME */
#define UNIT            16u             /* one quad-word */
#endif

static uint32_t saved;

static int wait_ready(void) {
    for (uint32_t n = 0;; n++) {
#if MB_SAMD_SERIES == 21
        if (RD(N_INTFLAG, 8) & 1u) break;
#else
        if (RD(N_STATUS, 16) & 1u) break;
#endif
        if (n > WAIT_LIMIT) return MB_E_TIMEOUT;
    }
    return MB_OK;
}

/* run one command, report its errors */
static int command(uint32_t cmd) {
    int rc = wait_ready();
    if (rc != MB_OK) return rc;
#if MB_SAMD_SERIES == 21
    WR(N_STATUS, STATUS_ERR, 16);
    WR(N_CTRLA, CMDEX | cmd, 16);
    if ((rc = wait_ready()) != MB_OK) return rc;
    return (RD(N_STATUS, 16) & STATUS_ERR) || (RD(N_INTFLAG, 8) & 2u) ? MB_E_IO : MB_OK;
#else
    WR(N_INTFLAG, 0xFFFFu, 16);
    WR(N_CTRLB, CMDEX | cmd, 16);
    if ((rc = wait_ready()) != MB_OK) return rc;
    return (RD(N_INTFLAG, 16) & INTFLAG_ERR) ? MB_E_IO : MB_OK;
#endif
}

static void begin(void) {
    (void)wait_ready();
#if MB_SAMD_SERIES == 21
    saved = RD(N_CTRLB, 32);
    WR(N_CTRLB, saved | CTRLB_MANW | CTRLB_CACHEDIS, 32);
#else
    saved = RD(N_CTRLA, 16);
    WR(N_CTRLA, (saved & ~CTRLA_WMODE) | CTRLA_CACHEDIS, 16);   // manual writes, no cache
#endif
}

static void end(void) {
    (void)wait_ready();
#if MB_SAMD_SERIES == 21
    WR(N_CTRLB, saved, 32);
#else
    WR(N_CTRLA, saved, 16);
#endif
}

/* flash [addr, addr+n) all equal to v? */
static bool flash_all(uint32_t addr, uint32_t n, uint8_t v) {
    uint32_t w = v * 0x01010101u;
    for (uint32_t i = 0; i < n; i += 4)
        if (RD(addr + i, 32) != w) return false;
    return true;
}

static bool buf_all(const uint8_t* p, uint32_t n, uint8_t v) {
    while (n--) if (*p++ != v) return false;
    return true;
}

static uint32_t le32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* flash [addr, addr+n) holds p? */
static bool flash_eq(uint32_t addr, const uint8_t* p, uint32_t n) {
    for (uint32_t i = 0; i < n; i += 4)
        if (RD(addr + i, 32) != le32(p + i)) return false;
    return true;
}

int mcu_flash_erase(uint32_t off, size_t len) {
    if (off >= MB_FLASH_SIZE || len > MB_FLASH_SIZE - off) return MB_E_BADARG;
    uint32_t end_off = off + (uint32_t)len;
    off -= off % MB_SAMD_ERASE;                             // whole rows / blocks (regions are aligned to them)
    int rc = MB_OK;
    begin();
    for (; rc == MB_OK && off < end_off; off += MB_SAMD_ERASE) {
        uint32_t addr = MB_FLASH_BASE + off;
        if (flash_all(addr, MB_SAMD_ERASE, 0xFF)) continue;
#ifndef MB_CM_CLIENT
        mcu_wdt_feed();
#endif
#if MB_SAMD_SERIES == 21
        WR(N_ADDR, addr >> 1, 32);                          // 16-bit-word address
        rc = command(CMD_ER);
#else
        WR(N_ADDR, addr, 32);
        rc = command(CMD_EB);
#endif
        if (rc == MB_OK && !flash_all(addr, MB_SAMD_ERASE, 0xFF)) rc = MB_E_IO;
    }
    end();
    return rc;
}

int mcu_flash_program(uint32_t off, const void* buf, size_t len) {
    if (off >= MB_FLASH_SIZE || len > MB_FLASH_SIZE - off || (off % UNIT) || (len % UNIT)) return MB_E_BADARG;
    const uint8_t* src = buf;
    int rc = MB_OK;
    begin();
    for (uint32_t i = 0; rc == MB_OK && i < len; i += UNIT) {
        uint32_t addr = MB_FLASH_BASE + off + i;
        const uint8_t* want = src + i;
        if (buf_all(want, UNIT, 0xFF) || flash_eq(addr, want, UNIT)) continue;
        if (!flash_all(addr, UNIT, 0xFF)) { rc = MB_E_IO; break; }   // programmed already: needs an erase first
        if ((rc = command(CMD_PBC)) != MB_OK) break;        // page buffer to all ones
        for (uint32_t k = 0; k < UNIT; k += 4)              // 32-bit writes only
            WR(addr + k, le32(want + k), 32);
#if MB_SAMD_SERIES == 21
        WR(N_ADDR, addr >> 1, 32);                          // the buffer writes set it too; be explicit
        rc = command(CMD_WP);
#else
        WR(N_ADDR, addr, 32);
        rc = command(CMD_WQW);
#endif
        if (rc == MB_OK && !flash_eq(addr, want, UNIT)) rc = MB_E_IO;
    }
    end();
    return rc;
}
