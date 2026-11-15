/*
 * Host test: port/samd/samd_flash.c against a model of the SAM D21 / D51
 * NVM controller, written from the datasheets. Build with -DMB_HOST_SIM
 * -DMB_SAMD_SERIES=21 or 51 (tests/test_sim_flash.py does).
 *
 * The model is strict where hardware would silently misbehave:
 *   - a page (D21) / quad-word (D51) programmed twice without an erase
 *   - page-buffer writes that aren't 32-bit, or made in an automatic write mode
 *   - a command without the CMDEX key, or with the NVM cache still on
 *   - D21 ADDR is a 16-bit-word address: a byte address would hit the wrong row
 * and it reports LOCKE for a locked region, like BOOTPROT / region locks.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/mimiboot.h"
#include "port/cortexm/mcu.h"

#define NVM         0x41004000u
#define FLASH       MB_FLASH_SIZE
#define LOCKED      0x2000u             /* the first 8 KB is "BOOTPROT": commands there fail */
#if MB_SAMD_SERIES == 21
#define PAGE        64u
#define ERASE       256u
#define WUNIT       64u
#else
#define PAGE        512u
#define ERASE       8192u
#define WUNIT       16u
#endif

static uint8_t flash[FLASH];
static uint8_t written[FLASH / WUNIT];  /* programmed since the last erase */
static uint8_t pb[PAGE];
static uint32_t ctrla, ctrlb, intflag, addr;
#if MB_SAMD_SERIES == 21
static uint32_t status;
#endif
static int violations, commands, feeds;
static const char* last_violation = "";

static void violate(const char* why) { violations++; last_violation = why; fprintf(stderr, "  model: %s\n", why); }

void mcu_wdt_feed(void) { feeds++; }

static void execute(uint32_t cmd) {
    commands++;
#if MB_SAMD_SERIES == 21
    if (!(ctrlb & (1u << 18))) violate("command with the NVM cache on");
    uint32_t a = addr * 2u;             /* ADDR holds a 16-bit-word address */
    switch (cmd) {
    case 0x02: {                        /* ER: erase row */
        uint32_t r = a - a % ERASE;
        if (r >= FLASH) { status |= 1u << 2; intflag |= 2; return; }
        if (r < LOCKED) { status |= 1u << 3; intflag |= 2; return; }
        memset(flash + r, 0xFF, ERASE);
        memset(written + r / WUNIT, 0, ERASE / WUNIT);
        return;
    }
    case 0x04: {                        /* WP: write page */
        uint32_t pg = a - a % PAGE;
        if (pg >= FLASH) { status |= 1u << 2; intflag |= 2; return; }
        if (pg < LOCKED) { status |= 1u << 3; intflag |= 2; return; }
        if (written[pg / WUNIT]) violate("D21 page written twice without an erase");
        for (uint32_t i = 0; i < PAGE; i++) flash[pg + i] &= pb[i];
        written[pg / WUNIT] = 1;
        return;
    }
    case 0x44: memset(pb, 0xFF, PAGE); return;   /* PBC */
    default: violate("unknown D21 command");
    }
#else
    if ((ctrla & (3u << 14)) != (3u << 14)) violate("command with the NVM cache on");
    switch (cmd) {
    case 0x01: {                        /* EB: erase block */
        uint32_t b = addr - addr % ERASE;
        if (b >= FLASH) { intflag |= 1u << 1; return; }
        if (b < LOCKED) { intflag |= 1u << 3; return; }
        memset(flash + b, 0xFF, ERASE);
        memset(written + b / WUNIT, 0, ERASE / WUNIT);
        return;
    }
    case 0x04: {                        /* WQW: write quad-word at ADDR */
        if (addr % 16 || addr >= FLASH) { intflag |= 1u << 1; return; }
        if (addr < LOCKED) { intflag |= 1u << 3; return; }
        if (written[addr / WUNIT]) violate("D51 quad-word written twice without an erase (ECC)");
        for (uint32_t i = 0; i < 16; i++) flash[addr + i] &= pb[(addr % PAGE) + i];
        written[addr / WUNIT] = 1;
        return;
    }
    case 0x15: memset(pb, 0xFF, PAGE); return;   /* PBC */
    default: violate("unknown D51 command");
    }
#endif
}

uint32_t sim_rd(uint32_t a, unsigned bits) {
    if (a < FLASH) {
        uint32_t v = 0;
        for (unsigned i = 0; i < bits / 8; i++) v |= (uint32_t)flash[a + i] << (8 * i);
        return v;
    }
#if MB_SAMD_SERIES == 21
    switch (a - NVM) {
    case 0x00: return ctrla;
    case 0x04: return ctrlb;
    case 0x14: return intflag | 1u;     /* READY: the model is instant */
    case 0x18: return status;
    case 0x1C: return addr;
    }
#else
    switch (a - NVM) {
    case 0x00: return ctrla;
    case 0x04: return ctrlb;
    case 0x10: return intflag;
    case 0x12: return 1u;               /* STATUS.READY */
    case 0x14: return addr;
    }
#endif
    violate("read of an unexpected address");
    return 0;
}

void sim_wr(uint32_t a, uint32_t v, unsigned bits) {
    if (a < FLASH) {                    /* a flash address: the page buffer */
        if (bits != 32) violate("page buffer written with a non-32-bit access");
#if MB_SAMD_SERIES == 21
        if (!(ctrlb & (1u << 7))) violate("page buffer loaded with MANW off (automatic write)");
        addr = a >> 1;                  /* the hardware updates ADDR on buffer writes */
#else
        if (ctrla & (3u << 4)) violate("page buffer loaded in an automatic write mode");
#endif
        for (unsigned i = 0; i < 4; i++) pb[(a % PAGE) + i] = (uint8_t)(v >> (8 * i));
        return;
    }
#if MB_SAMD_SERIES == 21
    switch (a - NVM) {
    case 0x00:
        if ((v >> 8) != 0xA5) { violate("command without the CMDEX key"); return; }
        ctrla = v; execute(v & 0x7F); return;
    case 0x04: ctrlb = v; return;
    case 0x14: intflag &= ~v; return;
    case 0x18: status &= ~v; return;
    case 0x1C: addr = v; return;
    }
#else
    switch (a - NVM) {
    case 0x00: ctrla = v; return;
    case 0x04:
        if ((v >> 8) != 0xA5) { violate("command without the CMDEX key"); return; }
        ctrlb = v; execute(v & 0x7F); return;
    case 0x10: intflag &= ~v; return;
    case 0x14: addr = v; return;
    }
#endif
    violate("write to an unexpected address");
}

/* ------------------------------------------------------------------------------------- */
static int checks, fails;
#define CHECK(c, what) do { checks++; if (!(c)) { fails++; printf("  FAIL %s (line %d)\n", what, __LINE__); } } while (0)

static void fill(uint8_t* b, uint32_t n, uint32_t seed) {
    for (uint32_t i = 0; i < n; i++) b[i] = (uint8_t)(seed * 131u + i * 7u + (i >> 5));
}

int main(void) {
    memset(flash, 0x00, sizeof flash);  /* "factory" content: not blank */
    memset(written, 1, sizeof written);
#if MB_SAMD_SERIES == 21
    ctrlb = 0x00000080u;                /* reset value: MANW */
    const uint32_t ctrl_before = ctrlb;
#else
    ctrla = 0x0004u;                    /* reset value: AUTOWS, WMODE = manual */
    ctrla |= 3u << 4;                   /* pretend an app left automatic-page mode on */
    const uint32_t ctrl_before = ctrla;
#endif
    const uint32_t S = 0x4000;          /* a 16 KB region well clear of the lock */
    uint8_t buf[1024], back[1024];

    /* erase: whole region blank, nothing outside touched */
    CHECK(mcu_flash_erase(S, 0x4000) == MB_OK, "erase a region");
    int blank = 1;
    for (uint32_t i = S; i < S + 0x4000; i++) blank &= flash[i] == 0xFF;
    CHECK(blank, "region blank after erase");
    CHECK(flash[S - 1] == 0x00 && flash[S + 0x4000] == 0x00, "neighbours untouched");
    CHECK(feeds > 0, "watchdog fed during the erase");

    /* erasing blank flash issues no commands */
    commands = 0;
    CHECK(mcu_flash_erase(S, 0x4000) == MB_OK && commands == 0, "already blank: skipped");

    /* the core's write pattern: 256-byte pages, data padded with 0xFF */
    fill(buf, 256, 1);
    memset(buf + 100, 0xFF, 156);
    CHECK(mcu_flash_program(S, buf, 256) == MB_OK, "program a padded page");
    memcpy(back, flash + S, 256);
    CHECK(!memcmp(back, buf, 256), "read back the padded page");
    /* the same page again: units that hold the value are skipped (no double write) */
    CHECK(mcu_flash_program(S, buf, 256) == MB_OK, "re-program identical data");
    /* the rest of that 256-byte page, aligned to the write unit: allowed */
    uint8_t rest[256];
    memset(rest, 0xFF, 256);
    uint32_t from = ((100 + WUNIT - 1) / WUNIT) * WUNIT;
    fill(rest + from, 256 - from, 2);
    CHECK(mcu_flash_program(S, rest, 256) == MB_OK, "fill the untouched units of a page");
    CHECK(!memcmp(flash + S + from, rest + from, 256 - from), "second fill landed");
    /* changing a unit that is already programmed: refused, flash unchanged */
    uint8_t clash[WUNIT];
    memcpy(clash, flash + S, WUNIT);
    clash[0] ^= 0x01;
    memcpy(back, flash + S, WUNIT);
    CHECK(mcu_flash_program(S, clash, WUNIT) == MB_E_IO, "refuse a second write to a unit");
    CHECK(!memcmp(back, flash + S, WUNIT), "refused write changed nothing");

    /* a big block of data across several pages / rows */
    fill(buf, 1024, 3);
    CHECK(mcu_flash_program(S + 0x1000, buf, 1024) == MB_OK, "program 1 KB");
    CHECK(!memcmp(flash + S + 0x1000, buf, 1024), "1 KB read back");

    /* erase granularity: a 4 KB erase covers whole rows (D21) / the whole 8 KB block (D51) */
    fill(buf, 256, 4);
    CHECK(mcu_flash_program(S + 0x3000, buf, 256) == MB_OK, "program in the upper half");
    CHECK(mcu_flash_erase(S + 0x2000, 0x1000) == MB_OK, "erase 4 KB");
#if MB_SAMD_SERIES == 21
    CHECK(flash[S + 0x3000] != 0xFF || buf[0] == 0xFF, "D21: rows outside the 4 KB stay");
#else
    CHECK(flash[S + 0x3000] == 0xFF, "D51: the whole 8 KB block is erased");
#endif
    CHECK(flash[S + 0x2000] == 0xFF, "erased range is blank");

    /* locked region (BOOTPROT): errors, not silence */
    CHECK(mcu_flash_erase(0x0000, 0x1000) == MB_E_IO, "erase in a locked region reports an error");

    /* arguments */
    CHECK(mcu_flash_program(S + 4, buf, WUNIT) == MB_E_BADARG, "unaligned program refused");
    CHECK(mcu_flash_program(S, buf, WUNIT / 2) == MB_E_BADARG, "partial unit refused");
    CHECK(mcu_flash_erase(FLASH, 1) == MB_E_BADARG, "erase past the end refused");

    /* controller left as found */
#if MB_SAMD_SERIES == 21
    CHECK(ctrlb == ctrl_before, "CTRLB (MANW, cache) restored");
#else
    CHECK(ctrla == ctrl_before, "CTRLA (write mode, cache) restored");
#endif
    CHECK(violations == 0, last_violation);
    printf("samd%d flash model: %d checks, %d failed\n", MB_SAMD_SERIES, checks, fails);
    return fails != 0;
}
