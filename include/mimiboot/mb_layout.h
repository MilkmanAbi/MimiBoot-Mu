/*
 * MimiBoot - flash layout
 *
 * Offsets from the start of flash, all sector aligned. Slot roles:
 *   AB      slots 0 and 1: the update pair (trial boots, rollback)
 *   GOLDEN  slot 2: recovery, only ever replaced by a newer version
 *   AUX     slots 3+: extra images (a RISC-V build, a test kernel, a tool),
 *           booted when a menu/config entry asks for them
 *
 * Default for a 16 MB part (Waveshare RP2350-LCD-1.28):
 *
 *   0x000000  240 KB  MimiBoot (room for a universal Arm + RISC-V build)
 *   0x03C000    8 KB  boot control log (2 sectors)
 *   0x03E000    8 KB  boot config (2 sectors)
 *   0x040000    2 MB  slot A
 *   0x240000    2 MB  slot B
 *   0x440000    1 MB  golden
 *   0x540000    2 MB  slot C
 *   0x740000    2 MB  slot D
 *   0x940000  6.75 MB data: the OS's (e.g. settings in the last sector)
 */
#ifndef MIMIBOOT_LAYOUT_H
#define MIMIBOOT_LAYOUT_H

#include <stdint.h>

#define MB_MAX_SLOTS    6

#define MB_ROLE_NONE    0
#define MB_ROLE_AB      1
#define MB_ROLE_GOLDEN  2
#define MB_ROLE_AUX     3

typedef struct {
    uint32_t offset, size;
} mb_region_t;

typedef struct {
    uint32_t offset, size;
    uint8_t role;               /* MB_ROLE_* */
    char name[7];               /* "a", "b", "g", "c"... what the console and config call it */
} mb_slot_def_t;

typedef struct {
    uint32_t flash_size;
    uint32_t sector_size;       /* erase unit */
    uint32_t page_size;         /* program unit */
    mb_region_t boot;           /* the bootloader itself */
    mb_region_t log[2];
    mb_region_t cfg[2];
    uint8_t n_slots;
    mb_slot_def_t slot[MB_MAX_SLOTS];   /* [0]=A, [1]=B (AB), [2]=golden, then aux */
    mb_region_t data;           /* everything the bootloader doesn't own */
} mb_layout_t;

#define MB_LAYOUT_2M_INIT { \
 .flash_size=2u<<20,.sector_size=4096,.page_size=256, \
 .boot={0,0x3c000},.log={{0x3c000,4096},{0x3d000,4096}},.cfg={{0x3e000,4096},{0x3f000,4096}}, \
 .n_slots=4,.slot={{0x40000,0x80000,MB_ROLE_AB,"a"},{0xc0000,0x80000,MB_ROLE_AB,"b"},{0x140000,0x40000,MB_ROLE_GOLDEN,"g"},{0x180000,0x40000,MB_ROLE_AUX,"c"}},.data={0x1c0000,0x40000} \
}

#define MB_LAYOUT_16M_INIT { \
    .flash_size = 16u << 20, .sector_size = 4096, .page_size = 256, \
    .boot = { 0x000000, 0x03C000 }, \
    .log = { { 0x03C000, 0x1000 }, { 0x03D000, 0x1000 } }, \
    .cfg = { { 0x03E000, 0x1000 }, { 0x03F000, 0x1000 } }, \
    .n_slots = 5, \
    .slot = { { 0x040000, 0x200000, MB_ROLE_AB, "a" }, { 0x240000, 0x200000, MB_ROLE_AB, "b" }, \
              { 0x440000, 0x100000, MB_ROLE_GOLDEN, "g" }, { 0x540000, 0x200000, MB_ROLE_AUX, "c" }, \
              { 0x740000, 0x200000, MB_ROLE_AUX, "d" } }, \
    .data = { 0x940000, (16u << 20) - 0x940000 }, \
}

/* 4 MB part (Pico 2): A/B 1 MB, golden 512 KB, one aux 512 KB, 768 KB data */
#define MB_LAYOUT_4M_INIT { \
    .flash_size = 4u << 20, .sector_size = 4096, .page_size = 256, \
    .boot = { 0x000000, 0x03C000 }, \
    .log = { { 0x03C000, 0x1000 }, { 0x03D000, 0x1000 } }, \
    .cfg = { { 0x03E000, 0x1000 }, { 0x03F000, 0x1000 } }, \
    .n_slots = 4, \
    .slot = { { 0x040000, 0x100000, MB_ROLE_AB, "a" }, { 0x140000, 0x100000, MB_ROLE_AB, "b" }, \
              { 0x240000, 0x080000, MB_ROLE_GOLDEN, "g" }, { 0x2C0000, 0x080000, MB_ROLE_AUX, "c" } }, \
    .data = { 0x340000, 0x0C0000 }, \
}

#endif
