/*
 * MimiBoot-Mu Lite - what the AVR bootloader and the apps it starts agree on.
 * Apps include client/mu_avr.h, which includes this.
 *
 *   EEPROM, top 16 bytes (E2END-15 .. E2END): the app record
 *     [0] 'M' [1] 'u'   magic (anything else: no record)
 *     [2..5]  length of the app in bytes (u32 LE), from address 0
 *     [6..9]  CRC-32 of those bytes (u32 LE)
 *     [10]    state: MU_ST_CONFIRMED (0xFF also = confirmed) or MU_ST_TRIAL
 *     [11]    trial boots left
 *     [12]    stage magic 'S' when a staged image waits to be installed
 *     [13..15] reserved
 *   staged image record (when [12] == 'S'): length/CRC reuse an extra 8
 *   bytes below the app record: E2END-23 .. E2END-16 (u32 len, u32 crc)
 *
 *   RAM, top 8 bytes (RAMEND-7 .. RAMEND): survive a watchdog reset
 *     RAMEND-3..RAMEND    MU_REQ_MAGIC: "start the bootloader, not the app"
 *     RAMEND-7..RAMEND-4  "Mu" + kind + MCUSR (internal): start the app right after the
 *                         watchdog reset, untouched peripherals. kind G: after an upload,
 *                         R: nobody came; MCUSR: the original reset cause, for the handoff
 *
 *   Handoff, in registers the C runtime doesn't touch:
 *     r2      MCUSR at reset (Optiboot convention)
 *     GPIOR0  MU_HANDOFF_SIG when started by MimiBoot
 *     GPIOR1  MCUSR again
 *     GPIOR2  MU_HF_* flags
 *
 *   Flash service (MU_FEAT_SPM_API): 8 bytes at FLASHEND-7:
 *     'M' 'u'   api version   0   then at +4: jmp mu_spm (the entry point)
 *     void mu_spm(uint8_t op, uint32_t byte_address, const uint8_t* page)
 */
#ifndef MU_LITE_H
#define MU_LITE_H

#define MU_REC_MAGIC0       'M'
#define MU_REC_MAGIC1       'u'
#define MU_ST_CONFIRMED     0xC0
#define MU_ST_TRIAL         0x7A
#define MU_STAGE_MAGIC      'S'
#define MU_REC_OFF          (E2END - 15)
#define MU_STAGE_OFF        (E2END - 23)

#define MU_REQ_MAGIC        0x4C42754DUL    /* "MuBL" */
#define MU_REQ_ADDR         (RAMEND - 3)
#define MU_GO_ADDR          (RAMEND - 7)
#define MU_RAM_RESERVED     8

#define MU_HANDOFF_SIG      0xB7
#define MU_HF_VERIFIED      0x01    /* the app's CRC matched its record */
#define MU_HF_TRIAL         0x02    /* this boot is a trial: call mu_confirm() */
#define MU_HF_UPLOADED      0x04    /* first start after an upload */
#define MU_HF_INSTALLED     0x08    /* first start after installing a staged image */
#define MU_HF_NO_RECORD     0x10    /* no app record (flashed by ISP?): started unchecked */

#define MU_API_VERSION      1
#define MU_SPM_ERASE        1       /* erase the page at byte_address */
#define MU_SPM_WRITE        2       /* erase + write one page from page[] */
#define MU_API_ADDR         (FLASHEND - 7)
#define MU_API_ENTRY        (MU_API_ADDR + 4)

#endif
