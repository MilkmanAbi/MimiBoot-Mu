/*
 * MimiBoot-Mu: TinyUSB configuration for the USB console (one CDC-ACM port,
 * device only, no RTOS). TinyUSB reads this from every one of its files.
 */
#ifndef MB_TUSB_CONFIG_H
#define MB_TUSB_CONFIG_H

#ifdef MB_CONFIG_HEADER
#include MB_CONFIG_HEADER
#endif

#if MB_SAMD_SERIES == 21
#define CFG_TUSB_MCU            OPT_MCU_SAMD21
#else
#define CFG_TUSB_MCU            OPT_MCU_SAMD51
#endif
#define CFG_TUSB_OS             OPT_OS_NONE
#define CFG_TUSB_DEBUG          0

#define CFG_TUD_ENABLED         1
#define CFG_TUD_MAX_SPEED       OPT_MODE_FULL_SPEED
#define CFG_TUD_ENDPOINT0_SIZE  64

#define CFG_TUD_CDC             1
#define CFG_TUD_MSC             0
#define CFG_TUD_HID             0
#define CFG_TUD_MIDI            0
#define CFG_TUD_VENDOR          0
#define CFG_TUD_CDC_RX_BUFSIZE  256
#define CFG_TUD_CDC_TX_BUFSIZE  512
#define CFG_TUD_CDC_EP_BUFSIZE  64

#endif
