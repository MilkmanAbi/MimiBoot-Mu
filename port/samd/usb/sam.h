/*
 * MimiBoot-Mu: the part of a SAM D device header that TinyUSB's dcd_samd.c
 * uses, and nothing else: the register types, the IRQ numbers, the core
 * configuration for CMSIS, the USB peripheral and the NVM fuse row that holds
 * the USB pad calibration. Values from Microchip's samd21g18a.h /
 * samd51j19a.h (third_party/microchip, Apache-2.0); the register layouts are
 * Microchip's own component headers, included unchanged.
 */
#ifndef MB_SAMD_USB_SAM_H
#define MB_SAMD_USB_SAM_H

#include <stdint.h>

#ifndef MB_SAMD_SERIES
#error "MB_SAMD_SERIES (21 or 51) comes from the generated config header"
#endif

#define _U_(x)  x ## U                 /* literal helpers the component headers use */
#define _L_(x)  x ## L
#define _UL_(x) x ## UL

typedef volatile const uint32_t RoReg;
typedef volatile const uint16_t RoReg16;
typedef volatile const uint8_t  RoReg8;
typedef volatile       uint32_t WoReg;
typedef volatile       uint16_t WoReg16;
typedef volatile       uint8_t  WoReg8;
typedef volatile       uint32_t RwReg;
typedef volatile       uint16_t RwReg16;
typedef volatile       uint8_t  RwReg8;

#if MB_SAMD_SERIES == 21
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13, SVCall_IRQn = -5, PendSV_IRQn = -2, SysTick_IRQn = -1,
    USB_IRQn = 7,
} IRQn_Type;
#define __CM0PLUS_REV          1
#define __MPU_PRESENT          0
#define __NVIC_PRIO_BITS       2
#define __VTOR_PRESENT         1
#define __Vendor_SysTickConfig 0
#include "core_cm0plus.h"
#include "component/usb.h"
#include "component/nvmctrl.h"
#define NVMCTRL_OTP4           (0x00806020UL)
#define USB                    ((Usb *)0x41005000UL)
#else
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13, MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5, DebugMonitor_IRQn = -4, PendSV_IRQn = -2, SysTick_IRQn = -1,
    USB_0_IRQn = 80, USB_1_IRQn = 81, USB_2_IRQn = 82, USB_3_IRQn = 83,
} IRQn_Type;
#define __CM4_REV              1
#define __FPU_PRESENT          1
#define __MPU_PRESENT          1
#define __NVIC_PRIO_BITS       3
#define __VTOR_PRESENT         1
#define __Vendor_SysTickConfig 0
#include "core_cm4.h"
#include "component/usb.h"
#include "component/nvmctrl.h"
#define NVMCTRL_SW0            (0x00800080UL)
#define USB                    ((Usb *)0x41000000UL)
#endif
#include "instance/usb.h"

#endif
