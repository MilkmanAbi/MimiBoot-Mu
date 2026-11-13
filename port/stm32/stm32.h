/*
 * MimiBoot-Mu - STM32 vendor part of the Cortex-M port: shared definitions
 *
 * No vendor headers and no HAL. Every address, bit position, pin and size
 * comes from the generated config header (mimiconf.py renders it from
 * config/targets.toml), so adding a chip is data, not code:
 *
 *   MB_STM32_FLASH_{F0F1,F2F4,L4G0G4}, MB_STM32_FLASH_REGS, MB_STM32_BKER_BIT, MB_STM32_BANK_PAGES
 *   MB_RCC_BASE, MB_RCC_CSR_OFF, MB_RCC_RMVF_BIT, MB_CLOCK_HZ, MB_CLOCK_L4_HSI16, MB_LSI_HZ
 *   MB_GPIO_BASE/STRIDE/KIND/RCC_OFF/RCC_BIT0
 *   MB_UART_BASE/KIND/RCC_OFF/RCC_BIT/BAUD, MB_UART_{TX,RX}_{PORT,PIN}, MB_UART_AF
 *   MB_LED_*, MB_BUTTON_* (optional), MB_SYSMEM_ADDR, MB_M0_VECTORS (F0)
 */
#ifndef MB_STM32_H
#define MB_STM32_H

#include "port/cortexm/mcu.h"

/* UART kinds */
#define MB_UART_LEGACY  0   /* F1/F2/F4: SR, DR, BRR, CR1 (UE = bit 13) */
#define MB_UART_MODERN  1   /* F0/F3/F7/L4/G0/G4: CR1 (UE = bit 0), BRR, ISR, ICR, RDR, TDR */
#define MB_UART_LPUART  2   /* modern registers, BRR = 256 * f / baud */

/* GPIO kinds */
#define MB_GPIO_F1      0   /* CRL/CRH nibbles */
#define MB_GPIO_MODER   1   /* MODER/OTYPER/OSPEEDR/PUPDR/AFR */

#endif
