/*
 * MimiBoot-Mu - bare-metal Cortex-M port: what a chip vendor provides
 *
 * port/cortexm/cm_port.c is the Komorebi port for any Cortex-M MCU (startup,
 * vector table, starting images, console glue, the app-side client). The
 * chip-specific parts are these functions, one directory per vendor:
 *
 *   port/stm32   STM32 F0/F1/F2/F3/F4/F7/L4/G0/G4
 *   port/nrf     Nordic nRF51 / nRF52
 *   port/samd    Microchip SAM D21 / D51
 *
 * Everything else (addresses, pins, sizes) comes from the generated config
 * header (muconfigurator.py renders it from config/targets.toml). Common macros:
 *
 *   MB_FLASH_BASE/SIZE, MB_RAM_BASE/SIZE, MB_RAM2_BASE/SIZE, MB_LOADER_RAM
 *   MB_SECTOR_GROUPS        {start, size, count} erase units as the layout sees them
 *   MB_CLOCK_HZ             core clock while the bootloader runs
 *   MB_TIME_SYSTICK         1: cm_port keeps time with SysTick; 0: mcu_time_ms()
 *   MB_VECTORS              0 VTOR, 1 SRAM remap (STM32F0), 2 relay through RAM (nRF51)
 *   MB_NVIC_WORDS, MB_VTOR_ALIGN, MB_IRQS (relay: IRQ count), MB_RELAY_ADDR
 */
#ifndef MB_MCU_H
#define MB_MCU_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define REG32(a)        (*(volatile uint32_t*)(uintptr_t)(a))
#define REG16(a)        (*(volatile uint16_t*)(uintptr_t)(a))
#define REG8(a)         (*(volatile uint8_t*)(uintptr_t)(a))

/* Cortex-M system control (same on every M0/M0+/M3/M4/M7/M33) */
#define SCB_ICSR        0xE000ED04u
#define SCB_VTOR        0xE000ED08u
#define SCB_AIRCR       0xE000ED0Cu
#define SYST_CSR        0xE000E010u
#define SYST_RVR        0xE000E014u
#define SYST_CVR        0xE000E018u
#define NVIC_ICER0      0xE000E180u
#define NVIC_ICPR0      0xE000E280u
#define ICSR_PENDSTCLR  (1u << 25)
#define ICSR_PENDSVCLR  (1u << 27)

/* how an image's vector table is put in force */
#define MB_VECTORS_VTOR   0     /* SCB->VTOR (M0+, M3, M4, M7, M33) */
#define MB_VECTORS_REMAP  1     /* copy to SRAM, map SRAM at 0 (STM32F0: M0 without VTOR) */
#define MB_VECTORS_RELAY  2     /* bootloader table forwards through a RAM word (nRF51: M0, no remap) */

#ifndef MB_TIME_SYSTICK
#define MB_TIME_SYSTICK 1
#endif
#ifndef MB_VECTORS
#define MB_VECTORS MB_VECTORS_VTOR
#endif

/* ---- flash: offsets from MB_FLASH_BASE; erase rounds out to whole erase units -------- */
int  mcu_flash_erase(uint32_t off, size_t len);
int  mcu_flash_program(uint32_t off, const void* buf, size_t len);

/* ---- the rest is only needed by the bootloader, not by the app-side client -------------- */
uint32_t mcu_reset_flags_take(void);     /* MB_RESET_*, and clears the hardware flags */
void mcu_init(void);                     /* clocks (and the timer, if !MB_TIME_SYSTICK) */
void mcu_restore(void);                  /* undo mcu_init before an image starts */
#if !MB_TIME_SYSTICK
uint32_t mcu_time_ms(void);
#endif
void mcu_uart_init(void);
void mcu_uart_deinit(void);              /* waits for the last byte, then back to reset state */
int  mcu_uart_getc(void);                /* -1: nothing waiting */
void mcu_uart_putc(char c);
void mcu_wdt_start(uint32_t ms);
void mcu_wdt_feed(void);                 /* also feeds a watchdog an app left running */
void mcu_wdt_disarm(void);               /* stop it, or (when it can't be stopped) feed it */
void mcu_led(bool on);
bool mcu_button(void);
void mcu_pins_release(void);             /* LED / button pins back to reset state */
#if MB_VECTORS == MB_VECTORS_REMAP
void mcu_remap_vectors(uint32_t vectors);
#endif
#ifdef MB_VENDOR_NRF
int  mcu_random(void* buf, size_t len);   /* hardware RNG (nRF); other vendors: none yet */
#endif
uint32_t mb_cm_ms(void);                    /* cm_port's millisecond clock (SysTick or the timer) */
#if defined(MB_CONSOLE_USB) && MB_CONSOLE_USB
/* The console over native USB (port/samd/samd_usb.c): brought up on demand,
 * taken down before an image starts. open: true once a terminal has the port. */
bool mcu_usb_open(uint32_t wait_ms);
int  mcu_usb_getc(void);                    /* -1: nothing (runs the USB stack) */
void mcu_usb_write(const char* s, size_t n);
void mcu_usb_close(void);
void mb_usb_irq(void);                      /* the USB interrupt (cm_port's vector table) */
#endif
#if defined(MB_FEAT_BOOT_LOCK) && MB_FEAT_BOOT_LOCK
/* Write/erase-protect [off, off+len) until the next reset, also against a
 * debugger-driven CPU. Called right before an image starts, after the
 * bootloader's last flash write. MB_OK, or an error if the lock didn't take. */
int  mcu_flash_lock(uint32_t off, uint32_t len);
#endif

#endif
