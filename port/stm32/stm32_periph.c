/*
 * MimiBoot-Mu - STM32 peripherals the bootloader needs: reset cause, clock,
 * GPIO for the UART / LED / button, UART, independent watchdog.
 *
 * The bootloader runs on the reset clock (HSI/MSI): no PLL, no flash wait
 * states, nothing the app has to undo. L4 starts on MSI 4 MHz, which is too
 * coarse for 115200 baud, so it switches to HSI16 and switches back before
 * starting an image.
 */
#include "core/mimiboot.h"
#include "port/stm32/stm32.h"

/* ---- reset cause --------------------------------------------------------- */
#define CSR_SFTRSTF   (1u << 28)
#define CSR_IWDGRSTF  (1u << 29)
#define CSR_WWDGRSTF  (1u << 30)

uint32_t mcu_reset_flags_take(void) {
    uint32_t csr = REG32(MB_RCC_BASE + MB_RCC_CSR_OFF);
    REG32(MB_RCC_BASE + MB_RCC_CSR_OFF) |= 1u << MB_RCC_RMVF_BIT;
    if (csr & (CSR_IWDGRSTF | CSR_WWDGRSTF)) return MB_RESET_WATCHDOG;
    if (csr & CSR_SFTRSTF) return MB_RESET_SOFT;
    return MB_RESET_POWER;
}

/* ---- clock ------------------------------------------------------------------ */
void mcu_init(void) {
#if MB_CLOCK_L4_HSI16
    REG32(MB_RCC_BASE + 0x00) |= 1u << 8;                               // HSION
    for (uint32_t n = 0; !(REG32(MB_RCC_BASE + 0x00) & (1u << 10)) && n < 1000000u; n++) {}   // HSIRDY
    REG32(MB_RCC_BASE + 0x08) = (REG32(MB_RCC_BASE + 0x08) & ~3u) | 1u; // SW = HSI16
    for (uint32_t n = 0; ((REG32(MB_RCC_BASE + 0x08) >> 2) & 3u) != 1u && n < 1000000u; n++) {}
#endif
}

void mcu_restore(void) {
#if MB_CLOCK_L4_HSI16
    REG32(MB_RCC_BASE + 0x08) &= ~3u;                                   // SW = MSI (reset value)
    for (uint32_t n = 0; ((REG32(MB_RCC_BASE + 0x08) >> 2) & 3u) != 0u && n < 1000000u; n++) {}
#endif
}

/* ---- GPIO ---------------------------------------------------------------------- */
#define GPIO(port)  (MB_GPIO_BASE + (uint32_t)(port) * MB_GPIO_STRIDE)
enum { PIN_AF_OUT, PIN_IN_PULLUP, PIN_IN_PULLDOWN, PIN_OUT, PIN_ANALOG_RESET };

static void pin_mode(int port, int pin, int mode, int af) {
    REG32(MB_RCC_BASE + MB_GPIO_RCC_OFF) |= 1u << (MB_GPIO_RCC_BIT0 + port);
    (void)REG32(MB_RCC_BASE + MB_GPIO_RCC_OFF);                         // let the clock settle
    uint32_t g = GPIO(port);
#if MB_GPIO_KIND == MB_GPIO_F1
    (void)af;
    static const uint8_t nib[] = { 0xA, 0x8, 0x8, 0x2, 0x4 };           // AF push-pull 2 MHz, in pull, in pull, out 2 MHz, floating (reset)
    uint32_t reg = g + (pin < 8 ? 0x00 : 0x04), sh = (uint32_t)(pin & 7) * 4;
    REG32(reg) = (REG32(reg) & ~(0xFu << sh)) | ((uint32_t)nib[mode] << sh);
    if (mode == PIN_IN_PULLUP) REG32(g + 0x10) = 1u << pin;             // BSRR: ODR=1 selects pull-up
    if (mode == PIN_IN_PULLDOWN) REG32(g + 0x10) = 1u << (pin + 16);
#else
    static const uint8_t moder[] = { 2, 0, 0, 1, 3 };
    uint32_t sh = (uint32_t)pin * 2;
    if (mode == PIN_AF_OUT) {
        uint32_t afr = g + (pin < 8 ? 0x20 : 0x24), ash = (uint32_t)(pin & 7) * 4;
        REG32(afr) = (REG32(afr) & ~(0xFu << ash)) | ((uint32_t)af << ash);
        REG32(g + 0x08) = (REG32(g + 0x08) & ~(3u << sh)) | (1u << sh);   // OSPEEDR: medium
    }
    uint32_t pull = mode == PIN_IN_PULLUP ? 1u : mode == PIN_IN_PULLDOWN ? 2u : 0u;
    REG32(g + 0x0C) = (REG32(g + 0x0C) & ~(3u << sh)) | (pull << sh);   // PUPDR
    REG32(g + 0x00) = (REG32(g + 0x00) & ~(3u << sh)) | ((uint32_t)moder[mode] << sh);
#endif
}

__attribute__((unused)) static void pin_write(int port, int pin, bool high) {
    uint32_t bsrr = GPIO(port) + (MB_GPIO_KIND == MB_GPIO_F1 ? 0x10 : 0x18);
    REG32(bsrr) = high ? 1u << pin : 1u << (pin + 16);
}

__attribute__((unused)) static bool pin_read(int port, int pin) {
    uint32_t idr = GPIO(port) + (MB_GPIO_KIND == MB_GPIO_F1 ? 0x08 : 0x10);
    return (REG32(idr) >> pin) & 1u;
}

void mcu_led(bool on) {
#ifdef MB_LED_PORT
    static bool ready;
    if (!ready) { pin_mode(MB_LED_PORT, MB_LED_PIN, PIN_OUT, 0); ready = true; }
    pin_write(MB_LED_PORT, MB_LED_PIN, on == (MB_LED_ACTIVE_HIGH != 0));
#else
    (void)on;
#endif
}

bool mcu_button(void) {
#ifdef MB_BUTTON_PORT
    pin_mode(MB_BUTTON_PORT, MB_BUTTON_PIN, MB_BUTTON_ACTIVE_HIGH ? PIN_IN_PULLDOWN : PIN_IN_PULLUP, 0);
    for (volatile int i = 0; i < 2000; i++) {}
    bool level = pin_read(MB_BUTTON_PORT, MB_BUTTON_PIN);
    return level == (MB_BUTTON_ACTIVE_HIGH != 0);
#else
    return false;
#endif
}

void mcu_pins_release(void) {
#ifdef MB_LED_PORT
    mcu_led(false);
    pin_mode(MB_LED_PORT, MB_LED_PIN, PIN_ANALOG_RESET, 0);
#endif
#ifdef MB_BUTTON_PORT
    pin_mode(MB_BUTTON_PORT, MB_BUTTON_PIN, PIN_ANALOG_RESET, 0);
#endif
}

/* ---- UART ---------------------------------------------------------------------- */
#define U MB_UART_BASE
#if MB_UART_KIND == MB_UART_LEGACY
#define U_SR    (U + 0x00)
#define U_RDR   (U + 0x04)
#define U_TDR   (U + 0x04)
#define U_BRR   (U + 0x08)
#define U_CR1   (U + 0x0C)
#define CR1_ON  ((1u << 13) | (1u << 3) | (1u << 2))       /* UE, TE, RE */
#else
#define U_SR    (U + 0x1C)                                 /* ISR */
#define U_ICR   (U + 0x20)
#define U_RDR   (U + 0x24)
#define U_TDR   (U + 0x28)
#define U_BRR   (U + 0x0C)
#define U_CR1   (U + 0x00)
#define CR1_ON  ((1u << 0) | (1u << 3) | (1u << 2))        /* UE, TE, RE */
#endif
#define SR_ORE  (1u << 3)
#define SR_RXNE (1u << 5)
#define SR_TC   (1u << 6)
#define SR_TXE  (1u << 7)

void mcu_uart_init(void) {
    REG32(MB_RCC_BASE + MB_UART_RCC_OFF) |= 1u << MB_UART_RCC_BIT;
    (void)REG32(MB_RCC_BASE + MB_UART_RCC_OFF);
    pin_mode(MB_UART_TX_PORT, MB_UART_TX_PIN, PIN_AF_OUT, MB_UART_AF);
#ifndef MB_UART_RX_AF
#define MB_UART_RX_AF MB_UART_AF
#endif
    pin_mode(MB_UART_RX_PORT, MB_UART_RX_PIN, MB_GPIO_KIND == MB_GPIO_F1 ? PIN_IN_PULLUP : PIN_AF_OUT, MB_UART_RX_AF);
#if MB_GPIO_KIND != MB_GPIO_F1
    {   // the RX pin is AF mode; pull it up so a floating line doesn't read as data
        uint32_t g = GPIO(MB_UART_RX_PORT), sh = (uint32_t)MB_UART_RX_PIN * 2;
        REG32(g + 0x0C) = (REG32(g + 0x0C) & ~(3u << sh)) | (1u << sh);
    }
#endif
    REG32(U_CR1) = 0;
#if MB_UART_KIND == MB_UART_LPUART
    REG32(U_BRR) = (uint32_t)(((uint64_t)MB_CLOCK_HZ * 256u + MB_UART_BAUD / 2) / MB_UART_BAUD);
#else
    REG32(U_BRR) = (MB_CLOCK_HZ + MB_UART_BAUD / 2) / MB_UART_BAUD;
#endif
    REG32(U_CR1) = CR1_ON;
}

void mcu_uart_deinit(void) {
    for (uint32_t n = 0; !(REG32(U_SR) & SR_TC) && n < 2000000u; n++) {}
    REG32(U_CR1) = 0;
    REG32(MB_RCC_BASE + MB_UART_RCC_OFF) &= ~(1u << MB_UART_RCC_BIT);
    pin_mode(MB_UART_TX_PORT, MB_UART_TX_PIN, PIN_ANALOG_RESET, 0);
    pin_mode(MB_UART_RX_PORT, MB_UART_RX_PIN, PIN_ANALOG_RESET, 0);
}

int mcu_uart_getc(void) {
    uint32_t sr = REG32(U_SR);
    if (sr & SR_ORE) {
#if MB_UART_KIND == MB_UART_LEGACY
        (void)REG32(U_RDR);                                 // SR then DR read clears ORE
#else
        REG32(U_ICR) = SR_ORE;
#endif
    }
    if (!(sr & SR_RXNE)) return -1;
    return (int)(REG32(U_RDR) & 0xFFu);
}

void mcu_uart_putc(char c) {
    for (uint32_t n = 0; !(REG32(U_SR) & SR_TXE) && n < 2000000u; n++) {}
    REG32(U_TDR) = (uint8_t)c;
}

/* ---- independent watchdog (can't be stopped once started) ------------------------ */
#define IWDG 0x40003000u
static bool iwdg_on;

void mcu_wdt_start(uint32_t ms) {
    uint32_t reload = (uint32_t)(((uint64_t)ms * MB_LSI_HZ) / (256u * 1000u));
    if (reload < 1) reload = 1;
    if (reload > 4095) reload = 4095;
    REG32(IWDG + 0x00) = 0xCCCC;                // start
    REG32(IWDG + 0x00) = 0x5555;                // unlock PR/RLR
    REG32(IWDG + 0x04) = 6;                     // /256
    REG32(IWDG + 0x08) = reload;
    for (uint32_t n = 0; (REG32(IWDG + 0x0C) & 3u) && n < 1000000u; n++) {}
    REG32(IWDG + 0x00) = 0xAAAA;                // reload now
    iwdg_on = true;
}

void mcu_wdt_feed(void) { if (iwdg_on) REG32(IWDG + 0x00) = 0xAAAA; }
void mcu_wdt_disarm(void) { mcu_wdt_feed(); }   // can't stop it: give the most time we can

#if MB_VECTORS == MB_VECTORS_REMAP
/* Cortex-M0 (F0): no VTOR. Copy the table to the start of SRAM and map SRAM
 * at 0. The app must keep the first MB_M0_VECTORS*4 bytes of RAM free. */
void mcu_remap_vectors(uint32_t vectors) {
    for (int i = 0; i < MB_M0_VECTORS; i++) REG32(MB_RAM_BASE + 4u * (uint32_t)i) = REG32(vectors + 4u * (uint32_t)i);
    REG32(MB_RCC_BASE + 0x18) |= 1u;                        // SYSCFGEN
    REG32(0x40010000u) = (REG32(0x40010000u) & ~3u) | 3u;   // SYSCFG_CFGR1.MEM_MODE = SRAM
}
#endif
