/*
 * MimiBoot-Mu - Microchip SAM D21 / D51 peripherals the bootloader needs:
 * reset cause, clock, PORT pins, a SERCOM as the console UART, watchdog.
 *
 * Clock: D21 resets on OSC8M divided by 8 (1 MHz), too slow for 115200 baud,
 * so the prescaler goes to /1 (8 MHz) and back before an image starts. D51
 * resets on the DFLL at 48 MHz (open loop) and is left alone. Both are the
 * factory-calibrated internal oscillators (about +-2 % over temperature):
 * fine for a UART at 115200, not crystal accurate.
 *
 * The SERCOM, its generic clock and its bus clock are switched off again, and
 * the pins handed back, before an image starts.
 *
 * Watchdog: D51 runs it from the 1.024 kHz ULP clock; D21 from generic clock
 * generator 2, which is set to OSCULP32K / 32 (= 1.024 kHz) when a trial
 * needs the watchdog. Unlike STM32 and nRF it can be switched off again.
 */
#include "core/mimiboot.h"
#include "port/cortexm/mcu.h"

#if MB_SAMD_SERIES == 21
#define PORT_BASE       0x41004400u
#define RCAUSE          0x40000438u     /* PM */
#define OSC8M           0x40000820u     /* SYSCTRL: PRESC 9:8 */
#define APB_BASE        0x40000400u     /* PM: APBxMASK at +0x18.. */
#define GCLK_STATUS     0x40000C01u
#define GCLK_CLKCTRL    0x40000C02u
#define GCLK_GENCTRL    0x40000C04u
#define GCLK_GENDIV     0x40000C08u
#define WDT             0x40001000u
#define WDT_CTRL        (WDT + 0x0)
#define WDT_CONFIG      (WDT + 0x1)
#define WDT_STATUS      (WDT + 0x7)
#define WDT_CLEAR       (WDT + 0x8)
#else
#define PORT_BASE       0x41008000u
#define RCAUSE          0x40000C00u     /* RSTC */
#define APB_BASE        0x40000800u     /* MCLK: APBxMASK at +0x14.. */
#define GCLK_PCHCTRL(n) (0x40001C80u + 4u * (uint32_t)(n))
#define WDT             0x40002000u
#define WDT_CTRL        (WDT + 0x0)
#define WDT_CONFIG      (WDT + 0x1)
#define WDT_SYNCBUSY    (WDT + 0x8)
#define WDT_CLEAR       (WDT + 0xC)
#endif
#define WDT_ENABLE      (1u << 1)
#define WDT_ALWAYSON    (1u << 7)
#define SPIN            2000000u

/* ---- reset cause (per reset, nothing to clear) --------------------------------- */
uint32_t mcu_reset_flags_take(void) {
    uint8_t r = REG8(RCAUSE);
    if (r & (1u << 5)) return MB_RESET_WATCHDOG;            // WDT
    if (r & (1u << 6)) return MB_RESET_SOFT;                // SYST (SYSRESETREQ)
    return MB_RESET_POWER;
}

/* ---- clock ------------------------------------------------------------------------ */
#if MB_SAMD_SERIES == 21
static uint32_t presc;
static void gclk_sync(void) { for (uint32_t n = 0; (REG8(GCLK_STATUS) & 0x80u) && n < SPIN; n++) {} }
#endif

void mcu_init(void) {
#if MB_SAMD_SERIES == 21
    presc = REG32(OSC8M) & (3u << 8);
    REG32(OSC8M) &= ~(3u << 8);                             // OSC8M / 1 = 8 MHz
#endif
}

void mcu_restore(void) {
#if MB_SAMD_SERIES == 21
    REG32(OSC8M) = (REG32(OSC8M) & ~(3u << 8)) | presc;     // back to the reset prescaler (/8)
#endif
}

/* ---- PORT --------------------------------------------------------------------------- */
#define GRP(p)          (PORT_BASE + 0x80u * (uint32_t)(p))
#define P_DIRCLR        0x04u
#define P_DIRSET        0x08u
#define P_OUTCLR        0x14u
#define P_OUTSET        0x18u
#define P_IN            0x20u
#define P_PMUX(pin)     (0x30u + (uint32_t)(pin) / 2u)
#define P_PINCFG(pin)   (0x40u + (uint32_t)(pin))
#define CFG_PMUXEN      0x01u
#define CFG_INEN        0x02u
#define CFG_PULLEN      0x04u

static void pin_mux(int port, int pin, uint32_t fn, uint8_t cfg) {
    uint32_t a = GRP(port) + P_PMUX(pin);
    uint8_t v = REG8(a);
    REG8(a) = (pin & 1) ? (uint8_t)((v & 0x0Fu) | (fn << 4)) : (uint8_t)((v & 0xF0u) | fn);
    REG8(GRP(port) + P_PINCFG(pin)) = cfg;
}

static void pin_reset(int port, int pin) {
    REG8(GRP(port) + P_PINCFG(pin)) = 0;
    uint32_t a = GRP(port) + P_PMUX(pin);
    REG8(a) = (pin & 1) ? (uint8_t)(REG8(a) & 0x0Fu) : (uint8_t)(REG8(a) & 0xF0u);
    REG32(GRP(port) + P_DIRCLR) = 1u << pin;
    REG32(GRP(port) + P_OUTCLR) = 1u << pin;
}

__attribute__((unused)) static void pin_write(int port, int pin, bool high) {
    REG32(GRP(port) + (high ? P_OUTSET : P_OUTCLR)) = 1u << pin;
}

void mcu_led(bool on) {
#ifdef MB_LED_PORT
    pin_write(MB_LED_PORT, MB_LED_PIN, on == (MB_LED_ACTIVE_HIGH != 0));
    REG32(GRP(MB_LED_PORT) + P_DIRSET) = 1u << MB_LED_PIN;
#else
    (void)on;
#endif
}

bool mcu_button(void) {
#ifdef MB_BUTTON_PORT
    REG32(GRP(MB_BUTTON_PORT) + P_DIRCLR) = 1u << MB_BUTTON_PIN;
    pin_write(MB_BUTTON_PORT, MB_BUTTON_PIN, !MB_BUTTON_ACTIVE_HIGH);   // OUT picks pull-up / pull-down
    REG8(GRP(MB_BUTTON_PORT) + P_PINCFG(MB_BUTTON_PIN)) = CFG_INEN | CFG_PULLEN;
    for (volatile int i = 0; i < 2000; i++) {}
    bool level = (REG32(GRP(MB_BUTTON_PORT) + P_IN) >> MB_BUTTON_PIN) & 1u;
    return level == (MB_BUTTON_ACTIVE_HIGH != 0);
#else
    return false;
#endif
}

void mcu_pins_release(void) {
#ifdef MB_LED_PORT
    pin_reset(MB_LED_PORT, MB_LED_PIN);
#endif
#ifdef MB_BUTTON_PORT
    pin_reset(MB_BUTTON_PORT, MB_BUTTON_PIN);
#endif
}

/* ---- SERCOM USART ------------------------------------------------------------------- */
#define S               MB_SAMD_SERCOM
#define S_CTRLA         (S + 0x00)
#define S_CTRLB         (S + 0x04)
#define S_BAUD          (S + 0x0C)
#define S_INTFLAG       (S + 0x18)      /* 8-bit: DRE 0, TXC 1, RXC 2 */
#define S_STATUS        (S + 0x1A)      /* 16-bit: PERR 0, FERR 1, BUFOVF 2 */
#define S_SYNCBUSY      (S + 0x1C)      /* SWRST 0, ENABLE 1, CTRLB 2 */
#define S_DATA          (S + 0x28)
#define APB_MASK        (APB_BASE + MB_SAMD_SERCOM_APB_OFF)

static void s_sync(uint32_t bits) { for (uint32_t n = 0; (REG32(S_SYNCBUSY) & bits) && n < SPIN; n++) {} }

static void sercom_reset(void) {
    REG32(S_CTRLA) = 0;                                     // disable first
    s_sync(2u);
    REG32(S_CTRLA) = 1;                                     // SWRST
    for (uint32_t n = 0; (REG32(S_CTRLA) & 1u) && n < SPIN; n++) {}
    s_sync(1u);
}

void mcu_uart_init(void) {
    REG32(APB_MASK) |= 1u << MB_SAMD_SERCOM_APB_BIT;        // bus clock
#if MB_SAMD_SERIES == 21
    REG16(GCLK_CLKCTRL) = (uint16_t)(MB_SAMD_SERCOM_GCLK | (0u << 8) | (1u << 14));   // core clock from GCLK0, CLKEN
    gclk_sync();
#else
    REG32(GCLK_PCHCTRL(MB_SAMD_SERCOM_GCLK)) = 0u | (1u << 6);                         // GCLK0, CHEN
    for (uint32_t n = 0; !(REG32(GCLK_PCHCTRL(MB_SAMD_SERCOM_GCLK)) & (1u << 6)) && n < SPIN; n++) {}
#endif
    sercom_reset();
    REG32(S_CTRLA) = (1u << 30)                             // LSB first
                   | ((uint32_t)MB_SAMD_RXPO << 20) | ((uint32_t)MB_SAMD_TXPO << 16)
                   | (1u << 2);                             // USART, internal clock, 16x arithmetic
    REG32(S_CTRLB) = (1u << 16) | (1u << 17);               // TXEN, RXEN, 8 bits
    s_sync(4u);
    REG16(S_BAUD) = (uint16_t)MB_SAMD_BAUD;
    REG32(S_CTRLA) |= 2u;                                   // ENABLE
    s_sync(2u);
    pin_mux(MB_UART_TX_PORT, MB_UART_TX_PIN, MB_SAMD_MUX, CFG_PMUXEN);
    pin_write(MB_UART_RX_PORT, MB_UART_RX_PIN, true);       // pull-up on RX: a floating line isn't data
    pin_mux(MB_UART_RX_PORT, MB_UART_RX_PIN, MB_SAMD_MUX, CFG_PMUXEN | CFG_PULLEN);
}

void mcu_uart_deinit(void) {
    for (uint32_t n = 0; !(REG8(S_INTFLAG) & 1u) && n < SPIN; n++) {}       // DRE
    for (uint32_t n = 0; !(REG8(S_INTFLAG) & 2u) && n < SPIN; n++) {}       // TXC: the last byte is out
    pin_reset(MB_UART_TX_PORT, MB_UART_TX_PIN);
    pin_reset(MB_UART_RX_PORT, MB_UART_RX_PIN);
    sercom_reset();
#if MB_SAMD_SERIES == 21
    REG16(GCLK_CLKCTRL) = (uint16_t)MB_SAMD_SERCOM_GCLK;   // CLKEN = 0
    gclk_sync();
#else
    REG32(GCLK_PCHCTRL(MB_SAMD_SERCOM_GCLK)) = 0;
#endif
    REG32(APB_MASK) &= ~(1u << MB_SAMD_SERCOM_APB_BIT);
}

int mcu_uart_getc(void) {
    uint16_t st = REG16(S_STATUS);
    if (st & 7u) REG16(S_STATUS) = st & 7u;                 // overflow / framing / parity: clear, carry on
    if (!(REG8(S_INTFLAG) & 4u)) return -1;                 // RXC
#if MB_SAMD_SERIES == 21
    return (int)(REG16(S_DATA) & 0xFFu);
#else
    return (int)(REG32(S_DATA) & 0xFFu);
#endif
}

void mcu_uart_putc(char c) {
    for (uint32_t n = 0; !(REG8(S_INTFLAG) & 1u) && n < SPIN; n++) {}       // DRE
    REG8(S_INTFLAG) = 2u;                                   // clear TXC: deinit waits for this byte
#if MB_SAMD_SERIES == 21
    REG16(S_DATA) = (uint8_t)c;
#else
    REG32(S_DATA) = (uint8_t)c;
#endif
}

/* ---- watchdog -------------------------------------------------------------------------- */
static void wdt_sync(void) {
#if MB_SAMD_SERIES == 21
    for (uint32_t n = 0; (REG8(WDT_STATUS) & 0x80u) && n < SPIN; n++) {}
#else
    for (uint32_t n = 0; REG32(WDT_SYNCBUSY) && n < SPIN; n++) {}
#endif
}

static bool wdt_on(void) { return REG8(WDT_CTRL) & (WDT_ENABLE | WDT_ALWAYSON); }

void mcu_wdt_feed(void) {
    if (!wdt_on()) return;
#if MB_SAMD_SERIES == 21
    if (REG8(WDT_STATUS) & 0x80u) return;                   // a clear is still being synchronised
#else
    if (REG32(WDT_SYNCBUSY) & (1u << 4)) return;
#endif
    REG8(WDT_CLEAR) = 0xA5u;
}

void mcu_wdt_start(uint32_t ms) {
    if (wdt_on()) { mcu_wdt_feed(); return; }
#if MB_SAMD_SERIES == 21
    REG32(GCLK_GENDIV) = 2u | (4u << 8);                    // generator 2: divide by 2^(4+1) = 32
    REG32(GCLK_GENCTRL) = 2u | (0x03u << 8) | (1u << 16) | (1u << 20);   // OSCULP32K, GENEN, DIVSEL
    gclk_sync();
    REG16(GCLK_CLKCTRL) = (uint16_t)(0x03u | (2u << 8) | (1u << 14));    // GCLK_WDT from generator 2
    gclk_sync();
#endif
    uint32_t cycles = (uint32_t)(((uint64_t)ms * 1024u) / 1000u), per = 0;
    while (per < 11 && (8u << per) < cycles) per++;         // PER: 8 << per cycles of 1.024 kHz (max 16 s)
    wdt_sync();
    REG8(WDT_CONFIG) = (uint8_t)per;
    wdt_sync();
    REG8(WDT_CTRL) = WDT_ENABLE;
    wdt_sync();
}

void mcu_wdt_disarm(void) {
    if (REG8(WDT_CTRL) & WDT_ALWAYSON) { mcu_wdt_feed(); return; }   // fuse-forced on: can only feed
    wdt_sync();
    REG8(WDT_CTRL) = 0;
    wdt_sync();
}
