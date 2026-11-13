/*
 * MimiBoot-Mu - Nordic nRF51 / nRF52 peripherals the bootloader needs:
 * reset cause, HF crystal, TIMER0 for time, GPIO, the console UART, watchdog.
 *
 * Clock: the CPU stays on its reset clock. The UART is clocked from HFCLK, so
 * the 32/16 MHz crystal is started for an accurate baud rate (every nRF52
 * module has one: the radio needs it) and stopped again before an image
 * starts. If it doesn't start, the internal RC (about +-1.5 %) is used.
 *
 * Time: TIMER0 at 1 MHz, polled (the nRF51 has no SysTick; the same code
 * runs on both). Restored to its reset state before an image starts.
 *
 * UART: the nRF51 and the nRF52832/833/840 have the classic UART (6-byte RX
 * FIFO, polled). Parts without it (nRF52805/810/811/820, MB_NRF_UARTE) use
 * UARTE with one-byte EasyDMA transfers, the way Zephyr's poll_in does.
 *
 * Watchdog: can't be stopped, and keeps running through a soft reset. A
 * watchdog the app left running is fed from the first instruction on.
 *
 * Debug access (nRF52 with the newer APPROTECT): when UICR.APPROTECT says
 * "HwDisabled", firmware has to open the debug port again on every boot, as
 * Nordic's SystemInit does. The bootloader does the same so a board sitting
 * in the menu stays debuggable. It never writes UICR.
 */
#include "core/mimiboot.h"
#include "port/cortexm/mcu.h"

/* ---- registers ------------------------------------------------------------- */
#define CLOCK_HFCLKSTART    0x40000000u
#define CLOCK_HFCLKSTOP     0x40000004u
#define CLOCK_HFSTARTED     0x40000100u
#define POWER_RESETREAS     0x40000400u
#define UICR_APPROTECT      0x10001208u
#define APPROTECT_DISABLE   0x40000558u
#define APPROTECT_SW_OPEN   0x5Au

#define TIMER               0x40008000u     /* TIMER0 */
#define T_START             (TIMER + 0x000)
#define T_STOP              (TIMER + 0x004)
#define T_CLEAR             (TIMER + 0x00C)
#define T_CAPTURE0          (TIMER + 0x040)
#define T_MODE              (TIMER + 0x504)
#define T_BITMODE           (TIMER + 0x508)
#define T_PRESCALER         (TIMER + 0x510)
#define T_CC0               (TIMER + 0x540)

#define WDT                 0x40010000u
#define WDT_START           (WDT + 0x000)
#define WDT_RUNSTATUS       (WDT + 0x400)
#define WDT_CRV             (WDT + 0x504)
#define WDT_RREN            (WDT + 0x508)
#define WDT_CONFIG          (WDT + 0x50C)
#define WDT_RR(n)           (WDT + 0x600 + 4u * (n))
#define WDT_RELOAD          0x6E524635u

#define U                   0x40002000u     /* UART0 / UARTE0 */
#define U_STARTRX           (U + 0x000)
#define U_STOPRX            (U + 0x004)
#define U_STARTTX           (U + 0x008)
#define U_STOPTX            (U + 0x00C)
#define U_RXDRDY            (U + 0x108)
#define U_ENDRX             (U + 0x110)
#define U_TXDRDY            (U + 0x11C)
#define U_ENDTX             (U + 0x120)
#define U_ERROR             (U + 0x124)
#define U_RXTO              (U + 0x144)
#define U_TXSTOPPED         (U + 0x158)
#define U_ERRORSRC          (U + 0x480)
#define U_ENABLE            (U + 0x500)
#define U_PSELRTS           (U + 0x508)
#define U_PSELTXD           (U + 0x50C)
#define U_PSELCTS           (U + 0x510)
#define U_PSELRXD           (U + 0x514)
#define U_RXD               (U + 0x518)
#define U_TXD               (U + 0x51C)
#define U_BAUDRATE          (U + 0x524)
#define U_RXD_PTR           (U + 0x534)
#define U_RXD_MAXCNT        (U + 0x538)
#define U_TXD_PTR           (U + 0x544)
#define U_TXD_MAXCNT        (U + 0x548)
#define U_CONFIG            (U + 0x56C)

#define GPIO(port)          ((port) ? 0x50000300u : 0x50000000u)
#define G_OUTSET            0x508u
#define G_OUTCLR            0x50Cu
#define G_IN                0x510u
#define G_PIN_CNF(n)        (0x700u + 4u * (uint32_t)(n))
#define CNF_RESET           0x2u            /* input, input buffer disconnected */
#define CNF_OUTPUT          0x3u            /* output, input buffer disconnected */
#define CNF_IN_PULLUP       0xCu
#define CNF_IN_PULLDOWN     0x4u
#define PSEL(port, pin)     (((uint32_t)(port) << 5) | (uint32_t)(pin))
#define PSEL_NONE           0xFFFFFFFFu
#define SPIN                200000u

/* ---- reset cause ------------------------------------------------------------- */
uint32_t mcu_reset_flags_take(void) {
    uint32_t r = REG32(POWER_RESETREAS);
    REG32(POWER_RESETREAS) = r;                             // write-1-to-clear: the next reset starts clean
    if (r & (1u << 1)) return MB_RESET_WATCHDOG;            // DOG
    if (r & ((1u << 2) | (1u << 3))) return MB_RESET_SOFT;  // SREQ, LOCKUP
    return MB_RESET_POWER;                                  // power-on, pin, wake-up
}

/* ---- clock + time ------------------------------------------------------------- */
static uint32_t last_us, rem_us, now;

void mcu_init(void) {
#if MB_NRF_SERIES == 52 && MB_NRF_APPROTECT
    if ((REG32(UICR_APPROTECT) & 0xFFu) == APPROTECT_SW_OPEN) REG32(APPROTECT_DISABLE) = APPROTECT_SW_OPEN;
#endif
    REG32(CLOCK_HFSTARTED) = 0;
    REG32(CLOCK_HFCLKSTART) = 1;
    for (uint32_t n = 0; !REG32(CLOCK_HFSTARTED) && n < SPIN; n++) {}
    REG32(T_STOP) = 1;
    REG32(T_CLEAR) = 1;
    REG32(T_MODE) = 0;                                      // timer
    REG32(T_BITMODE) = 3;                                   // 32 bit
    REG32(T_PRESCALER) = 4;                                 // 16 MHz / 2^4 = 1 MHz
    REG32(T_START) = 1;
}

void mcu_restore(void) {
    REG32(T_STOP) = 1;
    REG32(T_CLEAR) = 1;
    REG32(T_BITMODE) = 0;                                   // reset values
    REG32(T_PRESCALER) = 4;
    REG32(T_CC0) = 0;
    REG32(CLOCK_HFCLKSTOP) = 1;
    REG32(CLOCK_HFSTARTED) = 0;
}

uint32_t mcu_time_ms(void) {
    REG32(T_CAPTURE0) = 1;
    uint32_t us = REG32(T_CC0);
    rem_us += us - last_us;                                 // wraps cleanly every 71 minutes
    last_us = us;
    now += rem_us / 1000u;
    rem_us %= 1000u;
    return now;
}

/* ---- GPIO ------------------------------------------------------------------------ */
static void pin_cnf(int port, int pin, uint32_t cnf) { REG32(GPIO(port) + G_PIN_CNF(pin)) = cnf; }
__attribute__((unused)) static void pin_write(int port, int pin, bool high) {
    REG32(GPIO(port) + (high ? G_OUTSET : G_OUTCLR)) = 1u << pin;
}

void mcu_led(bool on) {
#ifdef MB_LED_PORT
    pin_write(MB_LED_PORT, MB_LED_PIN, on == (MB_LED_ACTIVE_HIGH != 0));
    pin_cnf(MB_LED_PORT, MB_LED_PIN, CNF_OUTPUT);
#else
    (void)on;
#endif
}

bool mcu_button(void) {
#ifdef MB_BUTTON_PORT
    pin_cnf(MB_BUTTON_PORT, MB_BUTTON_PIN, MB_BUTTON_ACTIVE_HIGH ? CNF_IN_PULLDOWN : CNF_IN_PULLUP);
    for (volatile int i = 0; i < 2000; i++) {}
    bool level = (REG32(GPIO(MB_BUTTON_PORT) + G_IN) >> MB_BUTTON_PIN) & 1u;
    return level == (MB_BUTTON_ACTIVE_HIGH != 0);
#else
    return false;
#endif
}

void mcu_pins_release(void) {
#ifdef MB_LED_PORT
    pin_cnf(MB_LED_PORT, MB_LED_PIN, CNF_RESET);
    pin_write(MB_LED_PORT, MB_LED_PIN, false);
#endif
#ifdef MB_BUTTON_PORT
    pin_cnf(MB_BUTTON_PORT, MB_BUTTON_PIN, CNF_RESET);
#endif
}

/* ---- UART -------------------------------------------------------------------------- */
#if MB_NRF_UARTE
static volatile uint8_t rx_byte, tx_byte;               // EasyDMA buffers: must be in RAM
#endif

void mcu_uart_init(void) {
    pin_write(MB_UART_TX_PORT, MB_UART_TX_PIN, true);       // idle high before the UART takes the pin
    pin_cnf(MB_UART_TX_PORT, MB_UART_TX_PIN, CNF_OUTPUT);
    pin_cnf(MB_UART_RX_PORT, MB_UART_RX_PIN, CNF_IN_PULLUP);
    REG32(U_PSELTXD) = PSEL(MB_UART_TX_PORT, MB_UART_TX_PIN);
    REG32(U_PSELRXD) = PSEL(MB_UART_RX_PORT, MB_UART_RX_PIN);
    REG32(U_PSELRTS) = PSEL_NONE;
    REG32(U_PSELCTS) = PSEL_NONE;
    REG32(U_BAUDRATE) = MB_NRF_BAUD;
    REG32(U_CONFIG) = 0;                                    // 8N1, no flow control
    REG32(U_ERRORSRC) = REG32(U_ERRORSRC);
    REG32(U_ERROR) = 0;
#if MB_NRF_UARTE
    REG32(U_ENABLE) = 8;
    REG32(U_ENDRX) = 0;
    REG32(U_RXD_PTR) = (uint32_t)(uintptr_t)&rx_byte;
    REG32(U_RXD_MAXCNT) = 1;
    REG32(U_STARTRX) = 1;
#else
    REG32(U_ENABLE) = 4;
    REG32(U_RXDRDY) = 0;
    REG32(U_TXDRDY) = 0;
    REG32(U_STARTTX) = 1;
    REG32(U_STARTRX) = 1;
#endif
}

void mcu_uart_deinit(void) {
#if MB_NRF_UARTE
    REG32(U_RXTO) = 0;
    REG32(U_TXSTOPPED) = 0;
    REG32(U_STOPRX) = 1;
    for (uint32_t n = 0; !REG32(U_RXTO) && n < SPIN; n++) {}
    REG32(U_STOPTX) = 1;
    for (uint32_t n = 0; !REG32(U_TXSTOPPED) && n < SPIN; n++) {}
#else
    REG32(U_STOPTX) = 1;                                    // putc waited for the last byte already
    REG32(U_STOPRX) = 1;
#endif
    REG32(U_ENABLE) = 0;
    REG32(U_PSELTXD) = PSEL_NONE;
    REG32(U_PSELRXD) = PSEL_NONE;
    REG32(U_BAUDRATE) = 0x04000000u;                        // reset value (250 kbaud)
    REG32(U_RXDRDY) = 0; REG32(U_TXDRDY) = 0; REG32(U_ERROR) = 0;
    REG32(U_ENDRX) = 0; REG32(U_ENDTX) = 0; REG32(U_RXTO) = 0; REG32(U_TXSTOPPED) = 0;
    REG32(U_ERRORSRC) = REG32(U_ERRORSRC);
    pin_cnf(MB_UART_TX_PORT, MB_UART_TX_PIN, CNF_RESET);
    pin_cnf(MB_UART_RX_PORT, MB_UART_RX_PIN, CNF_RESET);
    pin_write(MB_UART_TX_PORT, MB_UART_TX_PIN, false);
}

int mcu_uart_getc(void) {
    if (REG32(U_ERROR)) {                                   // overrun / framing: clear and carry on
        REG32(U_ERROR) = 0;
        REG32(U_ERRORSRC) = REG32(U_ERRORSRC);
    }
#if MB_NRF_UARTE
    if (!REG32(U_ENDRX)) return -1;
    int c = rx_byte;
    REG32(U_ENDRX) = 0;
    REG32(U_STARTRX) = 1;                                   // bytes meanwhile wait in the UARTE's RX FIFO
    return c;
#else
    if (!REG32(U_RXDRDY)) return -1;
    REG32(U_RXDRDY) = 0;                                    // clear first, then read: the FIFO may hold more
    return (int)(REG32(U_RXD) & 0xFFu);
#endif
}

void mcu_uart_putc(char c) {
#if MB_NRF_UARTE
    tx_byte = (uint8_t)c;
    REG32(U_ENDTX) = 0;
    REG32(U_TXD_PTR) = (uint32_t)(uintptr_t)&tx_byte;
    REG32(U_TXD_MAXCNT) = 1;
    REG32(U_STARTTX) = 1;
    for (uint32_t n = 0; !REG32(U_ENDTX) && n < SPIN; n++) {}
#else
    REG32(U_TXDRDY) = 0;
    REG32(U_TXD) = (uint8_t)c;
    for (uint32_t n = 0; !REG32(U_TXDRDY) && n < SPIN; n++) {}
#endif
}

/* ---- watchdog (can't be stopped; survives a soft reset) ---------------------------- */
void mcu_wdt_feed(void) {
    if (!(REG32(WDT_RUNSTATUS) & 1u)) return;
    uint32_t en = REG32(WDT_RREN);
    for (uint32_t i = 0; i < 8; i++)
        if (en & (1u << i)) REG32(WDT_RR(i)) = WDT_RELOAD;
}

void mcu_wdt_start(uint32_t ms) {
    if (REG32(WDT_RUNSTATUS) & 1u) { mcu_wdt_feed(); return; }   // already running: its timeout stays
    uint32_t crv = (uint32_t)(((uint64_t)ms * 32768u) / 1000u);
    REG32(WDT_CRV) = crv < 15 ? 15 : crv;
    REG32(WDT_RREN) = 1;                                    // one reload register (RR0)
    REG32(WDT_CONFIG) = 1;                                  // run while sleeping, pause while halted by a debugger
    REG32(WDT_START) = 1;
}

void mcu_wdt_disarm(void) { mcu_wdt_feed(); }             // can't stop it: give the most time we can
