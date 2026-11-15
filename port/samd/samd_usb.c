/*
 * MimiBoot-Mu - the console over native USB on SAM D21 / D51 (MB_CONSOLE_USB)
 *
 * One CDC-ACM port: the menu, the command line, uploads and SMP all run over
 * it unchanged. TinyUSB (third_party/tinyusb, 0.21.0, unmodified) does the
 * USB; this file brings up what it needs and takes all of it down again.
 *
 * Clock: USB needs 48 MHz +-0.25 %. It comes from the DFLL48M in USB
 * clock-recovery mode (USBCRM: the DFLL locks to the host's start-of-frame
 * every millisecond, so no crystal is needed), the way crystalless boards
 * (Feather M0/M4, Trinket, XIAO) run it.
 *   D21: the CPU moves from OSC8M (8 MHz) to the DFLL (48 MHz) with one flash
 *        wait state while USB runs: the USB bus clock may not drop below
 *        8 MHz, and OSC8M is only +-2 %. SysTick's reload follows the clock.
 *   D51: the CPU already runs on the DFLL (48 MHz, open loop, from reset);
 *        the DFLL goes to closed loop with USB recovery, the CPU sitting on
 *        the 32 kHz oscillator for the moment the DFLL is reconfigured.
 * Register values from the SAM D21 / D51 datasheets (SYSCTRL / OSCCTRL DFLL,
 * GCLK, PM / MCLK); the coarse calibration from the NVM software calibration
 * row. Checked against Adafruit's UF2 bootloader, which runs this way.
 *
 * USB is brought up only when the console is wanted (the button, nothing
 * bootable, the app's request): never on a normal boot. Before an image
 * starts: detach, the USB peripheral reset, its pins, clocks and bus clocks
 * back to how reset left them, the CPU clock and flash wait states restored,
 * and a pause so the host sees the device go before the app's own USB appears.
 *
 * NOT RUN ON A BOARD: built only. Nothing here has enumerated yet.
 */
#include "core/mimiboot.h"
#include "port/cortexm/mcu.h"

#if MB_CONSOLE_USB
#include "tusb.h"

#ifndef MB_USB_VID
#define MB_USB_VID 0x1209       /* pid.codes */
#define MB_USB_PID 0x0001       /* pid.codes test PID: for testing only, get your own for a product */
#endif

/* ---- registers ------------------------------------------------------------------- */
#define PORTA_PMUX(n)   (MB_SAMD_PORT_BASE + 0x30u + (uint32_t)(n) / 2u)
#define PORTA_PINCFG(n) (MB_SAMD_PORT_BASE + 0x40u + (uint32_t)(n))
#define USB_CTRLA       (MB_SAMD_USB_BASE + 0x00u)  /* 8-bit: SWRST 0, ENABLE 1 */
#define USB_SYNCBUSY    (MB_SAMD_USB_BASE + 0x02u)  /* 8-bit: SWRST 0, ENABLE 1 */
#define SPIN            2000000u

#if MB_SAMD_SERIES == 21
#define MB_SAMD_PORT_BASE 0x41004400u
#define MB_SAMD_USB_BASE  0x41005000u
#define NVM_CTRLB       0x41004004u     /* RWS 4:1 */
#define SC_PCLKSR       0x4000080Cu     /* DFLLRDY 4 */
#define SC_DFLLCTRL     0x40000824u     /* 16-bit */
#define SC_DFLLVAL      0x40000828u
#define SC_DFLLMUL      0x4000082Cu
#define GC_STATUS       0x40000C01u     /* SYNCBUSY 7 */
#define GC_CLKCTRL      0x40000C02u     /* 16-bit: ID 5:0, GEN 11:8, CLKEN 14 */
#define GC_GENCTRL      0x40000C04u     /* ID 3:0, SRC 12:8, GENEN 16, IDC 17 */
#define GC_GENDIV       0x40000C08u
#define PM_AHBMASK      0x40000414u     /* USB 6 */
#define PM_APBBMASK     0x4000041Cu     /* USB 5 */
#define DFLL_ENABLE     (1u << 1)
#define DFLL_MODE       (1u << 2)
#define DFLL_USBCRM     (1u << 5)
#define DFLL_ONDEMAND   (1u << 7)
#define DFLL_CCDIS      (1u << 8)
#define DFLL_BPLCKC     (1u << 10)
#define GEN_SRC_OSC8M   6u
#define GEN_SRC_DFLL    7u
#define GCLK_ID_USB     6u
#define USB_PMUX_FN     6u              /* G */
#define SERIAL_WORDS    { 0x0080A00Cu, 0x0080A040u, 0x0080A044u, 0x0080A048u }
#else
#define MB_SAMD_PORT_BASE 0x41008000u
#define MB_SAMD_USB_BASE  0x41000000u
#define OSC_STATUS      0x40001010u     /* DFLLRDY 8 */
#define OSC_DFLLCTRLA   0x4000101Cu     /* 8-bit: ENABLE 1 */
#define OSC_DFLLCTRLB   0x40001020u     /* 8-bit: MODE 0, USBCRM 3, CCDIS 4, WAITLOCK 7 */
#define OSC_DFLLVAL     0x40001024u
#define OSC_DFLLMUL     0x40001028u
#define OSC_DFLLSYNC    0x4000102Cu     /* 8-bit: ENABLE 1, DFLLCTRLB 2, DFLLVAL 3, DFLLMUL 4 */
#define GC_SYNCBUSY     0x40001C04u     /* GENCTRL0 2 */
#define GC_GENCTRL0     0x40001C20u     /* SRC 4:0, GENEN 8, IDC 9 */
#define GC_PCHCTRL(n)   (0x40001C80u + 4u * (uint32_t)(n))   /* GEN 3:0, CHEN 6 */
#define MC_AHBMASK      0x40000810u     /* USB 10 */
#define MC_APBBMASK     0x40000818u     /* USB 0 */
#define GEN_SRC_ULP32K  4u
#define GEN_SRC_DFLL    6u
#define GCLK_ID_USB     10u
#define USB_PMUX_FN     7u              /* H */
#define SERIAL_WORDS    { 0x008061FCu, 0x00806010u, 0x00806014u, 0x00806018u }
#endif

static bool up;
static struct {
    uint32_t nvm_ctrlb, ahb, apbb, dfllval, dfllmul;
    uint16_t dfllctrl;
} saved;

#if MB_SAMD_SERIES == 21
static void dfll_ready(void) { for (uint32_t n = 0; !(REG32(SC_PCLKSR) & (1u << 4)) && n < SPIN; n++) {} }
static void gclk_ready(void) { for (uint32_t n = 0; (REG8(GC_STATUS) & 0x80u) && n < SPIN; n++) {} }

static void clock_up(void) {
    saved.nvm_ctrlb = REG32(NVM_CTRLB);
    saved.ahb = REG32(PM_AHBMASK);
    saved.apbb = REG32(PM_APBBMASK);
    saved.dfllctrl = REG16(SC_DFLLCTRL);
    saved.dfllval = REG32(SC_DFLLVAL);
    saved.dfllmul = REG32(SC_DFLLMUL);
    REG32(NVM_CTRLB) = (saved.nvm_ctrlb & ~(0xFu << 1)) | (1u << 1);    // one wait state for 48 MHz
    REG16(SC_DFLLCTRL) = DFLL_ENABLE;                       // ONDEMAND off first (errata), then configure
    dfll_ready();
    uint32_t coarse = (REG32(0x00806024u) >> 26) & 0x3Fu;   // NVM software calibration row, bits 63:58
    if (coarse == 0x3Fu) coarse = 0x1Fu;
    REG32(SC_DFLLMUL) = (7u << 26) | (10u << 16) | 48000u;  // CSTEP, FSTEP, 48 MHz / 1 kHz SOF
    REG32(SC_DFLLVAL) = (coarse << 10) | 0x1FFu;
    REG16(SC_DFLLCTRL) = 0;
    dfll_ready();
    REG16(SC_DFLLCTRL) = DFLL_MODE | DFLL_CCDIS | DFLL_USBCRM | DFLL_BPLCKC;
    dfll_ready();
    REG16(SC_DFLLCTRL) |= DFLL_ENABLE;
    dfll_ready();
    REG32(GC_GENDIV) = 0;                                   // generator 0, no divider
    gclk_ready();
    REG32(GC_GENCTRL) = 0u | (GEN_SRC_DFLL << 8) | (1u << 16) | (1u << 17);
    gclk_ready();
    REG32(SYST_RVR) = 48000u - 1u;                          // SysTick: still 1 ms
    REG32(SYST_CVR) = 0;
    REG16(GC_CLKCTRL) = (uint16_t)(GCLK_ID_USB | (0u << 8) | (1u << 14));     // USB from generator 0
    gclk_ready();
    REG32(PM_AHBMASK) = saved.ahb | (1u << 6);
    REG32(PM_APBBMASK) = saved.apbb | (1u << 5);
}

static void clock_down(void) {
    REG16(GC_CLKCTRL) = GCLK_ID_USB;                        // CLKEN off
    gclk_ready();
    REG32(PM_AHBMASK) = saved.ahb;
    REG32(PM_APBBMASK) = saved.apbb;
    REG32(GC_GENCTRL) = 0u | (GEN_SRC_OSC8M << 8) | (1u << 16);              // the CPU back on OSC8M
    gclk_ready();
    REG32(SYST_RVR) = MB_CLOCK_HZ / 1000u - 1u;
    REG32(SYST_CVR) = 0;
    REG16(SC_DFLLCTRL) = DFLL_ENABLE;                       // ONDEMAND off while reconfiguring
    dfll_ready();
    REG32(SC_DFLLMUL) = saved.dfllmul;
    REG32(SC_DFLLVAL) = saved.dfllval;
    REG16(SC_DFLLCTRL) = saved.dfllctrl;                    // as reset left it (off, on demand)
    REG32(NVM_CTRLB) = saved.nvm_ctrlb;
}
#else
static void sync_wait(uint32_t bit) { for (uint32_t n = 0; (REG8(OSC_DFLLSYNC) & bit) && n < SPIN; n++) {} }
static void gen0_wait(void) { for (uint32_t n = 0; (REG32(GC_SYNCBUSY) & (1u << 2)) && n < SPIN; n++) {} }
static void gen0(uint32_t src) {
    REG32(GC_GENCTRL0) = src | (1u << 8) | (1u << 9);
    gen0_wait();
}

// The DFLL can't be reconfigured under the CPU: park the CPU on the 32 kHz oscillator meanwhile
static void dfll_set(uint8_t ctrlb, uint32_t mul, uint32_t val) {
    gen0(GEN_SRC_ULP32K);
    REG8(OSC_DFLLCTRLA) = 0;
    REG32(OSC_DFLLMUL) = mul;
    sync_wait(1u << 4);
    REG8(OSC_DFLLCTRLB) = 0;
    sync_wait(1u << 2);
    REG8(OSC_DFLLCTRLA) = 1u << 1;
    sync_wait(1u << 1);
    REG32(OSC_DFLLVAL) = val;
    sync_wait(1u << 3);
    REG8(OSC_DFLLCTRLB) = ctrlb;
    sync_wait(1u << 2);
    for (uint32_t n = 0; !(REG32(OSC_STATUS) & (1u << 8)) && n < SPIN; n++) {}
    gen0(GEN_SRC_DFLL);
}

static void clock_up(void) {
    saved.ahb = REG32(MC_AHBMASK);
    saved.apbb = REG32(MC_APBBMASK);
    saved.dfllval = REG32(OSC_DFLLVAL);
    saved.dfllmul = REG32(OSC_DFLLMUL);
    saved.dfllctrl = REG8(OSC_DFLLCTRLB);
    dfll_set((1u << 7) | (1u << 4) | (1u << 3), (1u << 26) | (1u << 16) | 48000u, saved.dfllval);   // WAITLOCK, CCDIS, USBCRM
    REG32(GC_PCHCTRL(GCLK_ID_USB)) = 0u | (1u << 6);        // USB from generator 0
    for (uint32_t n = 0; !(REG32(GC_PCHCTRL(GCLK_ID_USB)) & (1u << 6)) && n < SPIN; n++) {}
    REG32(MC_AHBMASK) = saved.ahb | (1u << 10);
    REG32(MC_APBBMASK) = saved.apbb | (1u << 0);
}

static void clock_down(void) {
    REG32(GC_PCHCTRL(GCLK_ID_USB)) = 0;
    REG32(MC_AHBMASK) = saved.ahb;
    REG32(MC_APBBMASK) = saved.apbb;
    dfll_set((uint8_t)saved.dfllctrl, saved.dfllmul, saved.dfllval);        // open loop, as reset left it
}
#endif

static void pins(bool usb) {
    // PA24 = D-, PA25 = D+: the USB function, or back to plain (reset) pins
    REG8(PORTA_PMUX(24)) = usb ? (uint8_t)(USB_PMUX_FN | (USB_PMUX_FN << 4)) : 0;
    REG8(PORTA_PINCFG(24)) = usb ? 1u : 0u;
    REG8(PORTA_PINCFG(25)) = usb ? 1u : 0u;
}

/* ---- TinyUSB: time, interrupt, descriptors ------------------------------------------- */
uint32_t tusb_time_millis_api(void) { return mb_cm_ms(); }

void mb_usb_irq(void) { tud_int_handler(0); }

static const tusb_desc_device_t dev_desc = {
    .bLength = sizeof(tusb_desc_device_t), .bDescriptorType = TUSB_DESC_DEVICE, .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC, .bDeviceSubClass = MISC_SUBCLASS_COMMON, .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE, .idVendor = MB_USB_VID, .idProduct = MB_USB_PID, .bcdDevice = 0x0200,
    .iManufacturer = 1, .iProduct = 2, .iSerialNumber = 3, .bNumConfigurations = 1,
};

#define CONFIG_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN)
static const uint8_t cfg_desc[CONFIG_LEN] = {
    TUD_CONFIG_DESCRIPTOR(1, 2, 0, CONFIG_LEN, 0, 100),
    TUD_CDC_DESCRIPTOR(0, 4, 0x81, 8, 0x02, 0x82, 64),
};

const uint8_t* tud_descriptor_device_cb(void) { return (const uint8_t*)&dev_desc; }
const uint8_t* tud_descriptor_configuration_cb(uint8_t index) { (void)index; return cfg_desc; }

const uint16_t* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    static uint16_t out[1 + 32];
    char buf[33];
    const char* s;
    if (index == 0) {
        out[1] = 0x0409;                                    // English
        out[0] = (uint16_t)((TUSB_DESC_STRING << 8) | 4);
        return out;
    }
    if (index == 1) s = "MimiBoot";
    else if (index == 2) s = "MimiBoot " MB_BOARD_NAME;
    else if (index == 3) {                                  // the chip's 128-bit serial number
        static const uint32_t words[4] = SERIAL_WORDS;
        for (int w = 0; w < 4; w++)
            for (int i = 0; i < 8; i++) buf[w * 8 + i] = "0123456789ABCDEF"[(REG32(words[w]) >> (28 - 4 * i)) & 15];
        buf[32] = 0;
        s = buf;
    } else if (index == 4) s = "MimiBoot console";
    else return NULL;
    size_t n = 0;
    for (; s[n] && n < 32; n++) out[1 + n] = (uint8_t)s[n];
    out[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * n + 2));
    return out;
}

/* ---- the console ---------------------------------------------------------------- */
bool mcu_usb_open(uint32_t wait_ms) {
    if (!up) {
        clock_up();
        pins(true);
        tusb_rhport_init_t init = { .role = TUSB_ROLE_DEVICE, .speed = TUSB_SPEED_FULL };
        tusb_init(0, &init);
        up = true;
    }
    // someone is there once a terminal opens the port (DTR)
    uint32_t t0 = mb_cm_ms();
    do {
        tud_task();
        mcu_wdt_feed();
        if (tud_cdc_connected()) return true;
    } while (mb_cm_ms() - t0 < wait_ms);
    return false;
}

int mcu_usb_getc(void) {
    if (!up) return -1;
    tud_task();
    return tud_cdc_available() ? tud_cdc_read_char() : -1;
}

void mcu_usb_write(const char* s, size_t n) {
    if (!up) return;
    uint32_t t0 = mb_cm_ms();
    while (n && tud_cdc_connected()) {
        uint32_t k = tud_cdc_write(s, (uint32_t)n);
        s += k;
        n -= k;
        tud_cdc_write_flush();
        tud_task();
        if (k) t0 = mb_cm_ms();
        else if (mb_cm_ms() - t0 > 500) break;           // the host stopped reading: drop it, don't hang
    }
}

void mcu_usb_close(void) {
    if (!up) return;
    tud_cdc_write_flush();
    for (uint32_t t0 = mb_cm_ms(); mb_cm_ms() - t0 < 20;) tud_task();     // let the last bytes go
    tud_disconnect();
    __asm volatile("cpsid i" ::: "memory");
    REG8(USB_CTRLA) = 1u;                                   // SWRST: the peripheral back to reset state
    for (uint32_t n = 0; (REG8(USB_SYNCBUSY) & 1u) && n < SPIN; n++) {}
    pins(false);
    clock_down();
    up = false;
    // a detach the host can see before the next device (the app's) attaches
    for (volatile uint32_t n = 0; n < MB_CLOCK_HZ / 100u; n++) {}
}
#endif /* MB_CONSOLE_USB */
