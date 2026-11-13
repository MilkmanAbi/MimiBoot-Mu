"""Render a Config into build inputs: the C config header, linker script,
layout description (json/txt), Zephyr devicetree overlay."""
from __future__ import annotations

import json
from pathlib import Path

from .layout import Layout, ROLE_AB, ROLE_GOLDEN, plan, sector_groups
from .model import Config, parse_pin, parse_size

ROLE_NAMES = {ROLE_AB: "A/B", ROLE_GOLDEN: "golden", 3: "aux"}
NATIVE_HDR = 0x1000
VECTOR_MODES = {"vtor": 0, "remap": 1, "relay": 2}


def read_keys(path: str) -> list[bytes]:
    keys = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k = bytes.fromhex(line.split()[0])
        if len(k) != 32:
            raise ValueError(f"{path}: each key is 64 hex digits")
        keys.append(k)
    if not keys:
        raise ValueError(f"{path}: no keys")
    return keys


def _c_bytes(b: bytes) -> str:
    return "{" + ",".join(f"0x{x:02x}" for x in b) + "}"


def feature_macros(cfg: Config) -> list[str]:
    out = []
    for o in cfg.options():
        if not o.macro:
            continue
        v = cfg.effective(o.id)
        if o.kind == "bool":
            out.append(f"#define {o.macro} {1 if v else 0}")
        elif o.kind == "int":
            out.append(f"#define {o.macro} {v}")
        elif o.kind == "choice":
            if all(c.isdigit() for c in o.choices):
                out.append(f"#define {o.macro} {v}")
            else:
                out.append(f"#define {o.macro} {o.choices.index(v)}")
                for i, c in enumerate(o.choices):
                    out.append(f"#define {o.macro}_{c.upper().replace('-', '_').replace('+', '_')} {i}")
    return out


def key_macros(cfg: Config) -> list[str]:
    path = cfg.effective("KEYS")
    if not path or not cfg.effective("SIGNATURES"):
        return []
    keys = read_keys(path)
    return [f"#define MB_TRUSTED_KEY_COUNT {len(keys)}",
            "#define MB_TRUSTED_KEYS {" + ",".join(_c_bytes(k) for k in keys) + "}"]


# ---------------------------------------------------------------------------
# bare-metal Cortex-M (build = "mcu"): STM32, nRF, SAMD
# ---------------------------------------------------------------------------
def flash_base(cfg: Config) -> int:
    return cfg.t.get("flash_base", 0x08000000)


def ram_base(cfg: Config) -> int:
    return cfg.t.get("ram_base", 0x20000000)


def mcuboot_hdr(cfg: Config) -> int:
    """MCUboot header size = where the vector table lands; must meet VTOR alignment"""
    return cfg.t.get("mcuboot_hdr", 0x200)


def vector_mode(cfg: Config) -> str:
    return cfg.t.get("vectors", "vtor")


def ram_reserved(cfg: Config) -> int:
    """bytes at the start of RAM that the bootloader needs kept free while an image runs"""
    mode = vector_mode(cfg)
    if mode == "remap":
        return cfg.t.get("m0_vectors", 48) * 4
    if mode == "relay":
        return 8
    return 0


def mcu_layout(cfg: Config, boot_bytes: int | None = None) -> Layout:
    t = cfg.t
    flash = parse_size(t.get("flash"))
    if boot_bytes is None:
        bs = str(cfg.effective("BOOT_SIZE") or "chip").strip().lower()
        boot_bytes = parse_size(t.get("boot")) if bs in ("chip", "auto") else parse_size(bs.upper())
    return plan(flash, t.get("sectors"), boot_bytes, cfg.effective("LAYOUT") or "ab",
                cfg.effective("AUX_SLOTS") or 0, bool(cfg.effective("CFG_FILE")))


def mcu_ram(cfg: Config):
    t = cfg.t
    ram = parse_size(t.get("ram"))
    ram2 = t.get("ram2")
    r2 = None
    if ram2:
        base, size = ram2.split(":")
        r2 = (int(base, 0), parse_size(size))
    return ram, r2


def _pins(cfg: Config, parse=parse_pin) -> list[str]:
    """LED / button macros, for the ones the board has and the config lets the bootloader use"""
    t = cfg.t
    lines = []
    for kind, opt in (("led", "BOARD_LED"), ("button", "BOARD_BUTTON")):
        if cfg.effective(opt) is False:
            continue
        pin = t.board.get(kind)
        if pin:
            p = parse(pin)
            up = kind.upper()
            lines += [f"#define MB_{up}_PORT {p[0]}", f"#define MB_{up}_PIN {p[1]}",
                      f"#define MB_{up}_ACTIVE_HIGH {1 if t.board.get(kind + '_active_high') else 0}"]
    return lines


def stm32_macros(cfg: Config) -> list[str]:
    t = cfg.t
    fam = t.family
    uart = fam["uarts"][t.get("uart")]
    gpio = fam["gpio"]
    tx, rx = parse_pin(t.get("tx")), parse_pin(t.get("rx"))
    lines = [
        f"#define MB_STM32_FLASH_{fam['flash_driver']} 1",
        f"#define MB_STM32_FLASH_REGS 0x{fam['flash_regs']:08x}u",
        f"#define MB_STM32_BKER_BIT {fam.get('bker_bit', 0) if t.get('bank_pages') else 0}",
        f"#define MB_STM32_BANK_PAGES {t.get('bank_pages', 0)}",
        f"#define MB_RCC_BASE 0x{fam['rcc']:08x}u",
        f"#define MB_RCC_CSR_OFF 0x{fam['rcc_csr']:x}u",
        f"#define MB_RCC_RMVF_BIT {fam['rmvf_bit']}",
        f"#define MB_CLOCK_L4_HSI16 {1 if fam.get('clock_l4_hsi16') else 0}",
        f"#define MB_LSI_HZ {fam['lsi_hz']}u",
        f"#define MB_GPIO_BASE 0x{gpio['base']:08x}u",
        f"#define MB_GPIO_STRIDE 0x{gpio['stride']:x}u",
        f"#define MB_GPIO_KIND {0 if gpio['kind'] == 'f1' else 1}",
        f"#define MB_GPIO_RCC_OFF 0x{gpio['rcc_off']:x}u",
        f"#define MB_GPIO_RCC_BIT0 {gpio['rcc_bit0']}",
        f"#define MB_UART_BASE 0x{uart['base']:08x}u",
        f"#define MB_UART_KIND {['legacy', 'modern', 'lpuart'].index(uart['kind'])}",
        f"#define MB_UART_RCC_OFF 0x{uart['rcc_off']:x}u",
        f"#define MB_UART_RCC_BIT {uart['rcc_bit']}",
        f"#define MB_UART_TX_PORT {tx[0]}", f"#define MB_UART_TX_PIN {tx[1]}",
        f"#define MB_UART_RX_PORT {rx[0]}", f"#define MB_UART_RX_PIN {rx[1]}",
        f"#define MB_UART_AF {t.get('af', 0)}",
    ]
    if t.get("rx_af") is not None:
        lines.append(f"#define MB_UART_RX_AF {t.get('rx_af')}")
    lines += _pins(cfg)
    sysmem = t.chip.get("sysmem", fam.get("sysmem"))
    if sysmem:
        lines.append(f"#define MB_SYSMEM_ADDR 0x{sysmem:08x}u")
    if vector_mode(cfg) == "remap":
        lines.append(f"#define MB_M0_VECTORS {t.get('m0_vectors', 48)}")
    return lines


# nRF: BAUDRATE register values from the product specifications (UART and UARTE differ)
NRF_BAUD_UART = {9600: 0x00275000, 19200: 0x004EA000, 38400: 0x009D5000, 57600: 0x00EBF000, 115200: 0x01D7E000,
                 230400: 0x03AFB000, 460800: 0x075F7000, 921600: 0x0EBED000, 1000000: 0x10000000}
NRF_BAUD_UARTE = {9600: 0x00275000, 19200: 0x004EA000, 38400: 0x009D0000, 57600: 0x00EB0000, 115200: 0x01D60000,
                  230400: 0x03B00000, 460800: 0x07400000, 921600: 0x0F000000, 1000000: 0x10000000}


def nrf_baud(baud: int, uarte: bool) -> int:
    table = NRF_BAUD_UARTE if uarte else NRF_BAUD_UART
    if baud in table:
        return table[baud]
    return (round(baud * (1 << 32) / 16_000_000) + 0x800) & ~0xFFF


def nrf_macros(cfg: Config) -> list[str]:
    t = cfg.t
    uarte = t.get("nrf_uart", "uart") == "uarte"
    tx, rx = parse_pin(t.get("tx")), parse_pin(t.get("rx"))
    baud = int(cfg.effective("BAUD") or 115200)
    lines = [
        f"#define MB_NRF_SERIES {t.get('series')}",
        f"#define MB_NRF_UARTE {1 if uarte else 0}",
        f"#define MB_NRF_BAUD 0x{nrf_baud(baud, uarte):08x}u",
        f"#define MB_NRF_PAGE {t.get('page')}u",
        f"#define MB_NRF_APPROTECT {1 if t.get('approtect_sw') else 0}",
        f"#define MB_UART_TX_PORT {tx[0]}", f"#define MB_UART_TX_PIN {tx[1]}",
        f"#define MB_UART_RX_PORT {rx[0]}", f"#define MB_UART_RX_PIN {rx[1]}",
    ]
    return lines + _pins(cfg)


def samd_macros(cfg: Config) -> list[str]:
    t = cfg.t
    fam = t.family
    n = int(t.get("sercom"))
    s = fam["sercoms"][n]
    tx, rx = parse_pin(t.get("tx")), parse_pin(t.get("rx"))
    baud = int(cfg.effective("BAUD") or 115200)
    clock = fam["clock_hz"]
    reg = round(65536 * (1 - 16 * baud / clock))
    if not 0 < reg < 65536:
        raise ValueError(f"{baud} baud is out of range for a {clock // 1000000} MHz SERCOM clock")
    mux = "ABCDEFGHIJKLMN".index(str(t.get("mux")).upper())
    lines = [
        f"#define MB_SAMD_SERIES {t.get('series')}",
        f"#define MB_SAMD_ERASE {t.get('erase_unit')}u",
        f"#define MB_SAMD_SERCOM 0x{s['base']:08x}u",
        f"#define MB_SAMD_SERCOM_GCLK {s['gclk']}",
        f"#define MB_SAMD_SERCOM_APB_OFF 0x{s['apb_off']:x}u",
        f"#define MB_SAMD_SERCOM_APB_BIT {s['apb_bit']}",
        f"#define MB_SAMD_BAUD {reg}u",
        f"#define MB_SAMD_RXPO {t.get('rxpo')}", f"#define MB_SAMD_TXPO {t.get('txpo')}",
        f"#define MB_SAMD_MUX {mux}",
        f"#define MB_UART_TX_PORT {tx[0]}", f"#define MB_UART_TX_PIN {tx[1]}",
        f"#define MB_UART_RX_PORT {rx[0]}", f"#define MB_UART_RX_PIN {rx[1]}",
    ]
    return lines + _pins(cfg)


VENDOR_MACROS = {"stm32": stm32_macros, "nrf": nrf_macros, "samd": samd_macros}


def mcu_header(cfg: Config, lay: Layout, loader_ram: int) -> str:
    t = cfg.t
    ram, r2 = mcu_ram(cfg)
    fb, rb = flash_base(cfg), ram_base(cfg)
    mode = vector_mode(cfg)
    lines = [
        "/* generated by mimiconf.py - do not edit; edit .config and rebuild */",
        "#ifndef MIMIBOOT_CONFIG_H", "#define MIMIBOOT_CONFIG_H", "",
        "/* features */", *feature_macros(cfg), *key_macros(cfg), "",
        "/* board */",
        f'#define MB_BOARD_NAME "{t.name}"',
        f'#define MB_TARGET "{t.chip_name[:15]}"',
        f"#define MB_VENDOR_{t.get('vendor').upper()} 1",
        f"#define MB_FLASH_BASE 0x{fb:08x}u",
        f"#define MB_FLASH_SIZE 0x{lay.flash_size:x}u",
        f"#define MB_RAM_BASE 0x{rb:08x}u",
        f"#define MB_RAM_SIZE 0x{ram:x}u",
        f"#define MB_LOADER_RAM 0x{rb + ram - loader_ram:08x}u",
        f"#define MB_LOADER_RAM_ASM 0x{rb + ram - loader_ram:08x}",
        f"#define MB_RAM_END_ASM 0x{rb + ram:08x}",
        f"#define MB_RAM_RESERVED {ram_reserved(cfg)}u",
        f"#define MB_CLOCK_HZ {t.get('clock_hz')}u",
        f"#define MB_TIME_SYSTICK {0 if t.get('time') == 'timer' else 1}",
        f"#define MB_VECTORS {VECTOR_MODES[mode]}",
        f"#define MB_NVIC_WORDS {t.get('nvic_words', 8)}",
        f"#define MB_VTOR_ALIGN {t.get('vtor_align', 512)}u",
    ]
    if mode == "relay":
        lines += [f"#define MB_RELAY_ADDR 0x{rb:08x}", f"#define MB_IRQS {t.get('irqs', 32)}"]
    if r2:
        lines += [f"#define MB_RAM2_BASE 0x{r2[0]:08x}u", f"#define MB_RAM2_SIZE 0x{r2[1]:x}u"]
    groups = ",".join(f"{{0x{a:x},0x{s:x},{n}}}" for a, s, n in sector_groups(lay.sectors))
    lines.append(f"#define MB_SECTOR_GROUPS {{{groups}}}")
    lines += VENDOR_MACROS[t.get("vendor")](cfg)
    lines += ["", "/* flash layout (offsets from MB_FLASH_BASE) */", layout_init(lay), "", "#endif", ""]
    return "\n".join(lines)


def layout_init(lay: Layout) -> str:
    def reg(r):
        return f"{{0x{r.offset:x},0x{r.size:x}}}" if r else "{0,0}"
    log = ",".join(reg(r) for r in lay.log)
    cfg = ",".join(reg(r) for r in lay.cfg) if lay.cfg else "{0,0},{0,0}"
    slots = ",".join(f'{{0x{s.offset:x},0x{s.size:x},{s.role},"{s.name}"}}' for s in lay.slots)
    return ("#define MB_LAYOUT_INIT { \\\n"
            f"  .flash_size=0x{lay.flash_size:x}, .sector_size=4096, .page_size=256, \\\n"
            f"  .boot={reg(lay.boot)}, .log={{{log}}}, .cfg={{{cfg}}}, \\\n"
            f"  .n_slots={len(lay.slots)}, .slot={{{slots}}}, \\\n"
            f"  .data={{0x{lay.data.offset:x},0x{lay.data.size:x}}} }}")


def mcu_linker(cfg: Config, boot_size: int, ram: int, loader_ram: int, stack: int) -> str:
    fb, rb = flash_base(cfg), ram_base(cfg)
    return f"""/* generated by mimiconf.py */
MEMORY {{
  FLASH (rx)  : ORIGIN = 0x{fb:08x}, LENGTH = 0x{boot_size:x}
  RAM   (rwx) : ORIGIN = 0x{rb + ram - loader_ram:08x}, LENGTH = 0x{loader_ram:x}
}}
_estack = ORIGIN(RAM) + LENGTH(RAM);
_stack_size = 0x{stack:x};
ENTRY(Reset_Handler)
SECTIONS {{
  .isr_vector : {{ KEEP(*(.isr_vector)) }} > FLASH
  .text : {{ *(.text*) *(.rodata*) . = ALIGN(4); }} > FLASH
  .ARM.exidx : {{ *(.ARM.exidx*) }} > FLASH
  _sidata = LOADADDR(.data);
  .data : {{ _sdata = .; *(.data*) . = ALIGN(4); _edata = .; }} > RAM AT > FLASH
  .bss (NOLOAD) : {{ _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; }} > RAM
  end = _ebss; _end = end;
  ASSERT(_ebss + _stack_size <= _estack, "MimiBoot: RAM too small for data + stack: turn features off")
}}
"""


def mcu_outputs(cfg: Config, lay: Layout, out: Path):
    """layout.json / layout.txt / zephyr overlay / app linker snippets / client recipe"""
    t = cfg.t
    fb, rb = flash_base(cfg), ram_base(cfg)
    mh = mcuboot_hdr(cfg)
    slots = []
    for s in lay.slots:
        base = fb + s.offset
        slots.append({"name": s.name, "role": ROLE_NAMES.get(s.role, "?"), "offset": s.offset, "size": s.size,
                      "address": base, "link_native": base + NATIVE_HDR, "link_mcuboot": base + mh,
                      "link_raw": base, "max_native": s.size - NATIVE_HDR})
    resv = ram_reserved(cfg)
    doc = {"board": t.name, "target": t.chip_name[:15], "flash_base": fb, "flash_size": lay.flash_size,
           "ram_base": rb, "ram_reserved": resv, "mcuboot_header": mh,
           "boot": {"offset": lay.boot.offset, "size": lay.boot.size},
           "log": [{"offset": r.offset, "size": r.size} for r in lay.log],
           "cfg": [{"offset": r.offset, "size": r.size} for r in lay.cfg], "slots": slots, "notes": lay.notes}
    (out / "layout.json").write_text(json.dumps(doc, indent=2) + "\n")
    rows = [f"MimiBoot-Mu layout for {t.name} ({t.chip_name}, {lay.flash_size // 1024} KB flash at 0x{fb:08x})",
            "", f"  {'region':8} {'address':>12} {'size':>8}  role"]
    for r in lay.regions():
        role = ROLE_NAMES.get(r.role, "") if r in lay.slots else ""
        rows.append(f"  {r.name:8} 0x{fb + r.offset:08x} {r.size // 1024:>6} K  {role}")
    rows += ["", "Link your firmware for a slot at:",
             "  MimiBoot image (mbtool pack)   slot address + 0x1000   (vector table there)",
             f"  Zephyr / MCUboot image         slot address + 0x{mh:x}    "
             f"(imgtool --header-size 0x{mh:x}, CONFIG_ROM_START_OFFSET=0x{mh:x})",
             "  raw .bin (FreeRTOS, bare)      slot address            (needs IMG_RAW)", ""]
    for s in slots:
        rows.append(f"  slot {s['name']}: native 0x{s['link_native']:08x}  mcuboot 0x{s['link_mcuboot']:08x}  "
                    f"raw 0x{s['link_raw']:08x}  (max {s['max_native'] // 1024} KB native)")
    if resv:
        rows += ["", f"RAM: apps start at 0x{rb + resv:08x}; keep RAM[0x{rb:08x} : 0x{rb + resv:08x}] free "
                     f"({'vector table copy' if vector_mode(cfg) == 'remap' else 'vector relay word'}: this chip has no VTOR)"]
    rows += [""] + [f"note: {n}" for n in lay.notes]
    (out / "layout.txt").write_text("\n".join(rows) + "\n")
    # an app linker MEMORY snippet per slot (MimiBoot images)
    ram, _ = mcu_ram(cfg)
    for s in slots:
        (out / f"app-slot-{s['name']}.ld").write_text(
            f"/* MimiBoot-Mu: link a MimiBoot image for slot {s['name']} (mbtool pack --target {t.chip_name[:15]}) */\n"
            f"MEMORY {{\n  FLASH (rx)  : ORIGIN = 0x{s['link_native']:08x}, LENGTH = 0x{s['size'] - NATIVE_HDR:x}\n"
            f"  RAM   (rwx) : ORIGIN = 0x{rb + resv:08x}, LENGTH = 0x{ram - resv:x}\n}}\n")
    (out / "zephyr-partitions.overlay").write_text(zephyr_overlay(cfg, lay))
    (out / "client.txt").write_text(client_recipe(cfg, out))


VENDOR_FLASH = {"stm32": "port/stm32/stm32_flash.c", "nrf": "port/nrf/nrf_flash.c", "samd": "port/samd/samd_flash.c"}
CLIENT_CORE = ["core/mb_hash.c", "core/mb_ed25519.c", "core/mb_image.c", "core/mb_bcl.c", "core/mb_config.c",
               "core/mb_control.c", "core/mb_grub.c", "core/mb_recv.c", "core/mb_formats.c", "client/mb_client.c",
               "port/cortexm/cm_port.c"]
CHUNK = {"stm32": "8 bytes (L4/G0/G4 program 8 bytes once per erase)", "nrf": "4 bytes",
         "samd": "64 bytes on SAM D21 (a page is written once per erase), 16 on SAM D51 (ECC quad-words)"}


def client_sources(cfg: Config) -> list[str]:
    return CLIENT_CORE + [VENDOR_FLASH[cfg.t.get("vendor")]]


def client_recipe(cfg: Config, out: Path) -> str:
    from .model import ROOT
    hdr = (out / "mimiboot_config.h").resolve().as_posix()
    srcs = " \\\n    ".join((ROOT / s).as_posix() for s in client_sources(cfg))
    vendor = cfg.t.get("vendor")
    extra = " -fno-delete-null-pointer-checks" if flash_base(cfg) == 0 else ""
    return f"""MimiBoot-Mu app side for {cfg.t.name}: status, confirm, requests, A/B install, OTA.
Compile these with your app (same -mcpu as the app, any optimisation):

    {srcs}

with
    -DMB_CM_CLIENT{extra} -DMB_CONFIG_HEADER=\\"{hdr}\\" -I{ROOT.as_posix()} -I{(ROOT / 'include').as_posix()}

Use the same mimiboot_config.h as the bootloader on the board (it carries the layout).

    #include "client/mb_client.h"
    extern const mb_port_t mb_mcu_port;
    MB_HANDOFF_BUFFER;                         /* optional; put .uninitialized_data* in a NOLOAD section */
    mb_client_init(&mb_mcu_port);
    mb_client_set_handoff(&mb_handoff);        /* args, how we were booted */
    if (st.state == MB_ST_TRIAL) mb_client_confirm();   /* after mb_client_status(&st) */
    mb_client_request(MB_REQ_MENU, 0);         /* then reset: the bootloader opens its menu */

Flash writes stall the CPU while they run: fine for an app, keep interrupt
latency in mind. mb_client_install_write(): pass chunks that start on a
{CHUNK[vendor]} boundary; 256-byte-aligned chunks work on every chip.

None of the flash-writing calls has run on {vendor.upper()} hardware yet (docs/HARDWARE-STATUS.md).
"""


def zephyr_overlay(cfg: Config, lay: Layout) -> str:
    mh = mcuboot_hdr(cfg)
    parts = [("boot_partition", "mimiboot", lay.boot.offset, lay.boot.size)]
    names = {0: "slot0_partition", 1: "slot1_partition", 2: "slot2_partition"}
    for i, s in enumerate(lay.slots):
        parts.append((names.get(i, f"slot{i}_partition"), f"image-{i}", s.offset, s.size))
    lo = min(r.offset for r in lay.log + lay.cfg) if lay.log else 0
    hi = max(r.offset + r.size for r in lay.log + lay.cfg) if lay.log else 0
    body = "".join(
        f"\t\t{lab}: partition@{off:x} {{\n\t\t\tlabel = \"{name}\";\n\t\t\treg = <0x{off:x} 0x{size:x}>;\n\t\t}};\n"
        for lab, name, off, size in parts)
    return f"""/*
 * MimiBoot-Mu flash partitions for a Zephyr app (generated by mimiconf.py).
 * Build the app with CONFIG_BOOTLOADER_MCUBOOT=y and CONFIG_ROM_START_OFFSET=0x{mh:x}
 * so it links at slot0 + 0x{mh:x}:
 *   west build -b <board> -- -DDTC_OVERLAY_FILE=zephyr-partitions.overlay
 * then: imgtool sign --header-size 0x{mh:x} --pad-header --align 8 --version 1.0.0
 *         --slot-size 0x{lay.slots[0].size:x} [--key key-ed25519.pem] zephyr.bin app.signed.bin
 * MimiBoot's boot-state log and config live at 0x{lo:x}..0x{hi:x}: no partition here
 * covers them, so keep Zephyr's settings/storage out of that range.
 * This replaces the board's whole partition table: anything else in the board
 * file that points at a partition label not defined below (e.g. storage_partition)
 * has to go too.
 */
/ {{
\tchosen {{
\t\tzephyr,code-partition = &slot0_partition;
\t}};
}};
&flash0 {{
\t/delete-node/ partitions;
\tpartitions {{
\t\tcompatible = "fixed-partitions";
\t\t#address-cells = <1>;
\t\t#size-cells = <1>;
{body}\t}};
}};
"""


# ---------------------------------------------------------------------------
# Pico SDK (RP2040 / RP2350): only the feature header; layouts are presets
# ---------------------------------------------------------------------------
def pico_header(cfg: Config) -> str:
    return "\n".join(["/* generated by mimiconf.py - do not edit */", "#ifndef MIMIBOOT_CONFIG_H",
                      "#define MIMIBOOT_CONFIG_H", *feature_macros(cfg), "#endif", ""])


def pico_keys_header(cfg: Config) -> str | None:
    k = key_macros(cfg)
    return "\n".join(["/* generated by mimiconf.py */", *k, ""]) if k else None


# ---------------------------------------------------------------------------
# AVR (Lite core)
# ---------------------------------------------------------------------------
def avr_header(cfg: Config, boot_size: int) -> str:
    t = cfg.t
    flash = parse_size(t.get("flash"))
    led = t.board.get("led")
    sig = t.get("signature")
    lines = ["/* generated by mimiconf.py - do not edit */", "#ifndef MU_CONFIG_H", "#define MU_CONFIG_H",
             *feature_macros(cfg),
             f"#define MU_BOARD \"{t.name}\"",
             f"#define MU_FLASH_SIZE {flash}UL",
             f"#define MU_BOOT_SIZE {boot_size}UL",
             f"#define MU_BOOT_START {flash - boot_size}UL",
             f"#define MU_PAGE_SIZE {t.get('page')}",
             f"#define MU_EEPROM_SIZE {t.get('eeprom')}",
             f"#define MU_SIG0 0x{sig[0]:02x}", f"#define MU_SIG1 0x{sig[1]:02x}", f"#define MU_SIG2 0x{sig[2]:02x}",
             f"#define MU_UART {t.get('uart', 0)}"]
    if led:
        port, pin = parse_pin(led)
        lines += [f"#define MU_LED_PORT_{chr(ord('A') + port)} 1", f"#define MU_LED_BIT {pin}"]
    lines += ["#endif", ""]
    return "\n".join(lines)
