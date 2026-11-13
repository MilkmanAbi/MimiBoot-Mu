#!/usr/bin/env python3
"""mimiconf: model, dependencies, .config round trip, layouts, generated headers,
the TUI state machine. --build-all also compiles every board's default config."""
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from mu import gen  # noqa: E402
from mu.layout import LayoutError, plan  # noqa: E402
from mu.model import Config, Db  # noqa: E402
from mu.tui import TuiState  # noqa: E402

checks = fails = 0


def check(ok, what):
    global checks, fails
    checks += 1
    if not ok:
        fails += 1
        print("  FAIL", what)


def main():
    db = Db()
    # every board resolves and its defaults are buildable (no errors)
    for name in db.boards:
        cfg = Config(db, name)
        errs = [m for lvl, m in cfg.problems() if lvl == "error"]
        check(not errs, f"{name}: default config has errors {errs}")
        check(cfg.t.core in ("night", "lite") and cfg.t.build in ("mcu", "pico", "avr"), f"{name}: core/build")

    # every chip is reachable from a board (so --build-all compiles every chip's configuration)
    used = {b["chip"] for b in db.boards.values()}
    for chip in db.chips:
        check(chip in used, f"chip {chip} has no board: --build-all would never compile it")

    # dependencies switch things off, never leave them half on
    cfg = Config(db, "nucleo-f411re")
    cfg.set("CONSOLE", False)
    check(cfg.values["RECV"] and not cfg.effective("RECV") and not cfg.enabled("RECV"), "RECV off without CONSOLE")
    cfg.set("AB_TRIAL", False)
    check(not cfg.effective("TRIAL_WATCHDOG"), "trial watchdog off without trials")
    check(cfg.effective("TRIES") == 3, "dependent int keeps its default value")
    check(not cfg.enabled("AUX_SLOTS"), "aux slots need ab+golden")
    cfg.set("LAYOUT", "ab+golden")
    check(cfg.enabled("AUX_SLOTS"), "aux slots selectable with ab+golden")
    cfg.set("REQUIRE_SIGNATURE", True)
    check(any("KEYS" in m for _, m in cfg.problems()), "required signatures without keys is an error")
    for bad in (("TRIES", "99"), ("LAYOUT", "abc"), ("CONSOLE", "maybe")):
        try:
            cfg.set(*bad)
            check(False, f"accepted {bad}")
        except ValueError:
            check(True, "")
    try:
        cfg.set("STK500", True)
        check(False, "AVR option accepted for an MCU board")
    except KeyError:
        check(True, "")

    # .config round trip
    text = cfg.dump()
    back = Config.parse(db, text)
    check(back.values == cfg.values and back.board == cfg.board, ".config round trip")
    check("# MU_CONSOLE is not set" in text, "kernel-style 'is not set' lines")

    # the generated header names every Night switch explicitly
    hdr = "\n".join(gen.feature_macros(Config(db, "netduinoplus2")))
    for m in ("CONSOLE", "RECV", "CFG_FILE", "GRUB", "CONTROL", "SIGNATURES", "ANTI_ROLLBACK", "RAM_IMAGES", "HANDOFF",
              "CRASH_GUARD", "TRIAL_WATCHDOG", "AB_TRIAL", "IMG_NATIVE", "IMG_MCUBOOT", "IMG_RAW"):
        check(f"#define MB_FEAT_{m} " in hdr, f"header defines MB_FEAT_{m}")
    avr = "\n".join(gen.feature_macros(Config(db, "uno")))
    check("#define MU_VERIFY 1" in avr and "#define MU_VERIFY_CRC32 1" in avr and "#define MU_TIMEOUT_MS 1000" in avr,
          "AVR choice macros")

    # layouts: every bare-metal board, aligned and non-overlapping (Layout.check runs inside plan)
    for name in db.boards:
        cfg = Config(db, name)
        if cfg.t.build != "mcu":
            continue
        align = cfg.t.get("vtor_align", 512)
        mh = gen.mcuboot_hdr(cfg)
        for slots in ("single", "ab", "ab+golden"):
            cfg.set("LAYOUT", slots)
            try:
                lay = gen.mcu_layout(cfg)
                check(len(lay.slots) == {"single": 1, "ab": 2, "ab+golden": 3}[slots], f"{name} {slots} slot count")
                for s in lay.slots:
                    check((s.offset + 0x1000) % align == 0 and (s.offset + mh) % align == 0, f"{name}: VTOR alignment")
            except LayoutError as e:
                # small parts may not fit three slots; that must be an explicit error, never a bad layout
                check(slots != "ab", f"{name} {slots}: {e}")
    # nRF / SAMD: pins, register values, generated headers
    from mu.model import parse_pin
    check(parse_pin("P1.11") == (1, 11) and parse_pin("P0.06") == (0, 6), "nRF pin names")
    check(parse_pin("PB22") == (1, 22) and parse_pin("C13") == (2, 13), "SAMD / STM32 pin names")
    for bad in ("P0.32", "Z9", "P2"):
        try:
            parse_pin(bad)
            check(False, f"pin {bad} accepted")
        except ValueError:
            check(True, "")
    check(gen.nrf_baud(115200, False) == 0x01D7E000 and gen.nrf_baud(115200, True) == 0x01D60000, "nRF BAUDRATE values")
    check(abs(gen.nrf_baud(76800, False) - 76800 * (1 << 32) / 16e6) < 0x1000, "nRF BAUDRATE formula")

    def header(board, **sets):
        c = Config(db, board)
        for k, v in sets.items():
            c.set(k, v)
        return gen.mcu_header(c, gen.mcu_layout(c), 8192), c
    h, c = header("nrf52840dk")
    for want in ("#define MB_FLASH_BASE 0x00000000u", "#define MB_TIME_SYSTICK 0", "#define MB_VECTORS 0",
                 "#define MB_NRF_BAUD 0x01d7e000u", "#define MB_NRF_UARTE 0", "#define MB_NRF_PAGE 4096u",
                 "#define MB_UART_TX_PIN 6", "#define MB_LED_PIN 13", "#define MB_LED_ACTIVE_HIGH 0", "#define MB_VENDOR_NRF 1"):
        check(want in h, f"nrf52840dk header: {want}")
    check("-fno-delete-null-pointer-checks" in gen.client_recipe(c, Path(".")), "client recipe: flash at 0")
    h, _ = header("xiao-nrf52840")
    check("#define MB_UART_TX_PORT 1" in h and "#define MB_UART_TX_PIN 11" in h, "P1.11 -> port 1 pin 11")
    h, _ = header("microbit")
    check("#define MB_VECTORS 2" in h and "#define MB_RELAY_ADDR 0x20000000" in h and "#define MB_RAM_RESERVED 8u" in h,
          "nRF51: relayed vectors, RAM word reserved")
    h, _ = header("nucleo-f030r8")
    check("#define MB_VECTORS 1" in h and "#define MB_RAM_RESERVED 192u" in h and "#define MB_SYSMEM_ADDR" in h,
          "STM32F0: remapped vectors, vector copy reserved")
    h, _ = header("arduino-zero")
    want_baud = round(65536 * (1 - 16 * 115200 / 8_000_000))
    for want in (f"#define MB_SAMD_BAUD {want_baud}u", "#define MB_SAMD_SERCOM 0x42001c00u", "#define MB_SAMD_SERCOM_GCLK 25",
                 "#define MB_SAMD_SERCOM_APB_BIT 7", "#define MB_SAMD_MUX 3", "#define MB_SAMD_RXPO 3", "#define MB_SAMD_TXPO 1",
                 "#define MB_SAMD_ERASE 256u", "#define MB_UART_TX_PORT 1", "#define MB_UART_TX_PIN 22"):
        check(want in h, f"arduino-zero header: {want}")
    check("MB_SYSMEM_ADDR" not in h, "SAMD: no ROM loader")
    h, c = header("feather-m4")
    for want in ("#define MB_VTOR_ALIGN 1024u", "#define MB_SAMD_SERCOM 0x43000400u", "#define MB_SAMD_SERCOM_GCLK 35",
                 "#define MB_SAMD_SERCOM_APB_OFF 0x20u", "#define MB_SAMD_ERASE 8192u", "#define MB_NVIC_WORDS 5"):
        check(want in h, f"feather-m4 header: {want}")
    check(gen.mcuboot_hdr(c) == 0x400, "SAMD51: MCUboot header 0x400 (1 KB vector alignment)")
    c.set("IMG_MCUBOOT", True)
    check(any("0x400" in m for _, m in c.problems()), "SAMD51 + MCUboot: header-size warning")
    try:
        header("arduino-zero", BAUD=1000000)
        check(False, "1 Mbaud from an 8 MHz SERCOM clock accepted")
    except ValueError:
        check(True, "")

    try:
        plan(256 * 1024, "4x16K,1x64K,1x128K", 48 * 1024, "ab")
        check(False, "F401CC: 48K boot + two slots can't fit")
    except LayoutError:
        check(True, "")
    lay = plan(512 * 1024, "4x16K,1x64K,3x128K", 48 * 1024, "ab")
    check([r.size // 1024 for r in lay.log] == [16, 64], "F4: logs in the small sectors after boot")
    check(lay.notes and "differ" in " ".join(lay.notes), "unequal slots are reported")

    # TUI state machine
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / ".config"
        st = TuiState(db, p)
        check(st.view.kind == "makers", "no .config: start with the maker list")
        check([i.key for i in st.items()][:4] == ["st", "nordic", "microchip", "rpi"], "makers in targets.toml order")
        check("STM32" in st.help_text(), "maker details describe the family")
        st.select("st")
        st.enter()
        check(st.view.kind == "categories" and st.items()[0].label == "Nucleo boards", "categories, in the maker's order")
        st.select("st\0Nucleo boards")
        st.enter()
        check(st.view.kind == "boards" and st.breadcrumb() == ["Boards", "STMicroelectronics", "Nucleo boards"], "breadcrumb")
        st.select("nucleo-f411re")
        det = st.help_text()
        check("stm32f411re" in det and "USART2" in det and "tested" in det, "board details: chip, console, status")
        st.enter()
        check(st.cfg.board == "nucleo-f411re" and st.view.kind == "main", "pick a board")
        check(st.current().kind != "section", "cursor never rests on a section header")
        st.move(1); st.move(1); st.move(1)
        check(st.current().kind != "section", "moving skips section headers")
        check(st.select("console"), "main lists the menus")
        check(st.current().value.endswith(" on"), "menu rows summarise how many options are on")
        st.enter()
        check(st.view.kind == "menu", "open a menu")
        st.select("CONSOLE")
        st.space()
        check(not st.cfg.values["CONSOLE"] and st.dirty, "space toggles")
        st.select("RECV")
        check(not st.current().enabled, "dependent option shown disabled")
        st.enter()
        check("needs" in st.message, "disabled option explains why")
        st.cfg.set("CONSOLE", True)
        st.select("BREAK_IN_MS")
        act = st.enter()
        check(act == "prompt" and st.prompt[0] == "BREAK_IN_MS", "int option prompts")
        st.finish_prompt("500")
        check(st.cfg.values["BREAK_IN_MS"] == 500, "prompt sets value")
        st.prompt = ("BREAK_IN_MS", "")
        st.finish_prompt("99999")
        check(st.cfg.values["BREAK_IN_MS"] == 500 and "outside" in st.message, "range enforced in the UI")
        st.select("SHELL_DIAG")
        check("MB_FEAT_SHELL_DIAG" in st.help_text() and "md" in st.help_text(), "option details: macro and help")
        st.back()
        st.search("zephyr")
        check(any(i.key == "IMG_MCUBOOT" for i in st.items()), "search finds options by help text")
        st.back()
        # presets
        st.select("presets")
        st.enter()
        check(st.view.kind == "presets" and [i.key for i in st.items()] == ["minimal", "hobby", "product", "secure"],
              "presets view")
        st.select("minimal")
        check("sets:" in st.help_text(), "preset details list what it sets")
        st.enter()
        check(st.view.kind == "main" and st.cfg.values["LAYOUT"] == "single" and not st.cfg.values["CONSOLE"]
              and "preset minimal" in st.message, "applying a preset")
        check(not st.cfg.enabled("AB_TRIAL"), "single slot: A/B trial options grey out")
        # output folder: quotes, home
        st.select("OUTPUT_DIR")
        act = st.enter()
        st.finish_prompt('"' + str(Path(td) / "out dir") + '"')
        check(st.cfg.output_dir() == Path(td) / "out dir" / "nucleo-f411re", "output folder typed in quotes")
        st.save()
        check(p.exists() and not st.dirty and Config.load(db, p).values["LAYOUT"] == "single", "save")
        st.select("board")
        st.enter()
        check(st.view.kind == "makers", "board row opens the picker")
        st.select("microchip"); st.enter(); st.select("microchip\0AVR: Arduino and classic ATmega"); st.enter()
        st.select("uno"); st.enter()
        check(st.cfg.board == "uno" and st.cfg.output_dir().parent == Path(td) / "out dir",
              "switching boards keeps options that still apply")
        from mu.tui import build_report, layout_lines
        rep = build_report(st, {"flash_used": 1604, "flash_region": 2048, "files": ["a.hex"]}, Path(td))
        check(any("1604 / 2048" in line for line in rep), "build report with a size bar")
        check(any("slot" in line or "a " in line for line in layout_lines(Config(db, "nucleo-f411re"))), "layout view")

    # docs/OPTIONS.md is generated: it must match features.toml + feature-sizes.json
    from mu import docs
    check(docs.OUT.read_text(encoding="utf-8") == docs.render(db), "docs/OPTIONS.md is stale: python mimiconf.py docs")

    # presets on a small part leave the chip's trims alone
    c = Config(db, "nucleo-g031k8")
    c.apply_preset("product")
    check(not c.values["SIGNATURES"] and "SIGNATURES" in c.preset_kept, "preset keeps a small chip's trims")
    c = Config(db, "pico")
    c.apply_preset("minimal")
    check(c.values["RAM_IMAGES"] and not [m for lvl, m in c.problems() if lvl == "error"], "RP2040's locked RAM_IMAGES")
    try:
        c.set("RAM_IMAGES", False)
        check(False, "locked option changed")
    except ValueError:
        check(True, "")
    c = Config(db, "nucleo-f411re")
    c.set("REQUIRE_SIGNATURE", True)
    c.set("BOOT_VERIFY", "once")
    check(any("every boot" in m for lvl, m in c.problems() if lvl == "error"), "secure boot needs the hash every boot")
    for pid in db.presets:
        for board in ("nucleo-f411re", "uno", "pico"):
            cc = Config(db, board)
            if cc.t.core in db.presets[pid].cores:
                cc.apply_preset(pid)
                errs = [m for lvl, m in cc.problems() if lvl == "error" and "KEYS" not in m]
                check(not errs, f"preset {pid} on {board}: {errs}")
    print(f"mimiconf: {checks} checks, {fails} failed")
    return fails


def build_all():
    from mu import build as mubuild
    db = Db()
    bad = []
    out = Path(tempfile.mkdtemp(prefix="mu-buildall-"))
    for name in db.boards:
        cfg = Config(db, name)
        if cfg.t.build == "pico":
            continue        # Pico SDK builds take minutes each: tests/build_pico.py
        try:
            info = mubuild.build(cfg, out / name, log=lambda *a: None)
            print(f"  {name:20} {info['flash_used']:6} / {info['flash_region']} bytes"
                  + (f", RAM {info['ram_used']}+{info['stack']}" if "ram_used" in info else ""))
        except Exception as e:      # noqa: BLE001
            bad.append(name)
            print(f"  {name:20} FAILED: {str(e).splitlines()[-1] if str(e) else traceback.format_exc()}")
    print(f"build-all: {len(bad)} failed" + (f" ({', '.join(bad)})" if bad else ""))
    return len(bad)


if __name__ == "__main__":
    rc = main()
    if "--build-all" in sys.argv:
        rc += build_all()
    sys.exit(1 if rc else 0)
