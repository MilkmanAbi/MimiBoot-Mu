#!/usr/bin/env python3
"""MuConfigurator: model, dependencies, .config round trip, layouts, generated headers,
the TUI state machine. --build-all also compiles every board's default config."""
import subprocess
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
        check(cfg.t.core in ("komorebi", "lite") and cfg.t.build in ("mcu", "pico", "avr"), f"{name}: core/build")

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

    # the generated header names every Komorebi switch explicitly
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
        check("A/B" in st.current().value or "menu" in st.current().value, "menu rows say what is on, in words")
        st.select("slots")
        check(st.current().value.startswith("A/B"), f"the slots line starts with the layout ({st.current().value})")
        st.select("console")
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
        # what else a change moves, before and after
        st.select("SHELL")
        check("also turns off" in st.help_text() and "uploads" in st.help_text(), "details preview the knock-on: uploads go with the shell")
        st.space()
        check("also off" in st.message and "uploads" in st.message, f"the message says what else went off ({st.message})")
        check(not st.cfg.effective("RECV"), "and it did")
        st.undo()
        check(st.cfg.values["SHELL"] and st.cfg.effective("RECV") and "undone" in st.message, "undo brings it back")
        check(st.current().note == "" or st.current().note.startswith(("+", "-")), "an option's note is its cost")
        st.select("RECV")
        st.space()
        st.reset_default()
        check(st.cfg.values["RECV"] == st.cfg.default(st.db.options["RECV"]), "d: back to the default")
        keys = [k for k, _ in st.keys_hint()]
        check("Space" in keys and "u" in keys and "B" in keys, f"the key bar lists what applies here ({keys})")
        st.back()
        st.search("zephyr")
        check(any(i.key == "IMG_MCUBOOT" for i in st.items()), "search finds options by help text")
        st.search("zephyr images")
        check(st.view.kind == "search" and len(st.views) == 2 and any(i.key == "IMG_MCUBOOT" for i in st.items()),
              "find as you type refines the same view, every word must match")
        st.back()
        # home: what you changed, what needs attention (Enter goes to the fix)
        st.cfg.set("REQUIRE_SIGNATURE", True)
        st.views = [st.views[0]]
        ks = [i.key for i in st.items()]
        check("REQUIRE_SIGNATURE" in ks, "home lists what was changed from the defaults")
        issues = [i for i in st.items() if i.kind == "issue"]
        check(issues and issues[0].style == "bad" and issues[0].value == "KEYS", f"an error points at KEYS ({[(i.label, i.value) for i in issues]})")
        st.select(issues[0].key)
        st.enter()
        check(st.view.kind == "menu" and st.current().key == "KEYS", "Enter on it goes to the option")
        st.views = [st.views[0]]
        st.cfg.set("REQUIRE_SIGNATURE", False)
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
        st.search("uno")
        check(st.view.kind == "boardsearch" and "uno" in [i.key for i in st.items()], "find in the picker finds boards")
        st.back()
        st2 = TuiState(db, Path(td) / "other")
        st2.search("f411")
        check(st2.view.kind == "boardsearch" and {"nucleo-f411re", "blackpill-f411ce"} <= {i.key for i in st2.items()},
              "find a board by part number, across makers")
        st2.search("nordic 52840 dk")
        found = [i.key for i in st2.items()]
        check("nrf52840dk" in found and len(found) <= 2, f"several words narrow it down ({found})")
        st.select("microchip"); st.enter(); st.select("microchip\0AVR: Arduino and classic ATmega"); st.enter()
        st.select("uno"); st.enter()
        check(st.cfg.board == "uno" and st.cfg.output_dir().parent == Path(td) / "out dir",
              "switching boards keeps options that still apply")
        from mu.tui import build_report, layout_lines
        # the size gauge: an estimate from the measured board + option costs, exact after a build
        st3 = TuiState(db, Path(td) / "g", Config(db, "nucleo-f411re"))
        st3.sizes = {"mcu": {"board": "nucleo-f411re", "base": 30000, "options": {"SMP": {"value": True, "delta": 4000}}},
                     "boards": {"nucleo-f411re": {"flash": 30000, "region": 49152}}}
        e0 = st3.estimate()
        st3.cfg.set("SMP", True)
        e1 = st3.estimate()
        check(e0["used"] == 30000 and e1["used"] == 34000 and not e1["exact"], f"estimate follows a change ({e0} {e1})")
        from mu.tui import gauge_text
        st3.cfg.set("BOOT_SIZE", "64K")
        check(st3.estimate()["region"] > 49152, f"a bigger BOOT_SIZE: the gauge's limit follows ({st3.estimate()['region']})")
        st3.cfg.set("BOOT_SIZE", "chip")
        st3.cfg.set("TWO_STAGE", True)
        check(st3.estimate()["region"] is None and "sized to fit" in gauge_text(st3.estimate())[0],
              "two-stage, stage-1 copies sized automatically: no fixed limit to show")
        st3.cfg.set("STAGE1_SIZE", "96K")
        check(st3.estimate()["region"] == 96 * 1024 - 4096, "two-stage with a set copy size: that is the limit")
        st3.cfg.set("TWO_STAGE", False)
        st3.last_info = ("nucleo-f411re", dict(st3.cfg.values), {"flash_used": 33950, "flash_region": 49152})
        check(st3.estimate()["exact"] and st3.estimate()["used"] == 33950, "a build of this configuration: the real size")
        check("~" in gauge_text(e1)[0] and "estimate" in gauge_text(e1)[0], "an estimate says so")
        near = dict(e1, used=48000)
        check("build to check" in gauge_text(near)[0] and gauge_text(near)[1] == "warn", "close to the limit: build to check")
        rep = build_report(st, {"flash_used": 1604, "flash_region": 2048, "files": ["a.hex"]}, Path(td))
        check(any("1604 / 2048" in line for line in rep), "build report with a size bar")
        check(any("slot" in line or "a " in line for line in layout_lines(Config(db, "nucleo-f411re"))), "layout view")

    # docs/OPTIONS.md is generated: it must match features.toml + feature-sizes.json
    from mu import docs
    check(docs.OUT.read_text(encoding="utf-8") == docs.render(db), "docs/OPTIONS.md is stale: python muconfigurator.py docs")

    # the docs site's generated pages: every board in the matrix, the STM32 warning, nothing Liquid would read
    import json as _json
    from mu import site
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "_config.yml").write_text("title: x\n")
        names = site.write(db, Path(td))
        page = (Path(td) / "matrix.html").read_text(encoding="utf-8")
    check({"matrix.html", "status.md", "security.md", "os-integration.md"} <= set(names), "site: pages written")
    body = page.split("{% raw %}", 1)
    check(len(body) == 2 and body[1].rstrip().endswith("{% endraw %}") and "{{" not in body[0] and "{%" not in body[0],
          "site: the matrix's script and data are inside {% raw %}")
    data = _json.loads(page.split('type="application/json">', 1)[1].split("</script>", 1)[0])
    check({b["name"] for b in data["boards"]} == set(db.boards), "site: every board in the matrix")
    stm = [b for b in data["boards"] if b["family"] == "stm32"]
    check(stm and all(b["flash_writes"] == "built" and "never" in b["never_ran"] for b in stm),
          "site: no STM32 board claims a flash write ran")
    check("ST-Link" in page and "connect under reset" in page, "site: the ST-Link warning is on the matrix page")
    hw = {b["name"] for b in data["boards"] if any(f[3] == "hardware" for f in b["f"])}
    check(hw <= {"pico", "rp2350-lcd"}, "site: only the RP boards that ran have hardware-level features")
    check({b["name"] for b in data["boards"] if b["flash_writes"] == "hardware"} <= {"rp2350-lcd"},
          "site: hardware flash writes only on the board that ran them")
    check(all("earlier build" in f[4] for b in data["boards"] for f in b["f"] if f[3] == "hardware"),
          "site: every hardware-level feature says it was an earlier build")

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
    provision_checks(db)
    print(f"MuConfigurator: {checks} checks, {fails} failed")
    return fails


def provision_checks(db):
    """mbtool provision: the printed steps for each vendor, from a fabricated build dir"""
    import json as _json
    from mu.provision import ProvisionError, steps

    def run(board, boot_off, boot_size, features=None, core="komorebi", store=None):
        """store: a two-stage build's store (offset, size) at the end of the boot region"""
        d = Path(tempfile.mkdtemp(prefix="mu-prov-"))
        t = db.target(board)
        (d / "build-info.json").write_text(_json.dumps({"board": board, "core": core, "features": features or {},
                                                        "flash_region": boot_size, "two_stage": bool(store)}))
        if core == "komorebi":
            (d / "layout.json").write_text(_json.dumps({"flash_base": t.get("flash_base", 0x08000000),
                                                        "boot": {"offset": boot_off, "size": boot_size},
                                                        "floor": {"offset": store[0], "size": store[1]} if store else None}))
        try:
            return "\n".join(steps(d))
        except ProvisionError as e:
            return "REFUSED " + str(e)

    o = run("nucleo-f411re", 0, 48 * 1024)
    check("nWRP0=0 nWRP1=0 nWRP2=0" in o and "RDP=0xBB" in o, "provision F4: sectors 0..2, RDP level 1")
    o = run("nucleo-l476rg", 0, 64 * 1024)
    check("WRP1A_STRT=0 WRP1A_END=31" in o, "provision L4: pages 0..31")
    o = run("arduino-zero", 0, 48 * 1024)
    check(o.startswith("REFUSED") and "32 KB" in o, "provision SAM D21: refuses a region BOOTPROT can't cover exactly")
    o = run("arduino-zero", 0, 16 * 1024)
    check("at91samd bootloader 16384" in o, "provision SAM D21: BOOTPROT for 16 KB")
    o = run("nrf52840dk", 0, 48 * 1024, {"BOOT_LOCK": True})
    check("ACL" in o and "nrfjprog --rbp ALL" in o and "BOOT_LOCK is on" in o, "provision nRF52840: ACL at run time, UICR")
    o = run("nrf52dk", 0, 48 * 1024, {"BOOT_LOCK": False})
    check("BOOT_LOCK is OFF" in o and "BPROT" in o, "provision nRF52832: says the lock is off")
    o = run("uno", 0, 512, core="lite")
    check("lock:w:0x2F:m" in o, "provision AVR: BLB1 lock bits")
    # two-stage: stage 0's code only (sector 0), never its store (sector 1) or the copies
    o = run("nucleo-f411re", 0, 32 * 1024, store=(16 * 1024, 16 * 1024))
    check("nWRP0=0" in o and "nWRP1" not in o and "lock stage 0 only" in o, "provision F4 two-stage: stage 0's sector, not the store")
    o = run("arduino-zero", 0, 16 * 1024 + 256, store=(16 * 1024, 256))
    check("at91samd bootloader 16384" in o, "provision SAM D21 two-stage: BOOTPROT over stage 0's 16 KB")
    o = run("nrf52840dk", 0, 16 * 1024, {"BOOT_LOCK": True}, store=(12 * 1024, 4096))
    check("both stage-1 copies" in o, "provision nRF two-stage: says what the run-time lock covers")
    two_stage_checks(db)


def two_stage_checks(db):
    """TWO_STAGE in the configurator: layout, problems, generated header"""
    from mu.layout import ROLE_STAGE1
    cfg = Config(db, "nrf52840dk")
    cfg.set("LAYOUT", "ab+golden")
    cfg.set("TWO_STAGE", True)
    check(not [m for lvl, m in cfg.problems() if lvl == "error"], "two-stage nRF52840: no errors")
    lay = gen.mcu_layout(cfg, boot_bytes=16 * 1024, s1_bytes=52 * 1024)
    s1 = [s for s in lay.slots if s.role == ROLE_STAGE1]
    check([s.name for s in s1] == ["s1a", "s1b"] and lay.slots.index(s1[0]) == 3, "stage-1 copies last in the slot table")
    check([s.name for s in lay.slots[:3]] == ["a", "b", "g"], "A, B, golden keep slots 0..2")
    check(all(s.size >= 52 * 1024 and s.offset % 4096 == 0 for s in s1), "copies sized and sector aligned")
    check(s1[0].offset > lay.log[1].offset, "copies after the log (small sectors go to the log first)")
    check(gen.floor_region(cfg, lay) == (8 * 1024, 8192) and gen.floor_unit(cfg, lay) == 4096,
          "two-stage: the store is the boot region's last two 4 KB units (they compact)")
    f4 = Config(db, "nucleo-f411re")
    lay4 = gen.mcu_layout(f4, boot_bytes=48 * 1024)
    check(gen._floor(lay4)[2] == 0 and gen._floor(lay4)[1] >= 16 * 1024,
          "big sectors (F4): one append-only unit")
    check(gen.stage1_bytes(cfg, 40000) == (4096 + 50000 + 4095) // 4096 * 4096, "STAGE1_SIZE auto: measured + 25% + header")
    cfg.set("AUX_SLOTS", 2)
    check(any("at most 6 slots" in m for lvl, m in cfg.problems() if lvl == "error"), "two-stage + 5 slots refused")
    try:
        plan(1 << 20, "256x4K", 16384, "ab+golden", 2, False, 64 * 1024)
        check(False, "planner took 7 slots")
    except LayoutError:
        check(True, "")
    small = Config(db, "nucleo-g071rb")
    small.set("TWO_STAGE", True)
    check(any("192 KB" in m for lvl, m in small.problems() if lvl == "error"), "two-stage refused on a 128 KB part")
    c2 = Config(db, "nucleo-f411re")
    for k, v in (("TWO_STAGE", True), ("KEYS", "x.pub"), ("REQUIRE_SIGNATURE", True)):
        c2.set(k, v)
    check(any("S1_KEYS" in m for lvl, m in c2.problems() if lvl == "error"), "required signatures need S1_KEYS")
    c2.set("STAGE1_VERSION", "1.2")
    check(any("STAGE1_VERSION" in m for lvl, m in c2.problems() if lvl == "error"), "a bad stage-1 version is refused")
    # key revocation: needs the protected store, and means little without required signatures
    c3 = Config(db, "nucleo-f411re")
    c3.set("REVOKE_KEYS", __file__)                # any existing file: only the checks run here
    check(any("protected store" in m for lvl, m in c3.problems() if lvl == "error"), "revocation without a store refused")
    check(any("protects nothing" in m for lvl, m in c3.problems() if lvl == "warn"), "revocation without required signatures warned")
    c3.set("TWO_STAGE", True)
    check(not any("protected store" in m for lvl, m in c3.problems()), "two-stage has the store")
    h = gen.mcu_header(cfg, lay, 0x3000, gen.STAGE0_OFF)
    check("#define MB_FEAT_TWO_STAGE 1" in h and "#define MB_FEAT_CONSOLE 0" in h and "#define MB_FEAT_RECV 0" in h,
          "stage 0's header: two-stage on, console and uploads off")
    check("#define MB_FEAT_ENC 0" in h, "stage 0's header: no decryption")
    check("#define MB_FEAT_OS_HOOKS 0" in h, "stage 0's header: no OS hooks (it starts stage 1, not an OS)")
    check("#define MB_FEAT_OS_HOOKS 1" in gen.mcu_header(cfg, lay, 0x3000), "OS hooks on by default")
    small = Config(db, "nucleo-f103rb")
    check(small.effective("OS_HOOKS") and not small.effective("SHELL_DIAG"), "a 32 KB part: OS hooks on, diagnostics off")
    # encrypted images: a key, a valid one, no open memory dump, and a warning about the debug port
    c4 = Config(db, "nucleo-f411re")
    c4.set("ENCRYPTED_IMAGES", True)
    errs = lambda c: [m for lvl, m in c.problems() if lvl == "error"]       # noqa: E731
    check(any("ENC_KEY" in m for m in errs(c4)), "encrypted images without a key refused")
    with tempfile.TemporaryDirectory() as td:
        bad_key, good_key = Path(td) / "bad.key", Path(td) / "good.key"
        bad_key.write_text("not a key\n")
        good_key.write_text("# board key\n" + "ab" * 32 + "\n")
        c4.set("ENC_KEY", str(bad_key))
        check(any("hex" in m for m in errs(c4)), "a malformed key file refused")
        c4.set("ENC_KEY", str(good_key))
        check(any("SHELL_DIAG" in m for m in errs(c4)), "the memory dump open to anyone refused")
        c4.set("SHELL_DIAG", False)
        check(not errs(c4), f"a good key, no dump: accepted ({errs(c4)})")
        check(any("debug port" in m for lvl, m in c4.problems() if lvl == "warn"), "warned about the debug port")
        h4 = gen.mcu_header(c4, lay, 0x3000)
        check("#define MB_FEAT_ENC 1" in h4 and "#define MB_ENC_KEY {" + ",".join(["0xab"] * 32) + "}" in h4,
              "the header carries the key")
        c5 = Config(db, "bluepill")                  # Cortex-M3: early-terminating multiplies
        for k, v in (("CONSOLE", True), ("SHELL", True), ("RECV", True), ("ENCRYPTED_IMAGES", True), ("ENC_KEY", str(good_key)), ("SHELL_DIAG", False)):
            c5.set(k, v)
        check(any("Cortex-M3" in m for m in errs(c5)), "Cortex-M3: encryption without CONSOLE_AUTH refused")
        c5.set("SIGNATURES", True)
        c5.set("CONSOLE_AUTH", True)
        check(not any("Cortex-M3" in m for m in errs(c5)), "Cortex-M3 with the console locked: allowed")
    lms_checks(db, lay)


def lms_key_file(path: Path, w: int = 4, ed: bool = False) -> Path:
    """a KEYS file with one LMS public key (H5, made from a fixed seed) and maybe an Ed25519 one"""
    import mb_lms
    lt, ot = mb_lms.lms_type_for(5, w)
    pub, _ = mb_lms.public_from_seed(lt, ot, bytes(range(16)), bytes(range(32)))
    path.write_text("# LMS\n" + pub.hex() + "\n" + ("cd" * 32 + "\n" if ed else ""))
    return path


def lms_checks(db, lay):
    """LMS keys: post-quantum only builds (no Ed25519 code), the key macros, the warnings"""
    errs = lambda c: [m for lvl, m in c.problems() if lvl == "error"]       # noqa: E731
    warns = lambda c: [m for lvl, m in c.problems() if lvl == "warn"]       # noqa: E731
    with tempfile.TemporaryDirectory() as td:
        keys = lms_key_file(Path(td) / "lms.pub")
        c = Config(db, "nucleo-f411re")
        for k, v in (("SIGNATURES", False), ("LMS", True), ("KEYS", str(keys)), ("REQUIRE_SIGNATURE", True)):
            c.set(k, v)
        check(c.effective("REQUIRE_SIGNATURE") and c.effective("KEYS"), "with LMS on, KEYS and required signatures need no Ed25519")
        check(not errs(c) and not any("LMS" in m for m in warns(c)), f"an LMS-only build: accepted ({errs(c)} {warns(c)})")
        h = gen.mcu_header(c, lay, 0x3000)
        check("#define MB_FEAT_SIGNATURES 0" in h and "#define MB_FEAT_LMS 1" in h and "#define MB_TRUSTED_LMS_KEY_COUNT 1" in h,
              "the header: no Ed25519, LMS on, the key")
        check("#define MB_LMS_SIG_MAX 2348" in h, "the upload buffer sized for the key (H5 / W4: 2348 bytes)")
        c.set("LMS", False)
        check(not c.effective("KEYS"), "LMS off and Ed25519 off: no keys at all")
        c.set("SIGNATURES", True)
        try:
            gen.key_macros(c)
            check(False, "an LMS key with LMS off: refused")
        except ValueError as e:
            check("turn on LMS" in str(e), "an LMS key with LMS off: refused")
        mixed = lms_key_file(Path(td) / "mixed.pub", ed=True)
        c.set("LMS", True)
        c.set("KEYS", str(mixed))
        check(any("quantum" in m for m in warns(c)), "LMS next to an Ed25519 key: warned")
        c.set("KEYS", str(Path(td) / "lms.pub"))
        c.set("SIGNATURES", False)
        c.set("TWO_STAGE", True)
        c.set("S1_KEYS", str(lms_key_file(Path(td) / "s1.pub", w=8)))
        check(any("W8" in m for m in warns(c)), "a W8 stage-1 key: warned (stage 0 checks two copies every boot)")
        h = gen.mcu_header(c, lay, 0x3000)
        check("#define MB_S1_LMS_KEY_COUNT 1" in h and "#define MB_LMS_SIG_MAX 2348" in h, "stage-1 LMS keys in the header")


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


def usb_descriptors(out: Path) -> list[str]:
    """Problems with the USB descriptors linked into a CONSOLE_USB build (read from the binary)"""
    import struct
    from mu import build as mubuild
    nm = mubuild._tool(mubuild.arm_gcc(), "nm")
    syms = {}
    for line in subprocess.run([nm, "-S", str(out / "mimiboot.elf")], capture_output=True, text=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 4:
            syms[parts[3]] = (int(parts[0], 16), int(parts[1], 16))
    image = (out / "mimiboot.bin").read_bytes()
    bad = []
    if "dev_desc" not in syms or "cfg_desc" not in syms:
        return ["descriptors not found in the binary"]
    a, n = syms["dev_desc"]
    dev = image[a:a + n]
    if n != 18 or dev[0] != 18 or dev[1] != 1 or struct.unpack_from("<H", dev, 2)[0] != 0x0200 or dev[7] != 64:
        bad.append(f"device descriptor {dev.hex()}")
    a, n = syms["cfg_desc"]
    cfg = image[a:a + n]
    if cfg[1] != 2 or struct.unpack_from("<H", cfg, 2)[0] != n:
        bad.append(f"configuration: total length {struct.unpack_from('<H', cfg, 2)[0]}, {n} bytes there")
    i, kinds, eps = 0, [], {}
    while i < n:
        ln, kind = cfg[i], cfg[i + 1]
        if ln < 2 or i + ln > n:
            bad.append(f"descriptor at {i}: length {ln}")
            break
        kinds.append(kind)
        if kind == 5:
            eps[cfg[i + 2]] = (cfg[i + 3] & 3, struct.unpack_from("<H", cfg, i + 4)[0])
        i += ln
    if kinds.count(0x0B) != 1 or kinds.count(4) != 2 or cfg[4] != 2:
        bad.append(f"expected one IAD and two interfaces: {kinds}")
    if eps != {0x81: (3, 8), 0x02: (2, 64), 0x82: (2, 64)}:
        bad.append(f"endpoints {eps}")
    return bad


def build_variants():
    """Every bare-metal board again, as two-stage and with SMP, where the configurator
    says the variant fits (small parts are refused up front, and that is checked too)"""
    from mu import build as mubuild
    db = Db()
    bad, built, refused = [], 0, 0
    out = Path(tempfile.mkdtemp(prefix="mu-variants-"))
    for name in db.boards:
        if Config(db, name).t.build != "mcu":
            continue
        lms_keys = lms_key_file(out / "lms.pub") if not (out / "lms.pub").exists() else out / "lms.pub"
        variants = [("two-stage", {"TWO_STAGE": True}), ("smp", {"SMP": True}),
                    ("lms-only", {"SIGNATURES": False, "LMS": True, "KEYS": str(lms_keys), "REQUIRE_SIGNATURE": True,
                                  "BOOT_VERIFY": "every-boot"})]
        if Config(db, name).t.get("vendor") == "samd":
            variants.append(("usb", {"CONSOLE_USB": True}))
        for variant, opts in variants:
            cfg = Config(db, name)
            for k, v in opts.items():
                cfg.set(k, v)
            if [m for lvl, m in cfg.problems() if lvl == "error"]:
                refused += 1        # e.g. two-stage on a part under 192 KB: said so before building
                continue
            try:
                info = mubuild.build(cfg, out / f"{name}-{variant}", log=lambda *a: None)
                built += 1
                if variant == "usb":
                    probs = usb_descriptors(out / f"{name}-{variant}")
                    if probs:
                        bad.append(f"{name}/usb descriptors")
                        print(f"  {name:20} usb       DESCRIPTORS: {'; '.join(probs)}")
                print(f"  {name:20} {variant:9} {info['flash_used']:6} / {info['flash_region']} bytes")
            except Exception as e:  # noqa: BLE001
                msg = str(e).splitlines()[-1] if str(e) else traceback.format_exc()
                if "RAM" in msg or "has room for" in msg or "flash layout" in msg:
                    refused += 1    # doesn't fit the part's default region or sectors, and the build says so
                    print(f"  {name:20} {variant:9} doesn't fit: {msg[:100]}")
                    continue
                bad.append(f"{name}/{variant}")
                print(f"  {name:20} {variant:9} FAILED: {msg}")
    print(f"build-variants: {built} built, {refused} refused as too small, {len(bad)} failed"
          + (f" ({', '.join(bad)})" if bad else ""))
    return len(bad) + lms_two_stage(db, out)


def lms_two_stage(db, out: Path) -> int:
    """Two-stage builds whose stage 0 checks stage 1 with LMS (the stage-1 copies signed with an
    LMS key by the build), with and without Ed25519 in the build"""
    import mb_lms
    from mu import build as mubuild
    sys.path.insert(0, str(ROOT / "tools"))
    import mbtool
    key = out / "s1-lms.key"
    if not key.exists():
        mb_lms.generate(str(key), h=5, w=4)
    pub = mb_lms.PrivateKey(str(key)).public
    (out / "s1-lms.pub").write_text(pub.hex() + "\n")
    bad = 0
    for board in ("microbit", "nucleo-l476rg"):
        for ed in (True, False):
            cfg = Config(db, board)
            for k, v in (("TWO_STAGE", True), ("LMS", True), ("SIGNATURES", ed), ("S1_KEYS", str(out / "s1-lms.pub")),
                         ("STAGE1_SIGN_KEY", str(key)), ("KEYS", str(out / "s1-lms.pub")), ("REQUIRE_SIGNATURE", True)):
                cfg.set(k, v)
            name = f"{board}-two-stage-lms{'+ed' if ed else ''}"
            try:
                info = mubuild.build(cfg, out / name, log=lambda *a: None)
                img = (out / name / "stage1-s1a.img").read_bytes()
                h = mbtool.parse_header(img)
                ok = h["flags"] & mbtool.F_LMS and mb_lms.verify(pub, img[:mbtool.SIGNED_BYTES], mbtool.lms_sig_of(img))
                print(f"  {name:32} stage 0 {info['stage0_used']} B, stage 1 {info['flash_used']} B, "
                      f"s1a LMS signature {'OK' if ok else 'BAD'}")
                bad += 0 if ok else 1
            except Exception as e:  # noqa: BLE001
                bad += 1
                print(f"  {name:32} FAILED: {str(e).splitlines()[-1] if str(e) else traceback.format_exc()}")
    return bad


if __name__ == "__main__":
    rc = main()
    if "--build-all" in sys.argv:
        rc += build_all()
    if "--build-variants" in sys.argv:
        rc += build_variants()
    sys.exit(1 if rc else 0)
