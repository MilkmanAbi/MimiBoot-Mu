"""The pages of the documentation site (MilkmaidAbi/MimiBoot-Mu-Docs) that come straight
from this repository, so they can't drift from it:

  options.md          every option (the same text as docs/OPTIONS.md)
  boards.md           every board, grouped as the board picker groups them
  matrix.html         the feature matrix: every board, every feature, whether it is there,
                      on by default, and how far it has been tested (hardware, emulator,
                      a register model, host tests, or only compiled)
  status.md           docs/HARDWARE-STATUS.md
  security.md         docs/SECURITY.md
  os-integration.md   docs/OS-INTEGRATION.md

    python muconfigurator.py site <docs site checkout>

How far each feature has been tested comes from EVIDENCE below, which follows
docs/HARDWARE-STATUS.md: change one, change the other.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

from .model import ROOT, STATUS_TEXT, Config, Db

# ---------------------------------------------------------------------------
# How far things have run. Levels, best first:
#   hardware   ran on a real board          emulator  the real build ran in QEMU / simavr
#   model      the driver ran against a register model on a PC
#   host       the logic is covered by host tests (simulated flash), not on this chip
#   built      compiles and fits; never executed
# ---------------------------------------------------------------------------
LEVELS = ["hardware", "emulator", "model", "host", "built"]
LEVEL_TEXT = {"hardware": "ran on a real board", "emulator": "ran in an emulator (QEMU / simavr)",
              "model": "driver ran against a register model", "host": "logic tested on a PC, not on this chip",
              "built": "compiles; never run"}

# what each emulator run covered (tests/qemu/test_qemu.py, tests/avr/test_avr.py)
EMULATOR = {
    "microbit": {"LAYOUT", "IMG_NATIVE", "CONSOLE", "SHELL", "SHELL_DIAG", "RECV", "SCRUB_RAM", "HANDOFF", "SIGNATURES",
                 "REQUIRE_SIGNATURE", "SMP", "ENCRYPTED_IMAGES", "BOOT_RECORD", "LMS", "TWO_STAGE", "REVOKE_KEYS",
                 "PROTECTED_FLOOR", "CONSOLE_AUTH", "BOARD_LED", "BREAK_IN_MS", "MENU_SECS", "AB_TRIAL"},
    "netduinoplus2": {"LAYOUT", "IMG_NATIVE", "IMG_RAW", "IMG_MCUBOOT", "SIGNATURES", "ECDSA", "REQUIRE_SIGNATURE",
                      "CONSOLE", "SHELL", "BREAK_IN_MS", "HANDOFF", "CONTROL", "OS_HOOKS", "TWO_STAGE"},
    "stm32vldiscovery": {"LAYOUT", "IMG_NATIVE", "IMG_RAW", "CONSOLE", "SHELL", "BREAK_IN_MS", "HANDOFF"},
    "uno": {"STK500", "EEPROM_RW", "ENTRY", "TIMEOUT_MS", "VERIFY", "NOAPP_STAY", "APP_REQUEST", "LITE_HANDOFF",
            "LITE_TRIAL", "LITE_TRIES", "SPM_API", "STAGED_UPDATE"},
}
# the RP ports ran on real boards as an earlier build (MimiBoot 2.0), before the configurable version
# Only what was recorded running: the RP2350 run of 28 October 2026 (boot from a slot, the SHA-256 check,
# trial + confirm, flash mode with an mbtool upload). The RP2040 board ran an earlier build too, with no
# record of which features, so only booting an image from flash and the console count.
HARDWARE = {
    "pico": {"LAYOUT", "IMG_NATIVE", "CONSOLE"},
    "rp2350-lcd": {"LAYOUT", "IMG_NATIVE", "BOOT_VERIFY", "CONSOLE", "SHELL", "RECV", "AB_TRIAL", "TRIES"},
}
HW_NOTE = "on an earlier build (MimiBoot 2.0), before the options existed"
# options whose logic the host tests cover (tests/run.py, tests/test_profiles.py, the fuzzers)
HOST = {"LAYOUT", "AUX_SLOTS", "AB_TRIAL", "TRIES", "TRIAL_WATCHDOG", "TRIAL_MS", "CRASH_GUARD", "ANTI_ROLLBACK",
        "IMG_NATIVE", "IMG_MCUBOOT", "IMG_RAW", "RAM_IMAGES", "BOOT_VERIFY", "SIGNATURES", "ECDSA", "LMS",
        "REQUIRE_SIGNATURE", "KEYS", "REVOKE_KEYS", "ENCRYPTED_IMAGES", "ENC_KEY", "BOOT_RECORD", "CFG_SIGNED",
        "FAULT_HARDENING", "CONSOLE_AUTH", "UNLOCK_KEYS", "PROTECTED_FLOOR", "CONSOLE", "SHELL", "SHELL_DIAG", "RECV",
        "SMP", "SMP_BUF", "CFG_FILE", "GRUB", "MENU_SECS", "HANDOFF", "CONTROL", "OS_HOOKS", "TWO_STAGE",
        "STAGE1_VERSION", "STAGE1_SECURITY", "S1_KEYS", "STAGE1_SIGN_KEY"}
# options that are build-tool settings, not code on the chip: no test level
TOOL_ONLY = {"OUTPUT_DIR", "EXPORT_SOURCE", "KEYS", "REVOKE_KEYS", "ENC_KEY", "UNLOCK_KEYS", "S1_KEYS", "STAGE1_SIGN_KEY",
             "STAGE1_VERSION", "STAGE1_SECURITY", "USB_VID", "USB_PID", "BOOT_SIZE", "STAGE1_SIZE"}
# a word on the features whose state needs one (shown next to them)
NOTES = {
    "BOOT_LOCK": "the lock itself has never been seen to hold (QEMU doesn't model it)",
    "LOCK_GOLDEN": "same lock code as BOOT_LOCK; never run",
    "DEBUG_LOCK": "never run; on nRF52 it closes the debug port until a full erase",
    "PROTECTED_FLOOR": "nRF51 in QEMU through the real NVMC driver; not on nRF52",
    "CONSOLE_USB": "never enumerated: no SAM D board here",
    "TRIAL_WATCHDOG": "the watchdog drivers never ran on a chip",
    "ENCRYPTED_IMAGES": "timing of X25519 / AES not measured on silicon",
    "LMS": "check time not measured on silicon",
    "OS_HOOKS": "the mailbox ran across real resets in QEMU (STM32F405); System OFF never ran",
    "TWO_STAGE": "both stages ran in QEMU (nRF51, STM32F405); the STM32 store write never ran",
    "SMP": "QEMU nRF51 with the smp library; no mcumgr CLI has talked to it",
}
# per family: the parts that never ran, whatever the options
NEVER_RAN = {
    "stm32": "No STM32 flash write has ever run: QEMU has no STM32 flash controller, so the erase/program drivers "
             "(F0/F1/F3, F2/F4/F7, L4/G0/G4) are written from the reference manuals and never executed. Uploads, "
             "the boot log, confirms and floors all write flash.",
    "nrf": "nRF51 ran in QEMU. On nRF52 the UARTE console, the HF crystal start, APPROTECT, the watchdog, GPIO port 1 "
           "and VTOR have never run.",
    "samd": "The flash driver ran against a register model; clocks, SERCOM, PORT, the watchdog and USB never ran.",
    "pico": "Earlier builds ran on real Pico / RP2350 boards; this configurable version has not been flashed.",
    "avr": "The Uno build ran in simavr with the real avrdude. Other AVRs only compile; the large-flash paths "
           "(RAMPZ/ELPM on 1284P/2560) never ran.",
}
FLASH_WRITES = {"stm32": "built", "samd": "model", "pico": "hardware"}       # nrf / avr: per board below


def _family(cfg: Config) -> str:
    return cfg.t.get("vendor") or cfg.t.build


def _flash_level(board: str, cfg: Config) -> str:
    fam = _family(cfg)
    if fam == "nrf":
        return "emulator" if cfg.t.chip_name.startswith("nrf51") else "built"
    if fam == "avr":
        return "emulator" if board == "uno" else "built"
    if fam == "pico":       # the RP2350 boot-ROM erase/program path ran (earlier build); RP2040's: no record
        return "hardware" if board == "rp2350-lcd" else "built"   # the board that ran (Arm)
    return FLASH_WRITES.get(fam, "built")


def _level(board: str, cfg: Config, oid: str) -> str | None:
    if oid in TOOL_ONLY:
        return None
    if oid in HARDWARE.get(board, ()):
        return "hardware"
    if oid in EMULATOR.get(board, ()):
        return "emulator"
    if oid in HOST and cfg.t.core == "komorebi":
        return "host"
    return "built"


def board_data(db: Db, board: str) -> dict:
    cfg = Config(db, board)
    t = cfg.t
    feats = []
    for o in cfg.options():
        if o.menu == "output":
            continue
        locked = cfg.locked(o.id)
        avail = "fixed" if locked is not None else "yes"
        val = cfg.effective(o.id) if cfg.enabled(o.id) else cfg.values[o.id]
        if o.kind == "bool":
            default = "on" if val else "off"
            if locked is not None:
                avail = "fixed on" if locked else "fixed off"
        else:
            default = str(val) if val not in ("", None) else "-"
        trimmed = cfg.trimmed(o.id)
        feats.append({"id": o.id, "menu": o.menu, "title": o.title, "avail": avail, "default": default,
                      "level": _level(board, cfg, o.id), "note": NOTES.get(o.id, "") + (
                          " (off by default: too big for this chip)" if trimmed and default == "off" else "")})
    fam = _family(cfg)
    facts = dict(t.facts())
    return {"name": board, "title": t.title, "maker": db.maker_title(t.maker), "category": t.category,
            "chip": t.chip_name, "cpu": t.get("cpu") or t.get("mcu") or t.get("platform") or "",
            "memory": facts.get("memory", ""), "console": facts.get("console", ""), "core": t.core,
            "family": fam, "status": t.status, "status_text": STATUS_TEXT.get(t.status, ""),
            "flash_writes": _flash_level(board, cfg), "status_note": HW_NOTE if t.status == "hardware" else "", "never_ran": NEVER_RAN.get(fam if fam != "mcu" else "", ""),
            "features": feats}


def matrix_data(db: Db) -> dict:
    menus = {m: title for m, title in db.menus}
    return {"menus": menus, "levels": LEVEL_TEXT, "boards": [board_data(db, b) for b in db.boards]}


def compact(data: dict) -> dict:
    """the same, with each option's title, area and note once (the page's script expands it)"""
    options, boards = {}, []
    for b in data["boards"]:
        rows = []
        for f in b["features"]:
            options[f["id"]] = [f["title"], f["menu"], NOTES.get(f["id"], "")]
            extra = "; ".join(x for x in ("off by default: too big for this chip" if "too big" in f["note"] else "",
                                           HW_NOTE if f["level"] == "hardware" else "") if x)
            rows.append([f["id"], f["avail"], f["default"], f["level"], extra])
        boards.append({**{k: v for k, v in b.items() if k != "features"}, "f": rows})
    return {"menus": data["menus"], "options": options, "boards": boards}


# ---------------------------------------------------------------------------
# pages
# ---------------------------------------------------------------------------
MATRIX_INTRO = """
<h1>Feature matrix</h1>

<p>Every board, every feature: whether the board has it, whether it is on by default, and how far it has
actually been run. Pick a board, or open a maker below. The same facts in words are on
<a href="status.html">Test status</a>; what to have at hand before you flash is on
<a href="before-you-flash.html">Before you flash</a>.</p>

<div class="warn-box">
<strong>STM32 users: keep an ST-Link (SWD) connected.</strong> No STM32 flash write has ever run on a real chip:
QEMU has no STM32 flash controller, so the erase and program drivers are written from the reference manuals and
have never executed. Uploads, the boot log, confirming an image and the rollback floors all write flash. Until a
board has been tried, wire SWD (an ST-Link, or the one on a Nucleo), make sure STM32CubeProgrammer can
<em>connect under reset</em> and mass-erase it, and don't touch readout protection (RDP level 2 can't be undone).
On most families, holding BOOT0 high at reset starts the chip's own ROM loader; on STM32G0 the factory option bytes
take BOOT0 from an option bit instead of the pin, so there SWD is the way back.
<a href="before-you-flash.html">Details for every family.</a>
</div>
"""

MATRIX_BODY = """
<div class="mx-controls">
  <label>Board <select id="mx-board"><option value="">every board</option></select></label>
  <label>Area <select id="mx-area"><option value="">every area</option></select></label>
  <label>Show <select id="mx-show">
    <option value="">everything</option>
    <option value="nothw">not run on hardware yet</option>
    <option value="built">only compiled, never run</option>
    <option value="on">on by default</option>
    <option value="off">available, off by default</option>
  </select></label>
  <button id="mx-open" type="button">open all</button>
</div>

<p class="mx-legend">
  <span class="lvl lvl-hardware">hardware</span> ran on a real board
  <span class="lvl lvl-emulator">emulator</span> the real build ran in QEMU / simavr
  <span class="lvl lvl-model">model</span> driver ran against a register model
  <span class="lvl lvl-host">host</span> logic tested on a PC, not on this chip
  <span class="lvl lvl-built">built</span> compiles; never run
</p>

<h2>At a glance</h2>
<p>A dot is a feature the board has (filled: on by default); its colour is how far it has run on that board.
Empty cells: not on this board.</p>
<div id="mx-grid"></div>

<h2>Board by board</h2>
<div id="mx-boards"><noscript><p>This page needs JavaScript to draw the tables; the same
facts are on <a href="boards.html">Boards</a> and <a href="status.html">Test status</a>.</p></noscript></div>

<script id="mx-data" type="application/json">__DATA__</script>
<script>
(function () {
  var D = JSON.parse(document.getElementById("mx-data").textContent);
  D.boards.forEach(function (b) {
    b.features = b.f.map(function (a) {
      var o = D.options[a[0]];
      return {id: a[0], title: o[0], menu: o[1], avail: a[1], "default": a[2], level: a[3],
              note: [o[2], a[4]].filter(function (x) { return x; }).join("; ")};
    });
  });
  var esc = function (s) { return String(s).replace(/[&<>"]/g, function (c) { return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;"}[c]; }); };
  var GRID = [["LAYOUT","slots"],["AB_TRIAL","trials"],["CRASH_GUARD","crash guard"],["SIGNATURES","Ed25519"],
              ["ECDSA","P-256"],["LMS","LMS"],["ENCRYPTED_IMAGES","encrypted"],["IMG_MCUBOOT","Zephyr"],
              ["SMP","SMP"],["CONSOLE_USB","USB console"],["TWO_STAGE","two-stage"],["OS_HOOKS","OS hooks"],
              ["BOOT_LOCK","flash lock"],["DEBUG_LOCK","debug lock"],["STK500","STK500"],["STAGED_UPDATE","staged update"]];
  var bSel = document.getElementById("mx-board"), aSel = document.getElementById("mx-area"),
      sSel = document.getElementById("mx-show"), grid = document.getElementById("mx-grid"),
      list = document.getElementById("mx-boards");
  D.boards.forEach(function (b) { bSel.insertAdjacentHTML("beforeend", "<option value=\\"" + esc(b.name) + "\\">" + esc(b.name) + "</option>"); });
  Object.keys(D.menus).forEach(function (m) { aSel.insertAdjacentHTML("beforeend", "<option value=\\"" + esc(m) + "\\">" + esc(D.menus[m]) + "</option>"); });

  function keep(f) {
    var s = sSel.value, a = aSel.value;
    if (a && f.menu !== a) return false;
    if (s === "nothw") return f.level && f.level !== "hardware";
    if (s === "built") return f.level === "built";
    if (s === "on") return f.default !== "off" && f.default !== "-" && f.avail.indexOf("off") < 0;
    if (s === "off") return f.default === "off" && f.avail === "yes";
    return true;
  }
  function badge(l) { return l ? "<span class=\\"lvl lvl-" + l + "\\">" + l + "</span>" : "<span class=\\"lvl lvl-none\\">tool</span>"; }

  function drawGrid() {
    var boards = D.boards.filter(function (b) { return !bSel.value || b.name === bSel.value; });
    var h = "<table class=\\"mx-grid\\"><thead><tr><th>board</th><th>tested</th><th>flash writes</th>";
    GRID.forEach(function (g) { h += "<th>" + esc(g[1]) + "</th>"; });
    h += "</tr></thead><tbody>";
    boards.forEach(function (b) {
      var by = {}; b.features.forEach(function (f) { by[f.id] = f; });
      h += "<tr><td><a href=\\"#b-" + esc(b.name) + "\\">" + esc(b.name) + "</a></td><td title=\\"" + esc(b.status_note) + "\\">" + badge(b.status) + (b.status_note ? " <span class=\\"mx-count\\">earlier build</span>" : "") + "</td><td>" + badge(b.flash_writes) + "</td>";
      GRID.forEach(function (g) {
        var f = by[g[0]];
        if (!f || f.avail === "fixed off") { h += "<td></td>"; return; }
        var on = g[0] === "LAYOUT" ? true : f.default === "on" || f.avail === "fixed on";
        var tip = g[1] + (g[0] === "LAYOUT" ? ": " + f.default : on ? ": on by default" : ": available, off by default") + "; " + (f.level || "") + (f.note ? " (" + f.note + ")" : "");
        h += "<td class=\\"dot lvlc-" + (f.level || "none") + "\\" title=\\"" + esc(tip) + "\\">" + (g[0] === "LAYOUT" ? esc(f.default) : on ? "\\u25cf" : "\\u25cb") + "</td>";
      });
      h += "</tr>";
    });
    grid.innerHTML = h + "</tbody></table>";
  }

  function boardTable(b) {
    var rows = "", last = "";
    b.features.filter(keep).forEach(function (f) {
      if (f.menu !== last) { rows += "<tr class=\\"mx-area\\"><td colspan=\\"4\\">" + esc(D.menus[f.menu] || f.menu) + "</td></tr>"; last = f.menu; }
      rows += "<tr><td>" + esc(f.title) + "<br><code>" + esc(f.id) + "</code></td><td>" + esc(f.avail) + "</td><td>" + esc(f.default) +
              "</td><td>" + badge(f.level) + (f.note ? "<div class=\\"mx-note\\">" + esc(f.note) + "</div>" : "") + "</td></tr>";
    });
    if (!rows) rows = "<tr><td colspan=\\"4\\">nothing matches the filters</td></tr>";
    return "<table class=\\"mx-table\\"><thead><tr><th>feature</th><th>here</th><th>default</th><th>tested</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }

  function drawBoards() {
    var open = {}; list.querySelectorAll("details[open]").forEach(function (d) { open[d.id] = true; });
    var makers = {}, order = [];
    D.boards.forEach(function (b) {
      if (bSel.value && b.name !== bSel.value) return;
      if (!makers[b.maker]) { makers[b.maker] = []; order.push(b.maker); }
      makers[b.maker].push(b);
    });
    var h = "";
    order.forEach(function (m) {
      var mid = "m-" + m.replace(/\\W+/g, "-");
      h += "<details class=\\"mx-maker\\" id=\\"" + mid + "\\"" + (open[mid] || bSel.value ? " open" : "") + "><summary>" + esc(m) +
           " <span class=\\"mx-count\\">" + makers[m].length + " board" + (makers[m].length > 1 ? "s" : "") + "</span></summary>";
      makers[m].forEach(function (b) {
        var bid = "b-" + b.name;
        var hw = b.features.filter(function (f) { return f.level === "hardware"; }).length,
            all = b.features.filter(function (f) { return f.level; }).length;
        h += "<details class=\\"mx-board\\" id=\\"" + esc(bid) + "\\"" + (open[bid] || bSel.value ? " open" : "") + "><summary><strong>" + esc(b.name) +
             "</strong> " + esc(b.title) + " " + badge(b.status) + (b.status_note ? " <span class=\\"mx-count\\">(" + esc(b.status_note) + ")</span>" : "") + " <span class=\\"mx-count\\">" + hw + " of " + all + " features on hardware</span></summary>";
        h += "<div class=\\"mx-facts\\"><div><b>chip</b> " + esc(b.chip) + (b.cpu ? " (" + esc(b.cpu) + ")" : "") + "</div><div><b>memory</b> " + esc(b.memory) +
             "</div><div><b>console</b> " + esc(b.console) + "</div><div><b>core</b> " + esc(b.core === "komorebi" ? "full" : "Lite") +
             "</div><div><b>flash writes</b> " + badge(b.flash_writes) + "</div></div>";
        if (b.never_ran) h += "<p class=\\"" + (b.family === "stm32" ? "warn-box" : "mx-never") + "\\">" + esc(b.never_ran) +
             (b.family === "stm32" ? " Keep an ST-Link on SWD while you try it." : "") + "</p>";
        h += boardTable(b) + "</details>";
      });
      h += "</details>";
    });
    list.innerHTML = h || "<p>no board</p>";
  }
  function draw() { drawGrid(); drawBoards(); }
  [bSel, aSel, sSel].forEach(function (s) { s.addEventListener("change", draw); });
  document.getElementById("mx-open").addEventListener("click", function () {
    var ds = list.querySelectorAll("details"), anyClosed = false;
    ds.forEach(function (d) { if (!d.open) anyClosed = true; });
    ds.forEach(function (d) { d.open = anyClosed; });
    this.textContent = anyClosed ? "close all" : "open all";
  });
  function fromHash() {
    if (location.hash.indexOf("#b-") !== 0) return;
    bSel.value = decodeURIComponent(location.hash.slice(3));
    draw();
    var el = document.getElementById(location.hash.slice(1));
    if (el) el.scrollIntoView();
  }
  window.addEventListener("hashchange", fromHash);
  draw();
  fromHash();
})();
</script>
"""


def matrix_page(db: Db) -> str:
    data = json.dumps(compact(matrix_data(db)), separators=(",", ":")).replace("</", "<\\/")
    # {% raw %}: Liquid must not read the script or the data
    return ("---\ntitle: Feature matrix\nwide: true\n---\n" + MATRIX_INTRO + "{% raw %}" + MATRIX_BODY.replace("__DATA__", data)
            + "{% endraw %}\n")


LINKS = [("docs/SECURITY.md", "security.html"), ("docs/OS-INTEGRATION.md", "os-integration.html"),
         ("docs/HARDWARE-STATUS.md", "status.html"), ("docs/OPTIONS.md", "options.html"),
         ("docs/ZEPHYR-FREERTOS.md", "zephyr-freertos.html"),
         # the same, linked from inside docs/
         ("SECURITY.md", "security.html"), ("OS-INTEGRATION.md", "os-integration.html"),
         ("HARDWARE-STATUS.md", "status.html"), ("OPTIONS.md", "options.html")]


def copied_page(src: Path, title: str, note: str) -> str:
    text = src.read_text(encoding="utf-8")
    for a, b in LINKS:
        text = text.replace(f"({a})", f"({b})").replace(f"[{a}]", f"[{b.replace('.html', '')}]")
    first, rest = text.split("\n", 1)
    return f"---\ntitle: {title}\n---\n\n{first}\n\n> {note}\n{rest}"


def boards_page(db: Db) -> str:
    out = ["---", "title: Boards", "---", "", "# Boards", "",
           "Every board MimiBoot-Mu knows about, grouped the way the board picker groups them. \"Tested\" says how far "
           "each one has actually been run; the [feature matrix](matrix.html) goes feature by feature, and "
           "[Test status](status.html) has the details.", "",
           "> **STM32: no flash write has ever run on a real chip.** Keep an ST-Link on SWD while you try one; see "
           "[Before you flash](before-you-flash.html).", "",
           "To use a board that isn't listed, see [Adding boards and chips](porting.html).", ""]
    for maker, cats in db.tree().items():
        out += [f"## {db.maker_title(maker)}", "", db.makers.get(maker, {}).get("about", ""), ""]
        for cat, names in cats.items():
            out += [f"### {cat}", "", "| Board | Chip | Console | Tested |", "|---|---|---|---|"]
            for n in names:
                t = db.target(n)
                console = dict(t.facts()).get("console", "")
                out.append(f"| [`{n}`](matrix.html#b-{n})<br>{t.title} | {t.chip_name} | {console} | {t.status} |")
            out.append("")
    out += ["Status values: " + "; ".join(f"`{k}` {v}" for k, v in STATUS_TEXT.items()) + ".", ""]
    return "\n".join(out)


def options_page(db: Db) -> str:
    from . import docs
    body = docs.render(db).split("\n", 1)[1]
    body = body.replace("Generated from `config/features.toml` by `python muconfigurator.py docs`; don't edit by hand.",
                        "Generated from `config/features.toml` in the MimiBoot-Mu repository (`python muconfigurator.py site`).")
    return "---\ntitle: Option reference\n---\n\n# Option reference\n" + body


def write(db: Db, site: Path) -> list[str]:
    if not (site / "_config.yml").exists():
        raise SystemExit(f"{site} isn't the docs site (no _config.yml)")
    pages = {
        "options.md": options_page(db),
        "boards.md": boards_page(db),
        "matrix.html": matrix_page(db),
        "status.md": copied_page(ROOT / "docs/HARDWARE-STATUS.md", "Test status",
                                 "From `docs/HARDWARE-STATUS.md` in the repository; the [feature matrix](matrix.html) "
                                 "has the same facts board by board."),
        "security.md": copied_page(ROOT / "docs/SECURITY.md", "Security",
                                   "From `docs/SECURITY.md` in the repository."),
        "os-integration.md": copied_page(ROOT / "docs/OS-INTEGRATION.md", "OS integration",
                                         "From `docs/OS-INTEGRATION.md` in the repository."),
    }
    for name, text in pages.items():
        (site / name).write_text(text, encoding="utf-8", newline="\n")
    return list(pages)
