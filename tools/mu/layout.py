"""Flash layout planning for MCUs with physical erase sectors (STM32).

Every region (bootloader, the two log copies, the two config copies, each
slot) starts and ends on a physical sector boundary, so erasing one region
can never touch another. That matters on F2/F4/F7, whose sectors are 16 KB
to 256 KB: the core asks for 4 KB erases and the port rounds out to whole
sectors, which is only safe because of this rule.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .model import parse_sectors

LOG_MIN = 2048          # a log copy: a sector header + records of 256 bytes
CFG_MIN = 4096          # a config copy: 256-byte header + up to 3840 bytes of text
SLOT_NAMES = ["a", "b", "g", "c", "d", "e"]
ROLE_AB, ROLE_GOLDEN, ROLE_AUX = 1, 2, 3


class LayoutError(Exception):
    pass


@dataclass
class Region:
    name: str
    offset: int
    size: int
    role: int = 0


@dataclass
class Layout:
    flash_size: int
    sectors: list
    boot: Region
    log: list
    cfg: list
    slots: list
    data: Region
    notes: list = field(default_factory=list)

    def regions(self):
        yield self.boot
        yield from self.log
        yield from self.cfg
        yield from self.slots
        if self.data.size:
            yield self.data

    def check(self):
        """No overlaps, everything sector aligned, everything inside flash."""
        bounds = {o for o, _ in self.sectors} | {self.flash_size}
        regs = sorted(self.regions(), key=lambda r: r.offset)
        end = 0
        for r in regs:
            if r.offset < end:
                raise LayoutError(f"{r.name} overlaps the region before it")
            if r.offset not in bounds or (r.offset + r.size) not in bounds:
                raise LayoutError(f"{r.name} is not sector aligned")
            end = r.offset + r.size
        if end > self.flash_size:
            raise LayoutError("layout runs past the end of flash")


def plan(flash_size: int, sector_spec: str, boot_bytes: int, slots: str = "ab", aux: int = 0,
         cfg_file: bool = False) -> Layout:
    sectors = [(o, s) for o, s in parse_sectors(sector_spec) if o < flash_size]
    if sum(s for _, s in sectors) != flash_size:
        raise LayoutError(f"sector map covers {sum(s for _, s in sectors)} bytes, flash is {flash_size}")
    cur = 0
    notes = []

    def take(name, minimum, role=0):
        nonlocal cur
        start, total = cur, 0
        while total < minimum:
            if cur >= len(sectors):
                raise LayoutError(f"flash full while placing {name} (need {minimum} more bytes)")
            total += sectors[cur][1]
            cur += 1
        return Region(name, sectors[start][0], total, role)

    boot = take("boot", boot_bytes)
    if boot.size > boot_bytes:
        notes.append(f"bootloader region rounded up to {boot.size // 1024} KB (sector boundary)")
    log = [take("log0", LOG_MIN), take("log1", LOG_MIN)]
    cfg = [take("cfg0", CFG_MIN), take("cfg1", CFG_MIN)] if cfg_file else []
    if cfg and cfg[0].size + cfg[1].size > 4 * CFG_MIN:
        notes.append(f"config file costs {(cfg[0].size + cfg[1].size) // 1024} KB here (large sectors)")

    roles = {"single": [ROLE_AB], "ab": [ROLE_AB, ROLE_AB], "ab+golden": [ROLE_AB, ROLE_AB, ROLE_GOLDEN]}[slots]
    if aux:
        if slots != "ab+golden":
            raise LayoutError("aux slots need the ab+golden layout (slot 3+ follow golden)")
        roles += [ROLE_AUX] * aux
    rest = sectors[cur:]
    n = len(roles)
    if len(rest) < n:
        raise LayoutError(f"{len(rest)} sectors left for {n} slots: shrink the bootloader or use fewer slots")

    # Split the remaining sectors into n contiguous runs, maximising the smallest
    # run (an image must fit every slot it may be installed to). The last run
    # takes whatever is left over.
    def runs_for(minimum):
        out, i = [], 0
        for k in range(n):
            start, total = i, 0
            if k == n - 1:
                total = sum(s for _, s in rest[i:])
                if total < minimum or i >= len(rest):
                    return None
                out.append((start, len(rest)))
                return out
            while total < minimum and i < len(rest):
                total += rest[i][1]
                i += 1
            if total < minimum:
                return None
            out.append((start, i))
        return out

    candidates = sorted({sum(s for _, s in rest[a:b]) for a in range(len(rest)) for b in range(a + 1, len(rest) + 1)}) \
        if len(rest) <= 64 else sorted({rest[0][1] * k for k in range(1, len(rest) + 1)})
    best = None
    for c in candidates:
        r = runs_for(c)
        if r:
            best = r
    if not best:
        raise LayoutError("can't split the remaining flash into slots")
    slot_regions = []
    for k, (a, b) in enumerate(best):
        off = rest[a][0]
        size = sum(s for _, s in rest[a:b])
        slot_regions.append(Region(SLOT_NAMES[k], off, size, roles[k]))
    sizes = [r.size for r in slot_regions]
    if len(set(sizes)) > 1:
        notes.append("slot sizes differ (" + ", ".join(f"{r.name}={r.size // 1024}K" for r in slot_regions) +
                     f"): keep images under {min(sizes) // 1024} KB to fit any slot")
    lay = Layout(flash_size, sectors, boot, log, cfg, slot_regions, Region("data", flash_size, 0), notes)
    lay.check()
    return lay


def sector_groups(sectors) -> list[tuple[int, int, int]]:
    """[(start, size, count)] runs of equal sectors"""
    out = []
    for off, size in sectors:
        if out and out[-1][1] == size and out[-1][0] + out[-1][1] * out[-1][2] == off:
            out[-1] = (out[-1][0], size, out[-1][2] + 1)
        else:
            out.append((off, size, 1))
    return out
