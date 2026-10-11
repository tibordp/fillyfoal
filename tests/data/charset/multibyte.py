"""Generates the double-byte code page tables in crates/codec/src/codec/charset/
from CPython's codecs (cp932, gbk, cp949, cp950), and checks them by decoding
the written tables again.

    uv run --python 3.13 python3 -I tests/data/charset/multibyte.py crates/codec/src/codec/charset

Run with CPython 3.13 (the tables were generated with 3.13.13).

A table maps the bytes 0x80..=0xFF that stand alone (half-width katakana in
CP932) and every two-byte sequence the codec decodes to one character.
CP936 is Python's "gbk" plus 0x80 = U+20AC, which Windows' code page 936
(and the WHATWG gbk decoder) add.

File layout (little-endian u16s unless noted):

    u8 lead_min, lead_max, trail_min, trail_max
    u16 single[128]       0x80..=0xFF: a code point, 0xFFFF for a lead
                          byte, 0xFFFE for an invalid byte
    u16 segments
    (u16 start, u16 kind << 14 | len, u16 value) * segments
    u16 data[...]

A pair's pointer is (lead - lead_min) * (trail_max - trail_min + 1) +
(trail - trail_min). Segments cover the pointers in order: kind 0 is a gap
(unmapped), kind 1 a run of consecutive code points from `value`, kind 2
`len` code points from data[value..] (0xFFFF: unmapped).
"""

import os
import struct
import sys

CODECS = [("cp932", "cp932"), ("cp936", "gbk"), ("cp949", "cp949"), ("cp950", "cp950")]
MIN_RUN = 6  # shorter runs stay literal
MIN_GAP = 4  # shorter gaps stay literal (as 0xFFFF)


def decode(codec, b):
    try:
        s = b.decode(codec)
    except UnicodeDecodeError:
        return None
    return s if len(s) == 1 else None


def table(name, codec):
    single = []
    leads = []
    for b in range(0x80, 0x100):
        c = decode(codec, bytes([b]))
        if name == "cp936" and b == 0x80:
            c = "€"
        if c is not None:
            single.append(ord(c))
            continue
        if any(decode(codec, bytes([b, t])) for t in range(0x40, 0x100)):
            single.append(0xFFFF)
            leads.append(b)
        else:
            single.append(0xFFFE)
    pairs = {}
    for lead in leads:
        for t in range(0x30, 0x100):
            c = decode(codec, bytes([lead, t]))
            if c is not None:
                pairs[(lead, t)] = ord(c)
    lead_min, lead_max = min(leads), max(leads)
    trail_min = min(t for _, t in pairs)
    trail_max = max(t for _, t in pairs)
    width = trail_max - trail_min + 1
    total = (lead_max - lead_min + 1) * width
    cells = [None] * total
    for (lead, t), c in pairs.items():
        assert c < 0xFFFE, (name, lead, t, c)
        cells[(lead - lead_min) * width + (t - trail_min)] = c
    return (lead_min, lead_max, trail_min, trail_max), single, cells, pairs


def segments(cells):
    segs, data = [], []
    i, n = 0, len(cells)

    def run_len(i):
        j = i + 1
        while j < n and cells[j] is not None and cells[j] == cells[j - 1] + 1:
            j += 1
        return j - i

    def gap_len(i):
        j = i
        while j < n and cells[j] is None:
            j += 1
        return j - i

    lit = None
    while i < n:
        g = gap_len(i)
        r = run_len(i) if cells[i] is not None else 0
        if g >= MIN_GAP or r >= MIN_RUN:
            if lit is not None:
                segs.append(lit)
                lit = None
            if g >= MIN_GAP:
                g = min(g, 0x3FFF)
                segs.append((i, 0, g, 0))
                i += g
            else:
                r = min(r, 0x3FFF)
                segs.append((i, 1, r, cells[i]))
                i += r
            continue
        if lit is None or lit[2] == 0x3FFF:
            if lit is not None:
                segs.append(lit)
            lit = (i, 2, 0, len(data))
        data.append(0xFFFF if cells[i] is None else cells[i])
        lit = (lit[0], 2, lit[2] + 1, lit[3])
        i += 1
    if lit is not None:
        segs.append(lit)
    assert len(data) < 0x10000 and len(segs) < 0x10000
    return segs, data


def lookup(blob, p):
    """The table's code point for pointer p, read back from the file."""
    nseg = struct.unpack_from("<H", blob, 4 + 256)[0]
    base = 4 + 256 + 2
    data = base + nseg * 6
    lo, hi = 0, nseg
    while lo < hi:  # last segment with start <= p
        mid = (lo + hi) // 2
        if struct.unpack_from("<H", blob, base + mid * 6)[0] <= p:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    start, kl, value = struct.unpack_from("<HHH", blob, base + (lo - 1) * 6)
    kind, length, off = kl >> 14, kl & 0x3FFF, p - start
    if off >= length or kind == 0:
        return None
    if kind == 1:
        return value + off
    c = struct.unpack_from("<H", blob, data + (value + off) * 2)[0]
    return None if c == 0xFFFF else c


def main():
    out = sys.argv[1]
    for name, codec in CODECS:
        bounds, single, cells, pairs = table(name, codec)
        segs, data = segments(cells)
        blob = bytes(bounds) + struct.pack("<128H", *single)
        blob += struct.pack("<H", len(segs))
        for start, kind, length, value in segs:
            blob += struct.pack("<HHH", start, kind << 14 | length, value)
        blob += struct.pack("<%dH" % len(data), *data)
        lead_min, _, trail_min, trail_max = bounds
        width = trail_max - trail_min + 1
        for p, c in enumerate(cells):
            assert lookup(blob, p) == c, (name, p)
        assert len(pairs) == sum(c is not None for c in cells)
        with open(os.path.join(out, name + ".bin"), "wb") as f:
            f.write(blob)
        print(
            f"{name}: leads {bounds[0]:#x}-{bounds[1]:#x}, trails {trail_min:#x}-{trail_max:#x},"
            f" {len(pairs)} pairs, {len(segs)} segments, {len(data)} literals, {len(blob)} bytes"
        )


main()
