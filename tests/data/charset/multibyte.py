"""Generates the double-byte code page tables in crates/codec/src/codec/charset/
from CPython's codecs (cp932, gbk, cp949, cp950, big5hkscs), and checks them by
decoding the written tables again.

    uv run --python 3.13 python3 -I tests/data/charset/multibyte.py crates/codec/src/codec/charset

Run with CPython 3.13 (the tables were generated with 3.13.13).

A table maps the bytes 0x80..=0xFF that stand alone (half-width katakana in
CP932) and every two-byte sequence the codec decodes to one character.
CP936 is Python's "gbk" plus 0x80 = U+20AC, which Windows' code page 936
(and the WHATWG gbk decoder) add. Big5-HKSCS is Python's "big5hkscs" plus
A3E1 = U+20AC (the euro sign of code page 950, which the WHATWG big5 index
also has and Python's big5hkscs leaves unmapped).

File layout (little-endian unless noted):

    u8 lead_min, lead_max, trail_min, trail_max
    u16 single[128]       0x80..=0xFF: a code point, 0xFFFF for a lead
                          byte, 0xFFFE for an invalid byte
    u16 segments
    (u16 start, u16 kind << 14 | len, u16 value) * segments
    data[...]

A pair's pointer is (lead - lead_min) * (trail_max - trail_min + 1) +
(trail - trail_min). Segments cover the pointers in order: kind 0 is a gap
(unmapped), kind 1 a run of consecutive code points, kind 2 `len` entries
from data[value..].

In the narrow tables (cp9xx.bin) data entries are u16 code points (0xFFFF:
unmapped) and a run starts at code point `value`.

The wide table (big5hkscs.bin; 1,693 of its pairs are outside the BMP and 4
decode to two code points) has u32 data entries and a run starts at the code
point data[value]. An entry is a code point, 0xFFFFFFFF for unmapped, or
0x80000000 | i for the two code points data[i] and data[i + 1] (stored
after the entries the segments use).
"""

import os
import struct
import sys

# (file name, Python codec, wide)
CODECS = [
    ("cp932", "cp932", False),
    ("cp936", "gbk", False),
    ("cp949", "cp949", False),
    ("cp950", "cp950", False),
    ("big5hkscs", "big5hkscs", True),
]
MIN_RUN = 6  # shorter runs stay literal
MIN_GAP = 4  # shorter gaps stay literal (as unmapped)
EXTRA = {"cp936": {(0x80,): "€"}, "big5hkscs": {(0xA3, 0xE1): "€"}}


def decode(codec, b, wide):
    """The character(s) `b` decodes to: one code point, or for a wide table
    one or two."""
    try:
        s = b.decode(codec)
    except UnicodeDecodeError:
        return None
    return s if len(s) == 1 or (wide and len(s) == 2) else None


def table(name, codec, wide):
    extra = EXTRA.get(name, {})

    def dec(b):
        return extra.get(tuple(b)) or decode(codec, b, wide)

    single = []
    leads = []
    for b in range(0x80, 0x100):
        c = dec(bytes([b]))
        if c is not None:
            single.append(ord(c))
            continue
        if any(dec(bytes([b, t])) for t in range(0x40, 0x100)):
            single.append(0xFFFF)
            leads.append(b)
        else:
            single.append(0xFFFE)
    pairs = {}
    for lead in leads:
        for t in range(0x30, 0x100):
            c = dec(bytes([lead, t]))
            if c is not None:
                pairs[(lead, t)] = tuple(ord(x) for x in c)
    lead_min, lead_max = min(leads), max(leads)
    trail_min = min(t for _, t in pairs)
    trail_max = max(t for _, t in pairs)
    width = trail_max - trail_min + 1
    total = (lead_max - lead_min + 1) * width
    cells = [None] * total
    for (lead, t), c in pairs.items():
        if not wide:
            assert c[0] < 0xFFFE, (name, lead, t, c)
            c = c[0]
        elif len(c) == 1:
            c = c[0]
        cells[(lead - lead_min) * width + (t - trail_min)] = c
    return (lead_min, lead_max, trail_min, trail_max), single, cells, pairs


def segments(cells, wide):
    unmapped = 0xFFFFFFFF if wide else 0xFFFF
    segs, data = [], []
    seqs = []  # two-code-point cells: (data index, (a, b))
    i, n = 0, len(cells)

    def scalar(c):
        return isinstance(c, int)

    def run_len(i):
        j = i + 1
        while j < n and scalar(cells[j]) and cells[j] == cells[j - 1] + 1:
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
        r = run_len(i) if scalar(cells[i]) else 0
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
                if wide:
                    segs.append((i, 1, r, len(data)))
                    data.append(cells[i])
                else:
                    segs.append((i, 1, r, cells[i]))
                i += r
            continue
        if lit is None or lit[2] == 0x3FFF:
            if lit is not None:
                segs.append(lit)
            lit = (i, 2, 0, len(data))
        c = cells[i]
        if c is None:
            data.append(unmapped)
        elif scalar(c):
            data.append(c)
        else:
            seqs.append((len(data), c))
            data.append(None)  # patched below
        lit = (lit[0], 2, lit[2] + 1, lit[3])
        i += 1
    if lit is not None:
        segs.append(lit)
    for at, (a, b) in seqs:
        data[at] = 0x80000000 | len(data)
        data += [a, b]
    assert len(data) < 0x10000 and len(segs) < 0x10000
    return segs, data


def lookup(blob, p, wide):
    """The table's cell for pointer p, read back from the file."""
    nseg = struct.unpack_from("<H", blob, 4 + 256)[0]
    base = 4 + 256 + 2
    data = base + nseg * 6
    fmt, size = ("<I", 4) if wide else ("<H", 2)

    def entry(i):
        return struct.unpack_from(fmt, blob, data + i * size)[0]

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
        return (entry(value) if wide else value) + off
    c = entry(value + off)
    if c == (0xFFFFFFFF if wide else 0xFFFF):
        return None
    if wide and c & 0x80000000:
        i = c & 0x7FFFFFFF
        return (entry(i), entry(i + 1))
    return c


def main():
    out = sys.argv[1]
    for name, codec, wide in CODECS:
        bounds, single, cells, pairs = table(name, codec, wide)
        segs, data = segments(cells, wide)
        blob = bytes(bounds) + struct.pack("<128H", *single)
        blob += struct.pack("<H", len(segs))
        for start, kind, length, value in segs:
            blob += struct.pack("<HHH", start, kind << 14 | length, value)
        blob += struct.pack("<%d%s" % (len(data), "I" if wide else "H"), *data)
        _, _, trail_min, trail_max = bounds
        for p, c in enumerate(cells):
            assert lookup(blob, p, wide) == c, (name, p)
        assert len(pairs) == sum(c is not None for c in cells)
        with open(os.path.join(out, name + ".bin"), "wb") as f:
            f.write(blob)
        astral = sum(max(c) > 0xFFFF for c in pairs.values())
        double = sum(len(c) == 2 for c in pairs.values())
        print(
            f"{name}: leads {bounds[0]:#x}-{bounds[1]:#x}, trails {trail_min:#x}-{trail_max:#x},"
            f" {len(pairs)} pairs ({astral} outside the BMP, {double} two code points),"
            f" {len(segs)} segments, {len(data)} literals, {len(blob)} bytes"
        )


main()
