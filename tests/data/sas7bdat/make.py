"""Writes the synthetic SAS7BDAT fixtures (no free writer exists: ReadStat,
pyreadstat and pandas only read the format).

    uv run --with pandas==3.0.6 --with pyreadstat==1.3.6 python -I make.py

The layout follows what the open readers (ReadStat, pandas' `sas7bdat.py`)
expect, as remembered; the script then reads every file back with both
pandas and pyreadstat and checks the values, so the fixtures are at least
consistent with two independent readers. Pages and headers are smaller
than SAS itself would write (a 1 KiB header, 4 KiB pages) to keep the fixtures small.

- cars.sas7bdat: 64-bit little-endian, uncompressed; a mixed page (metadata
  subheaders and the first rows) and a data page.
- rle.sas7bdat: 32-bit little-endian, rows compressed with SASYZCRL (RLE),
  each in its own subheader on a metadata page.
- rdc.sas7bdat: 64-bit big-endian, rows compressed with SASYZCR2 (RDC).
"""

import math
import pathlib
import struct

OUT = pathlib.Path(__file__).resolve().parent / "../../fixtures/synthetic/sas7bdat"

MAGIC = bytes(12) + bytes.fromhex("c2ea8160b31411cfbd92080009c7318c181f1011")
SAS_EPOCH_OFFSET = 315619200  # 1960-01-01 to 1970-01-01, in seconds
PAGE = 4096
HEADER = 1024

# SAS missing values: NaN with the tag in bits 40..47 (complemented).
def missing(tag="."):
    code = {".": 0xFE, "_": 0xA0}.get(tag, None)
    if code is None:
        code = 0xFF - ord(tag)  # .A = 0xBE ... .Z = 0xA5
    bits = 0xFFFF000000000000 | (code << 40)
    return struct.unpack("<d", struct.pack("<Q", bits))[0]


def days(y, m, d):
    import datetime

    return float((datetime.date(y, m, d) - datetime.date(1960, 1, 1)).days)


COLUMNS = [
    # name, label, format, kind ("d" numeric / "s" string), width
    ("ID", "Identifier", "BEST", "d", 8),
    ("MAKE", "Manufacturer", "$", "s", 12),
    ("PRICE", "Price in USD", "DOLLAR", "d", 8),
    ("BUILT", "Date built", "DATE", "d", 8),
    ("CYL", "", "", "d", 3),  # truncated numeric
]

ROWS = [
    (1.0, "Volvo", 31250.5, days(2019, 3, 14), 4.0),
    (2.0, "Škoda", 18999.0, days(1999, 12, 31), 6.0),
    (3.0, "", missing("."), days(1960, 1, 1), missing("A")),
    (4.0, "Tatra", 1.0e9, missing("_"), 8.0),
    (5.0, "Trabant", -0.25, days(1972, 6, 1), 2.0),
    (6.0, "Trabant", -0.25, days(1972, 6, 1), 2.0),
]


class Layout:
    def __init__(self, u64, little):
        self.u64 = u64
        self.w = 8 if u64 else 4
        self.e = "<" if little else ">"
        self.little = little

    def int(self, v, n=None):
        n = n or self.w
        return v.to_bytes(n, "little" if self.little else "big", signed=v < 0)

    def sig(self, s32):
        # 32-bit signatures, sign-extended to 64 bits in 64-bit files.
        if not self.u64:
            return s32.to_bytes(4, "little" if self.little else "big")
        v = s32 if s32 < 0x80000000 else s32 | 0xFFFFFFFF00000000
        if s32 in (0xF7F7F7F7, 0xF6F6F6F6):
            v = s32
        return v.to_bytes(8, "little" if self.little else "big")

    @property
    def page_header(self):
        return 40 if self.u64 else 24

    @property
    def pointer(self):
        return 24 if self.u64 else 12


def row_bytes(lay, row):
    out = bytearray()
    for (name, _, _, kind, width), v in zip(COLUMNS, row):
        if kind == "s":
            raw = v.encode("utf-8")
            out += raw + b" " * (width - len(raw))
        else:
            full = struct.pack(lay.e + "d", v)
            out += full[8 - width :] if lay.little else full[:width]
    return bytes(out)


def pad(b, n):
    return b + bytes((-len(b)) % n)


def text_blob(lay, literal):
    """The column text subheader's blob and the (offset, length) of each
    string in it."""
    blob = bytearray(bytes(12))
    blob += literal.ljust(8, b"\0") if literal else bytes(8)
    blob += b"DATASTEP"
    refs = {}

    def add(s):
        if not s:
            return (0, 0)
        if s in refs:
            return refs[s]
        raw = s.encode("utf-8")
        refs[s] = (len(blob), len(raw))
        blob.extend(pad(raw, 4))
        return refs[s]

    names = [add(c[0]) for c in COLUMNS]
    formats = [add(c[2]) for c in COLUMNS]
    labels = [add(c[1]) for c in COLUMNS]
    label = add("Synthetic cars")
    return bytes(blob), names, formats, labels, label


def subheaders(lay, literal, row_length, row_count, mix_rows):
    w = lay.w
    subs = []
    # Row size.
    rs = bytearray(808 if lay.u64 else 480)
    rs[0:w] = lay.sig(0xF7F7F7F7)
    rs[5 * w : 6 * w] = lay.int(row_length)
    rs[6 * w : 7 * w] = lay.int(row_count)
    rs[9 * w : 10 * w] = lay.int(len(COLUMNS))
    rs[10 * w : 11 * w] = lay.int(0)
    rs[15 * w : 16 * w] = lay.int(mix_rows)
    # Text references near the end (ReadStat): the file label, the
    # compression method (the literal at blob offset 12) and the creator
    # procedure. pandas reads the lengths of the first and last as "lcs"
    # and "lcp".
    blob, names, formats, labels, label = text_blob(lay, literal)
    end = len(rs)

    def ref(at, offset, length):
        rs[at : at + 6] = lay.int(0, 2) + lay.int(offset, 2) + lay.int(length, 2)

    ref(end - 130, *label)
    if literal:
        ref(end - 118, 12, 8)
    ref(end - 106, 20, 8)
    subs.append(bytes(rs))
    # Column size.
    cs = lay.sig(0xF6F6F6F6) + lay.int(len(COLUMNS)) + bytes(w)
    subs.append(cs)
    # Column text.
    # The size field holds the same "remainder" as the other subheaders
    # (length less 4 and twice the signature size), which counts from the
    # field itself: the 4 + w bytes after it are padding.
    text = bytearray(pad(lay.sig(0xFFFFFFFD) + blob + bytes(4 + w), w))
    text[w : w + 2] = lay.int(len(text) - 4 - 2 * w, 2)
    subs.append(bytes(text))
    # Column names.
    cn = bytearray(lay.sig(0xFFFFFFFF))
    entries = b"".join(lay.int(0, 2) + lay.int(o, 2) + lay.int(n, 2) + bytes(2) for o, n in names)
    tail = bytes(12 if lay.u64 else 8)
    # ReadStat checks this "remainder": the subheader length less 4 and
    # twice the signature size.
    cn += lay.int(w + 8 + len(entries) + len(tail) - 4 - 2 * w, 2) + bytes(6)
    cn += entries + tail
    subs.append(bytes(cn))
    # Column attributes.
    ca = bytearray(lay.sig(0xFFFFFFFC))
    vectors = len(COLUMNS) * (w + 8)
    ca += lay.int(w + 8 + vectors + (12 if lay.u64 else 8) - 4 - 2 * w, 2) + bytes(6)
    offset = 0
    for name, _, _, kind, width in COLUMNS:
        ca += lay.int(offset) + lay.int(width, 4) + lay.int(4, 2)
        ca += bytes([1 if kind == "d" else 2]) + bytes(1)
        offset += width
    ca += bytes(12 if lay.u64 else 8)
    subs.append(bytes(ca))
    # Format and label, one per column.
    for i, (name, _, fmt, kind, width) in enumerate(COLUMNS):
        size = 64 if lay.u64 else 52
        fl = bytearray(size)
        fl[0:w] = lay.sig(0xFFFFFBFE)
        fwidth, fdec = {"DATE": (9, 0), "DOLLAR": (12, 2), "BEST": (12, 0)}.get(fmt, (0, 0))
        fl[3 * w + 12 : 3 * w + 14] = lay.int(fwidth, 2)
        fl[3 * w + 14 : 3 * w + 16] = lay.int(fdec, 2)
        fo, fn = formats[i]
        lo, ln = labels[i]
        at = 3 * w + 22
        fl[at : at + 6] = lay.int(0, 2) + lay.int(fo, 2) + lay.int(fn, 2)
        fl[at + 6 : at + 12] = lay.int(0, 2) + lay.int(lo, 2) + lay.int(ln, 2)
        subs.append(bytes(fl))
    return subs


def file_header(lay, name, page_count):
    h = bytearray(HEADER)
    h[0:32] = MAGIC
    h[32] = 0x33 if lay.u64 else 0x22
    h[35] = 0x33 if lay.u64 else 0x22
    h[37] = 1 if lay.little else 0
    h[39] = ord("2")
    h[70] = 20  # UTF-8
    h[84:92] = b"SAS FILE"
    h[92:156] = name.ljust(64).encode()
    h[156:164] = b"DATA    "
    pad1 = 4 if lay.u64 else 0
    at = 164 + pad1
    stamp = 2_000_000_000.0  # 2023-05-19
    h[at : at + 8] = struct.pack(lay.e + "d", stamp)
    h[at + 8 : at + 16] = struct.pack(lay.e + "d", stamp + 3600)
    at += 32
    h[at : at + 4] = lay.int(HEADER, 4)
    h[at + 4 : at + 8] = lay.int(PAGE, 4)
    h[at + 8 : at + 8 + lay.w] = lay.int(page_count)
    at += 8 + lay.w + 8
    h[at : at + 8] = b"9.0401M7"
    h[at + 8 : at + 24] = b"X64_10PRO".ljust(16, b"\0")
    h[at + 24 : at + 40] = b"10.0.19045".ljust(16, b"\0")
    h[at + 40 : at + 56] = bytes(16)
    h[at + 56 : at + 72] = b"x86_64".ljust(16, b"\0")
    return bytes(h)


def page(lay, kind, subs, rows=(), block_count=None, compressed=False):
    """A page: header, subheader pointers, rows after the pointers, and
    subheader bodies packed from the end of the page."""
    p = bytearray(PAGE)
    n = len(subs)
    off = lay.page_header - 8
    p[off : off + 2] = lay.int(kind, 2)
    p[off + 2 : off + 4] = lay.int(block_count if block_count is not None else n + len(rows), 2)
    p[off + 4 : off + 6] = lay.int(n, 2)
    end = PAGE
    for i, (body, comp, typ) in enumerate(subs):
        end -= len(body)
        end -= end % 8
        p[end : end + len(body)] = body
        at = lay.page_header + i * lay.pointer
        p[at : at + lay.w] = lay.int(end)
        p[at + lay.w : at + 2 * lay.w] = lay.int(len(body))
        p[at + 2 * lay.w] = comp
        p[at + 2 * lay.w + 1] = typ
    at = lay.page_header + n * lay.pointer
    at += at % 8
    for r in rows:
        p[at : at + len(r)] = r
        at += len(r)
    assert at <= end, "page overflow"
    return bytes(p)


# --- compressors -------------------------------------------------------------

def rle(data):
    """SASYZCRL: runs of blanks, zeros and other bytes, literal copies."""
    out = bytearray()
    lit = bytearray()

    def flush():
        i = 0
        while i < len(lit):
            n = min(len(lit) - i, 64 + 255 + 15 * 256)
            if n >= 64:
                m = n - 64
                out.extend([0x00 | (m >> 8), m & 0xFF])
            elif n >= 49:
                out.append(0xB0 | (n - 49))
            elif n >= 33:
                out.append(0xA0 | (n - 33))
            elif n >= 17:
                out.append(0x90 | (n - 17))
            else:
                out.append(0x80 | (n - 1))
            out.extend(lit[i : i + n])
            i += n
        lit.clear()

    i = 0
    while i < len(data):
        b = data[i]
        j = i
        while j < len(data) and data[j] == b and j - i < 17 + 255 + 15 * 256:
            j += 1
        run = j - i
        if (run >= 3 and b in (0x20, 0x00)) or run >= 4:
            flush()
            if b in (0x20, 0x00):
                small = {0x20: 0xE0, 0x00: 0xF0}[b]
                big = {0x20: 0x60, 0x00: 0x70}[b]
                if run >= 17:
                    m = run - 17
                    out += bytes([big | (m >> 8), m & 0xFF])
                else:
                    out.append(small | (run - 2))
            else:
                if run >= 18:
                    m = run - 18
                    out += bytes([0x40 | (m >> 8), m & 0xFF, b])
                else:
                    run = min(run, 18)
                    out += bytes([0xC0 | (run - 3), b])
            i += run
        else:
            lit.append(b)
            i += 1
    flush()
    return bytes(out)


def rdc(data):
    """SASYZCR2 (Ross Data Compression): literals, short runs and short
    back-references, chosen greedily."""
    out = bytearray()
    items = []  # (is_command, bytes)
    i = 0
    while i < len(data):
        b = data[i]
        run = 1
        while i + run < len(data) and data[i + run] == b and run < 18:
            run += 1
        if run >= 3:
            items.append((True, bytes([0x00 | (run - 3), b])))
            i += run
            continue
        best = (0, 0)
        for ofs in range(3, min(i, 4098) + 1):
            n = 0
            # Matches never overlap their source: ReadStat copies with memcpy.
            while n < min(15, ofs) and i + n < len(data) and data[i + n - ofs] == data[i + n]:
                n += 1
            if n >= 3 and n > best[0]:
                best = (n, ofs)
        if best[0] >= 3:
            n, ofs = best
            o = ofs - 3
            items.append((True, bytes([(n << 4) | (o & 0x0F), o >> 4])))
            i += n
            continue
        items.append((False, bytes([b])))
        i += 1
    for k in range(0, len(items), 16):
        group = items[k : k + 16]
        bits = 0
        for j, (cmd, _) in enumerate(group):
            if cmd:
                bits |= 0x8000 >> j
        out += bits.to_bytes(2, "big")
        for _, body in group:
            out += body
    return bytes(out)


# --- files ----------------------------------------------------------------------

def uncompressed(path, lay):
    rows = [row_bytes(lay, r) for r in ROWS]
    length = len(rows[0])
    mix_rows = 2
    subs = [(s, 0, 0) for s in subheaders(lay, b"", length, len(rows), mix_rows)]
    p1 = page(lay, 0x0200, subs, rows[:mix_rows], block_count=len(subs) + mix_rows)
    p2 = page(lay, 0x0100, [], rows[mix_rows:], block_count=len(rows) - mix_rows)
    path.write_bytes(file_header(lay, "CARS", 2) + p1 + p2)


def compressed(path, lay, literal, codec):
    rows = [row_bytes(lay, r) for r in ROWS]
    length = len(rows[0])
    meta = [(s, 0, 0) for s in subheaders(lay, literal, length, len(rows), 0)]
    packed = [(codec(r), 4, 1) for r in rows]
    for body, _, _ in packed:
        assert len(body) < length, (len(body), length)
    p1 = page(lay, 0x0000, meta + packed[:2])
    p2 = page(lay, 0x0000, packed[2:])
    path.write_bytes(file_header(lay, "CARS", 2) + p1 + p2)


def check(path):
    import pandas as pd
    import pyreadstat

    df = pd.read_sas(path, format="sas7bdat", encoding="utf-8")
    rs, meta = pyreadstat.read_sas7bdat(str(path))
    assert list(df.columns) == [c[0] for c in COLUMNS], df.columns
    assert list(rs.columns) == [c[0] for c in COLUMNS], rs.columns
    assert meta.column_labels[:4] == [c[1] for c in COLUMNS][:4], meta.column_labels
    for i, row in enumerate(ROWS):
        for j, (name, _, fmt, kind, _) in enumerate(COLUMNS):
            want = row[j]
            got_pd = df.iloc[i, j]
            got_rs = rs.iloc[i, j]
            if kind == "s" and want == "":
                # pandas reads blank strings as missing.
                assert pd.isna(got_pd) and got_rs == want, (path, i, name, got_pd, got_rs)
            elif kind == "s":
                assert got_pd == want and got_rs == want, (path, i, name, got_pd, got_rs)
            elif math.isnan(want):
                assert pd.isna(got_pd) and pd.isna(got_rs), (path, i, name, got_pd, got_rs)
            elif fmt == "DATE":
                assert (got_pd - pd.Timestamp("1960-01-01")).days == want, (path, i, name, got_pd)
            else:
                assert got_pd == want and got_rs == want, (path, i, name, got_pd, got_rs)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    uncompressed(OUT / "cars.sas7bdat", Layout(u64=True, little=True))
    compressed(OUT / "rle.sas7bdat", Layout(u64=False, little=True), b"SASYZCRL", rle)
    compressed(OUT / "rdc.sas7bdat", Layout(u64=True, little=False), b"SASYZCR2", rdc)
    for name in ("cars", "rle", "rdc"):
        check(OUT / f"{name}.sas7bdat")
    print("ok")
