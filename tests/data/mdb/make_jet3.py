"""Writes tests/fixtures/synthetic/mdb/jet3.mdb: a small Jet 3 (Access 97)
database laid out from mdbtools' HACKING notes, since no tool we can run
writes Jet 3 (Jackcess only reads it).

    python3 tests/data/mdb/make_jet3.py OUT

2 KiB pages: 0 header (RC4-obfuscated part), 1 usage maps, 2 MSysObjects'
definition, 3 its rows, 4 the definition of table Parts (with a primary
key), 5 Parts' rows (one longer than 256 bytes, so its variable offsets
need the jump table, and one deleted), 6 a long-value page holding a memo
stored outside its row.
"""
import struct
import sys

PAGE = 2048


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def header():
    p = bytearray(PAGE)
    p[0:4] = b"\x00\x01\x00\x00"
    p[4:20] = b"Standard Jet DB\x00"
    struct.pack_into("<I", p, 0x14, 0)  # Jet 3
    plain = bytearray(126)
    struct.pack_into("<H", plain, 0x3A - 0x18, 1252)
    struct.pack_into("<H", plain, 0x56 - 0x18, 0x409)
    p[0x18:0x18 + 126] = rc4(bytes([0xC7, 0xDA, 0x39, 0x6B]), bytes(plain))
    return p


def data_page(owner, rows, flags=None):
    """A data page with `rows` stored from the end downwards."""
    p = bytearray(PAGE)
    p[0] = 1
    p[1] = 1
    struct.pack_into("<I", p, 4, owner)
    struct.pack_into("<H", p, 8, len(rows))
    end = PAGE
    for i, r in enumerate(rows):
        start = end - len(r)
        p[start:end] = r
        word = start | ((flags or {}).get(i, 0))
        struct.pack_into("<H", p, 10 + 2 * i, word)
        end = start
    struct.pack_into("<H", p, 2, end - (10 + 2 * len(rows)))
    return p


def ptr(page, row):
    return (page << 8) | row


class Col:
    def __init__(self, name, kind, num, var=0, fixed=0, size=0, flags=0x03):
        self.name, self.kind, self.num = name, kind, num
        self.var, self.fixed, self.size, self.flags = var, fixed, size, flags


def tdef(cols, nrows, used, nvar, pk=None, kind=0x4E):
    """A Jet 3 table definition; `pk` is the column number of a primary key."""
    b = bytearray(43)
    b[0] = 2
    b[1] = 1
    b[2:4] = b"VC"
    struct.pack_into("<I", b, 12, nrows)
    struct.pack_into("<I", b, 16, nrows + 1)
    b[20] = kind
    struct.pack_into("<HHH", b, 21, len(cols), nvar, len(cols))
    nidx = 1 if pk is not None else 0
    struct.pack_into("<II", b, 27, nidx, nidx)
    struct.pack_into("<II", b, 35, used, 0)
    for _ in range(nidx):
        b += struct.pack("<II", 0, nrows)
    for c in cols:
        e = bytearray(18)
        e[0] = c.kind
        struct.pack_into("<HHH", e, 1, c.num, c.var, c.num)
        struct.pack_into("<H", e, 7, 0x409)
        if c.kind in (0x0A, 0x0C):
            struct.pack_into("<H", e, 9, 1252)
        e[13] = c.flags
        struct.pack_into("<HH", e, 14, c.fixed, c.size)
        b += e
    for c in cols:
        n = c.name.encode("cp1252")
        b += bytes([len(n)]) + n
    if pk is not None:
        blk = bytearray()
        blk += struct.pack("<HB", pk, 1)
        for _ in range(9):
            blk += struct.pack("<HB", 0xFFFF, 0)
        blk += struct.pack("<IIB", 0, 0, 0x09)
        b += blk
        b += struct.pack("<IIBiIBBB", 0, 0, 0, -1, 0, 0, 0, 1)
        b += bytes([10]) + b"PrimaryKey"
    struct.pack_into("<I", b, 8, len(b))
    return b + bytes(PAGE - len(b))


def row(cols, ncols, fixed_len, values, var_values):
    """A Jet 3 row: values maps column number to fixed bytes (None: null;
    True/False for Booleans), var_values lists the variable columns' bytes
    (None: null) in variable-index order."""
    data = bytearray([ncols])
    data += bytes(fixed_len)
    mask = bytearray((ncols + 7) // 8)
    for c in cols:
        v = values.get(c.num)
        if c.kind == 1:
            if v:
                mask[c.num // 8] |= 1 << (c.num % 8)
        elif c.flags & 1 and v is not None:
            data[1 + c.fixed:1 + c.fixed + c.size] = v
            mask[c.num // 8] |= 1 << (c.num % 8)
    offsets = []
    for c in sorted((c for c in cols if not c.flags & 1), key=lambda c: c.var):
        v = var_values[c.var]
        offsets.append(len(data))
        if v is not None:
            data += v
            mask[c.num // 8] |= 1 << (c.num % 8)
    offsets.append(len(data))
    nvar = len(offsets) - 1
    # The trailer: offsets (one byte each, reversed), jump table, count,
    # null mask. The jump count depends on the row length; iterate.
    jumps = 0
    while True:
        total = len(data) + len(offsets) + jumps + 1 + len(mask)
        want = (total - 1) // 256
        if want == jumps:
            break
        jumps = want
    jt = []
    for j in range(jumps):
        first = next((i for i, o in enumerate(offsets) if o >= 256 * (j + 1)), 0xFF)
        jt.append(first)
    trailer = bytes(o & 0xFF for o in reversed(offsets)) + bytes(reversed(jt))
    return bytes(data) + trailer + bytes([nvar]) + bytes(mask)


def text(s):
    return s.encode("cp1252")


def memo_inline(s):
    b = text(s)
    return struct.pack("<III", len(b) | 0x80000000, 0, 0) + b


def main(out):
    # MSysObjects: Id, ParentId, Name, Type, Flags.
    so = [
        Col("Id", 0x04, 0, fixed=0, size=4),
        Col("ParentId", 0x04, 1, fixed=4, size=4),
        Col("Name", 0x0A, 2, var=0, size=128, flags=0x02),
        Col("Type", 0x03, 3, fixed=8, size=2),
        Col("Flags", 0x04, 4, fixed=10, size=4),
    ]

    def obj(id_, parent, name, kind, flags):
        vals = {
            0: struct.pack("<i", id_),
            1: struct.pack("<i", parent),
            3: struct.pack("<h", kind),
            4: struct.pack("<i", flags),
        }
        return row(so, 5, 14, vals, [text(name)])

    objs = [
        obj(0x0F000001, 0x0F000000, "Tables", 3, 0),
        obj(2, 0x0F000001, "MSysObjects", 1, -0x80000000),
        obj(4, 0x0F000001, "Parts", 1, 0),
        obj(5, 0x0F000000, "Overview", -32768, 0),
    ]
    parts = [
        Col("ID", 0x04, 0, fixed=0, size=4, flags=0x07),
        Col("Note", 0x0C, 1, var=0, flags=0x02),
        Col("Name", 0x0A, 2, var=1, size=40, flags=0x02),
        Col("Qty", 0x03, 3, fixed=4, size=2),
        Col("InStock", 0x01, 4, fixed=6, size=0),
        Col("Price", 0x05, 5, fixed=6, size=8),
        Col("Added", 0x08, 6, fixed=14, size=8),
    ]

    def part(id_, name, qty, stock, price, days, note):
        vals = {
            0: struct.pack("<i", id_),
            3: struct.pack("<h", qty),
            4: stock,
            5: struct.pack("<q", price),
            6: struct.pack("<d", days),
        }
        return row(parts, 7, 22, vals, [note, text(name) if name else None])

    long_note = text("an off-row memo, " * 8)
    rows = [
        part(1, "bolt", -3, True, 123400, 36925.25, memo_inline("note bolt")),
        part(2, "nut", 4, False, 133400, 36926.5, None),
        part(3, "washer", 11, True, 143400, 36927.0, memo_inline("long note " * 30)),
        part(4, "gone", 0, False, 0, 0.0, None),
        part(5, None, 7, True, -50000, 36928.75,
             struct.pack("<III", len(long_note) | 0x40000000, ptr(6, 0), 0)),
    ]
    pages = [
        header(),
        data_page(0, [
            b"\x00" + struct.pack("<I", 0) + bytes([1 << 3]),
            b"\x00" + struct.pack("<I", 0) + bytes([1 << 5]),
        ]),
        tdef(so, len(objs), ptr(1, 0), 1, kind=0x53),
        data_page(2, objs),
        tdef(parts, 4, ptr(1, 1), 2, pk=0),
        data_page(4, rows, {3: 0x8000}),
        data_page(0x4C41564C, [long_note]),
    ]
    with open(out, "wb") as f:
        for p in pages:
            assert len(p) == PAGE
            f.write(p)


if __name__ == "__main__":
    main(sys.argv[1])
