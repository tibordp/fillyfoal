"""Writes the synthetic PST fixtures (our own reading of [MS-PST]).

    python3 tests/data/pst/synthetic.py tests/fixtures

- `synthetic/pst/ansi.pst`: a small ANSI (32-bit) PST written from
  scratch: message store, root folder, an Inbox with one message (plain
  text body, a recipient, a text attachment), no obfuscation.
- `synthetic/pst/ansi-cyclic.pst`: the same with its data blocks
  encoded with the cyclic cipher (NDB_CRYPT_CYCLIC).

The blocks start right after the header instead of after the first
allocation map page (which these files do not have).

Neither shows conformance: they share this project's understanding of the
format (the cyclic tables in particular are written from memory).
"""

import os
import struct
import sys

# --------------------------------------------------------------------------
# CRC and obfuscation tables

def crc32(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
    return c


MPBB_I = bytes.fromhex(
    "47f1b4e60b6a7248854e9eebe2f89453"
    "e0bba002e85a09abdbe3bac67cc310dd"
    "39059630f53760828cc9134a6b1df3fb"
    "8f2697ca911701c4322d6e3195ffd923"
    "d1005e79dc443b1a28c5615720903d83"
    "b943be67d2464276c06d5b7eb20f1629"
    "3ca903540dda5ddff6b7c762cd8d06d3"
    "695c86d614f7a56675acb1e94521700c"
    "879f74a4224c6fbf1f56aa2eb3783350"
    "b0a392bccf191ca763cb1e4d3e4b1b9b"
    "4fe7f0eead3ab55904ea40552551e57a"
    "893868527bfc27aed7bdfa07f4cc8e5f"
    "ef359c842b15d5773449b6120a7f7188"
    "fd9d18417d93d8582ccefe24afdeb836"
    "c8a180a69998a82f0e816573e4c2a28a"
    "d4e111d0088b2af2ed9a643fc16cf9ec"
)
MPBB_S = bytes.fromhex(
    "14530f56b3c87a9ceb65481716159f02"
    "cc547c83000d0c0ba262a876dbd9edc7"
    "c5a4dcac8574d6d0a79bae9a967166c3"
    "6399b8dd73928e847da55ed15d93b157"
    "5150808952944f4e0a6bbc8d7f6e4746"
    "4140440111cb033ff7f4e1a98f3c3af9"
    "fbf0193082092ec99da08649ee6f4d6d"
    "c42d813425871b88aafc06a11238fd4c"
    "4272641337246a757743ffe6b44b365c"
    "e4d8353d45b92cecb7312b290768a30e"
    "697b189e2139be281a5b78f523ca2ab0"
    "af3efe048ce7e5983295d3f64ae8a6ea"
    "e9f3d52f7020f21f0567ad5510cecde3"
    "273bdabad7c226d4911dd21c2233f8fa"
    "f15aefcf90b68bb5bdc0bf08971e6ce2"
    "61e0c6c159abbb58de5fdf60797eb28a"
)
assert len(MPBB_I) == 256 and len(MPBB_S) == 256
MPBB_R = bytes(MPBB_I.index(i) for i in range(256))


def cyclic(data, key):
    w = (key ^ (key >> 16)) & 0xFFFF
    out = bytearray()
    for b in data:
        lo, hi = w & 0xFF, w >> 8
        b = (b + lo) & 0xFF
        b = MPBB_R[b]
        b = (b + hi) & 0xFF
        b = MPBB_S[b]
        b = (b - hi) & 0xFF
        b = MPBB_I[b]
        b = (b - lo) & 0xFF
        out.append(b)
        w = (w + 1) & 0xFFFF
    return bytes(out)


def signature(ib, bid):
    x = (ib ^ bid) & 0xFFFFFFFF
    return ((x >> 16) ^ x) & 0xFFFF


# --------------------------------------------------------------------------
# ANSI writer

PT_SHORT, PT_LONG, PT_BOOLEAN, PT_STRING8, PT_SYSTIME, PT_BINARY = (
    0x0002, 0x0003, 0x000B, 0x001E, 0x0040, 0x0102)
FIXED = {PT_SHORT: 2, PT_LONG: 4, PT_BOOLEAN: 1, PT_SYSTIME: 8}


def filetime(y, mo, d, h, mi):
    import datetime
    t = datetime.datetime(y, mo, d, h, mi, tzinfo=datetime.timezone.utc)
    return int(t.timestamp()) * 10_000_000 + 116444736000000000


def s8(text):
    return text.encode("cp1252")


class Heap:
    """A single-block heap-on-node."""

    def __init__(self, client):
        self.client = client
        self.items = []

    def alloc(self, data):
        self.items.append(bytes(data))
        return len(self.items) << 5  # HID: index in bits 5-15, block 0

    def build(self, root):
        body = bytearray(12)
        bounds = [12]
        for item in self.items:
            body += item
            bounds.append(len(body))
        if len(body) % 2:
            body.append(0)
        pm = len(body)
        body += struct.pack("<HH", len(self.items), 0)
        body += b"".join(struct.pack("<H", b) for b in bounds)
        struct.pack_into("<HBBI", body, 0, pm, 0xEC, self.client, root)
        assert len(body) <= 8180
        return bytes(body)


def bth(heap, key_size, ent_size, records):
    leaf = heap.alloc(b"".join(records)) if records else 0
    return heap.alloc(struct.pack("<BBBBI", 0xB5, key_size, ent_size, 0, leaf))


def pc(props):
    """props: list of (id, type, value bytes)."""
    heap = Heap(0xBC)
    records = []
    for pid, ptype, value in sorted(props):
        if ptype in FIXED and FIXED[ptype] <= 4:
            raw = value.ljust(4, b"\0")
        else:
            raw = struct.pack("<I", heap.alloc(value) if value else 0)
        records.append(struct.pack("<HH", pid, ptype) + raw)
    root = bth(heap, 2, 6, records)
    return heap.build(root)


def tc(columns, rows, rows_nid=0):
    """columns: list of (id, type); rows: list of dicts id -> bytes.
    The row ID (0x67F2) and version (0x67F3) columns are added. With
    `rows_nid`, the row matrix goes to that subnode: returns (heap, rows)."""
    heap = Heap(0x7C)
    cols = [(0x67F2, PT_LONG), (0x67F3, PT_LONG)] + columns

    def width(t):
        return FIXED.get(t, 4)

    order = sorted(range(len(cols)), key=lambda i: (-min(width(cols[i][1]), 4), i))
    offsets, at = {}, 0
    groups = []
    for size_class in (4, 2, 1):
        for i in order:
            if min(width(cols[i][1]), 4) == size_class:
                offsets[i] = at
                at += width(cols[i][1])
        groups.append(at)
    ceb = at
    row_size = ceb + (len(cols) + 7) // 8
    groups.append(row_size)
    matrix = bytearray()
    index = []
    for r, row in enumerate(rows):
        data = bytearray(row_size)
        for i, (pid, ptype) in enumerate(cols):
            if pid not in row:
                continue
            value = row[pid]
            if ptype in FIXED:
                raw = value
            else:
                raw = struct.pack("<I", heap.alloc(value) if value else 0)
            data[offsets[i]:offsets[i] + len(raw)] = raw
            data[ceb + i // 8] |= 0x80 >> (i % 8)
        matrix += data
        index.append(struct.pack("<IH", struct.unpack_from("<I", row[0x67F2])[0], r))
    row_index = bth(heap, 4, 2, sorted(index))
    if rows_nid:
        rows_hid = rows_nid
    else:
        rows_hid = heap.alloc(matrix) if rows else 0
    info = struct.pack("<BB4HIII", 0x7C, len(cols), *groups, row_index, rows_hid, 0)
    for i, (pid, ptype) in enumerate(cols):
        info += struct.pack("<IHBB", (pid << 16) | ptype, offsets[i], width(ptype), i)
    root = heap.alloc(info)
    if rows_nid:
        return heap.build(root), bytes(matrix)
    return heap.build(root)


def u32(v):
    return struct.pack("<I", v)


def make_ansi(crypt):
    blocks = {}  # bid -> data
    next_bid = [4]

    def block(data, internal=False):
        bid = next_bid[0] | (2 if internal else 0)
        next_bid[0] += 4
        blocks[bid] = data
        return bid

    nodes = []  # (nid, bid_data, bid_sub, parent)
    delivered = struct.pack("<Q", filetime(2024, 3, 4, 9, 30))

    nodes.append((0x21, block(pc([
        (0x3001, PT_STRING8, s8("ANSI folders")),
        (0x0FF9, PT_BINARY, bytes(range(16))),
        (0x67FF, PT_LONG, u32(0)),
    ])), 0, 0))
    nodes.append((0x122, block(pc([
        (0x3001, PT_STRING8, b""),
        (0x3602, PT_LONG, u32(0)),
        (0x3603, PT_LONG, u32(0)),
        (0x360A, PT_BOOLEAN, b"\x01"),
    ])), 0, 0x122))
    folder_cols = [(0x3001, PT_STRING8), (0x3602, PT_LONG), (0x3603, PT_LONG),
                   (0x360A, PT_BOOLEAN)]
    nodes.append((0x12D, block(tc(folder_cols, [{
        0x67F2: u32(0x8022), 0x67F3: u32(1), 0x3001: s8("Inbox"),
        0x3602: u32(1), 0x3603: u32(1), 0x360A: b"\x00",
    }])), 0, 0))
    content_cols = [(0x0037, PT_STRING8), (0x0042, PT_STRING8),
                    (0x0E06, PT_SYSTIME), (0x0E07, PT_LONG), (0x0E08, PT_LONG)]
    nodes.append((0x12E, block(tc(content_cols, [])), 0, 0))
    nodes.append((0x8022, block(pc([
        (0x3001, PT_STRING8, s8("Inbox")),
        (0x3602, PT_LONG, u32(1)),
        (0x3603, PT_LONG, u32(1)),
        (0x360A, PT_BOOLEAN, b"\x00"),
        (0x3613, PT_STRING8, s8("IPF.Note")),
    ])), 0, 0x122))
    nodes.append((0x802D, block(tc(folder_cols, [])), 0, 0))
    subject = s8("Grüße from an ANSI file")
    # The Inbox's contents table keeps its rows in a subnode (as large
    # tables do).
    table, matrix = tc(content_cols, [{
        0x67F2: u32(0x200024), 0x67F3: u32(1), 0x0037: subject,
        0x0042: s8("Alice"), 0x0E06: delivered, 0x0E07: u32(0x11),
        0x0E08: u32(600),
    }], rows_nid=0x3F)
    rows_sub = block(struct.pack("<BBH", 2, 0, 1) + struct.pack("<III", 0x3F, block(matrix), 0),
                     internal=True)
    nodes.append((0x802E, block(table), rows_sub, 0))

    # The message, with its recipient table, attachment table and
    # attachment in subnodes.
    recipients = block(tc([(0x3001, PT_STRING8), (0x3003, PT_STRING8),
                           (0x0C15, PT_LONG)], [{
        0x67F2: u32(0), 0x67F3: u32(1), 0x3001: s8("Bob"),
        0x3003: s8("bob@example.com"), 0x0C15: u32(1),
    }]))
    attach_name = s8("hello.txt")
    attach_data = b"Hello from an ANSI PST.\r\n"
    attachments = block(tc([(0x3707, PT_STRING8), (0x0E20, PT_LONG),
                            (0x3705, PT_LONG)], [{
        0x67F2: u32(0x8025), 0x67F3: u32(1), 0x3707: attach_name,
        0x0E20: u32(len(attach_data)), 0x3705: u32(1),
    }]))
    attachment = block(pc([
        (0x3705, PT_LONG, u32(1)),
        (0x3707, PT_STRING8, attach_name),
        (0x3701, PT_BINARY, attach_data),
        (0x0E20, PT_LONG, u32(len(attach_data))),
    ]))
    sl = struct.pack("<BBH", 2, 0, 3) + b"".join(
        struct.pack("<III", nid, bid, 0)
        for nid, bid in ((0x671, attachments), (0x692, recipients), (0x8025, attachment)))
    sub = block(sl, internal=True)
    nodes.append((0x200024, block(pc([
        (0x001A, PT_STRING8, s8("IPM.Note")),
        (0x0037, PT_STRING8, subject),
        (0x0042, PT_STRING8, s8("Alice")),
        (0x0065, PT_STRING8, s8("alice@example.com")),
        (0x0E04, PT_STRING8, s8("Bob")),
        (0x0E06, PT_SYSTIME, delivered),
        (0x0E07, PT_LONG, u32(0x11)),
        (0x0E08, PT_LONG, u32(600)),
        (0x1000, PT_STRING8, s8("Hi Bob,\r\nthis message lives in an ANSI PST.\r\n")),
    ])), sub, 0x8022))

    # Lay out: header, then blocks, then the two B-tree pages.
    out = bytearray(0x200)
    bbt = []
    for bid, data in sorted(blocks.items()):
        ib = len(out)
        if crypt == 2 and not bid & 2:
            data = cyclic(data, bid)
        size = (len(data) + 12 + 63) & ~63
        chunk = bytearray(size)
        chunk[:len(data)] = data
        struct.pack_into("<HHII", chunk, size - 12, len(data), signature(ib, bid), bid,
                         crc32(data))
        out += chunk
        bbt.append(struct.pack("<IIHH", bid, ib, len(data), 2))

    def page(entries, ptype, cb_ent, bid):
        ib = len(out)
        p = bytearray(512)
        p[:len(entries) * cb_ent] = b"".join(entries)
        p[496:500] = bytes([len(entries), 496 // cb_ent, cb_ent, 0])
        struct.pack_into("<BBHI", p, 500, ptype, ptype, signature(ib, bid), bid)
        struct.pack_into("<I", p, 508, crc32(p[:500]))
        out.extend(p)
        return bid, ib

    nbt = [struct.pack("<IIII", nid, data, sub, parent)
           for nid, data, sub, parent in sorted(nodes)]
    nbt_ref = page(nbt, 0x81, 16, 0x101)
    bbt_ref = page(bbt, 0x80, 12, 0x105)

    h = bytearray(512)
    h[0:4] = b"!BDN"
    struct.pack_into("<2sHHBB", h, 8, b"SM", 14, 19, 1, 1)
    struct.pack_into("<III", h, 24, next_bid[0], 0x109, 1)
    for i in range(32):
        struct.pack_into("<I", h, 36 + 4 * i, 0x400)
    struct.pack_into("<IIIIIIIIIBBH", h, 164, 0, len(out), 0, 0, 0,
                     nbt_ref[0], nbt_ref[1], bbt_ref[0], bbt_ref[1], 2, 0, 0)
    h[204:460] = b"\xff" * 256
    h[460] = 0x80
    h[461] = crypt
    struct.pack_into("<I", h, 4, crc32(h[8:8 + 471]))
    out[:512] = h
    return bytes(out)


def main():
    root = sys.argv[1]
    os.makedirs(os.path.join(root, "synthetic", "pst"), exist_ok=True)
    for name, crypt in (("ansi.pst", 0), ("ansi-cyclic.pst", 2)):
        with open(os.path.join(root, "synthetic", "pst", name), "wb") as f:
            f.write(make_ansi(crypt))


main()
