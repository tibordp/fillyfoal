"""Writes the synthetic DWG fixtures.

    python3 tests/data/dwg/make.py tests/fixtures/synthetic/dwg

No DWG writer was available (AutoCAD and the ODA File Converter are not
installed, and ezdxf's `odafc` add-on needs the latter), so these files are
built byte by byte from the Open Design Specification for .dwg files as
remembered: they show that the dissector agrees with this script, not that
either agrees with AutoCAD.

- `r2000.dwg` (AC1015): file header with section locators, header
  variables, classes, objects, object map, preview (header data and BMP).
- `r2004.dwg` (AC1018) and `r2018.dwg` (AC1032): encrypted file header,
  section page map, section map, compressed pages (the DWG LZ77 variant,
  encoded greedily below) for AcDb:Header, AcDb:Classes, AcDb:Handles and
  AcDb:AcDbObjects; stored AcDb:Preview (BMP / PNG), AcDb:SummaryInfo and
  AcDb:AppInfo. R2018 uses the R2007+ object coding: class strings in a
  string stream, UTF-16 strings, `OT` object types and handle stream sizes.
"""

import struct
import sys
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Bit codes


class Bits:
    def __init__(self):
        self.bits = []

    def b(self, v):
        self.bits.append(1 if v else 0)

    def n(self, v, count):
        for i in range(count - 1, -1, -1):
            self.bits.append((v >> i) & 1)

    def bb(self, v):
        self.n(v, 2)

    def rc(self, v):
        self.n(v & 0xFF, 8)

    def rs(self, v):
        self.rc(v)
        self.rc(v >> 8)

    def rl(self, v):
        self.rs(v & 0xFFFF)
        self.rs(v >> 16)

    def rd(self, v):
        for byte in struct.pack("<d", v):
            self.rc(byte)

    def bs(self, v):
        if v == 0:
            self.bb(2)
        elif v == 256:
            self.bb(3)
        elif v < 256:
            self.bb(1)
            self.rc(v)
        else:
            self.bb(0)
            self.rs(v)

    def bl(self, v):
        if v == 0:
            self.bb(2)
        elif v < 256:
            self.bb(1)
            self.rc(v)
        else:
            self.bb(0)
            self.rl(v)

    def bd(self, v):
        if v == 1.0:
            self.bb(1)
        elif v == 0.0:
            self.bb(2)
        else:
            self.bb(0)
            self.rd(v)

    def tv(self, s):
        data = s.encode("cp1252") + b"\0"
        self.bs(len(data))
        for c in data:
            self.rc(c)

    def tu(self, s):
        units = s.encode("utf-16-le") + b"\0\0"
        self.bs(len(units) // 2)
        for c in units:
            self.rc(c)

    def h(self, code, value):
        data = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
        self.n(code, 4)
        self.n(len(data), 4)
        for c in data:
            self.rc(c)

    def ot(self, t):
        if t < 256:
            self.bb(0)
            self.rc(t)
        elif 0x1F0 <= t < 0x1F0 + 256:
            self.bb(1)
            self.rc(t - 0x1F0)
        else:
            self.bb(2)
            self.rs(t)

    def extend(self, other):
        self.bits.extend(other.bits)

    def __len__(self):
        return len(self.bits)

    def bytes(self):
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            chunk = self.bits[i : i + 8]
            chunk += [0] * (8 - len(chunk))
            out.append(int("".join(map(str, chunk)), 2))
        return bytes(out)


def crc16(data, seed=0xC0C1):
    crc = seed
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def modular_char(v, signed=False):
    out = bytearray()
    if signed:
        neg = v < 0
        v = abs(v)
        while v >= 0x40:
            out.append(0x80 | (v & 0x7F))
            v >>= 7
        out.append(v | (0x40 if neg else 0))
    else:
        while v >= 0x80:
            out.append(0x80 | (v & 0x7F))
            v >>= 7
        out.append(v)
    return bytes(out)


def modular_short(v):
    out = bytearray()
    while v >= 0x8000:
        out += struct.pack("<H", 0x8000 | (v & 0x7FFF))
        v >>= 15
    out += struct.pack("<H", v)
    return bytes(out)


# ---------------------------------------------------------------------------
# The DWG LZ77 variant (greedy encoder; the inverse of src/codec/dwg.rs)


def literal_length(out, n):
    assert n >= 4
    if n <= 0x12:
        out.append(n - 3)
    else:
        out.append(0)
        r = n - 0x12
        while r > 0xFF:
            out.append(0)
            r -= 0xFF
        out.append(r)


def long_length(out, v):
    assert v >= 1
    if v <= 0xFF:
        out.append(v)
    else:
        out.append(0)
        r = v - 0xFF
        while r > 0xFF:
            out.append(0)
            r -= 0xFF
        out.append(r)


def opcode(length, offset):
    if 3 <= length <= 14 and offset <= 0x3FF:
        return bytearray([((length + 1) << 4) | ((offset & 3) << 2), offset >> 2]), 0
    if offset <= 0x3FF and length >= 3 or 0x3FF < offset <= 0x3FFF and length >= 3:
        if length <= 0x21:
            v = bytearray([length + 0x1E])
        else:
            v = bytearray([0x20])
            long_length(v, length - 0x21)
        o = offset
    elif 0x3FFF < offset <= 0x7FFE and length >= 4:
        if length <= 17:
            v = bytearray([0x10 | (length - 2)])
        else:
            v = bytearray([0x10])
            long_length(v, length - 9)
        o = offset - 0x3FFF
    else:
        return None
    at = len(v)
    v += bytes([(o & 0x3F) << 2, o >> 6])
    return v, at


def token(out, op, lits):
    if op is None:
        literal_length(out, len(lits))
    else:
        code, at = op
        k = len(lits)
        if 1 <= k <= 3:
            code[at] |= k
            out += code
        else:
            out += code
            if k:
                literal_length(out, k)
    out += lits


def compress(data):
    assert len(data) >= 4
    n = len(data)
    out = bytearray()
    chains = {}
    pending = None
    lit_start = 0
    pos = 0

    def index(at):
        if at + 3 <= n:
            chains.setdefault(data[at : at + 3], []).append(at)

    while pos < n:
        best = None
        if pos >= 4 and pos + 3 <= n:
            for cand in reversed(chains.get(data[pos : pos + 3], [])[-64:]):
                dist = pos - cand
                if dist > 0x7FFF:
                    break
                length = 0
                while pos + length < n and data[cand + length] == data[pos + length] and length < 0x300:
                    length += 1
                if opcode(length, dist - 1) and (best is None or length > best[0]):
                    best = (length, dist)
        if best is None:
            index(pos)
            pos += 1
            continue
        token(out, pending, data[lit_start:pos])
        pending = opcode(best[0], best[1] - 1)
        for at in range(pos, pos + best[0]):
            index(at)
        pos += best[0]
        lit_start = pos
    if pending is not None or lit_start < n:
        token(out, pending, data[lit_start:n])
    out.append(0x11)
    return bytes(out)


def page_checksum(seed, data):
    sum1 = seed & 0xFFFF
    sum2 = seed >> 16
    i = 0
    while i < len(data):
        chunk = data[i : i + 0x15B0]
        for b in chunk:
            sum1 += b
            sum2 += sum1
        sum1 %= 0xFFF1
        sum2 %= 0xFFF1
        i += 0x15B0
    return (sum2 << 16) | (sum1 & 0xFFFF)


def mask(length):
    seed = 1
    out = bytearray()
    for _ in range(length):
        seed = (seed * 0x343FD + 0x269EC3) & 0xFFFFFFFF
        out.append((seed >> 16) & 0xFF)
    return bytes(out)


# ---------------------------------------------------------------------------
# Content shared by the versions

SENTINEL_FILE = bytes.fromhex("95A04E2899821AE55E41E05F9D3A4D00")
SENTINEL_HEADER = bytes.fromhex("CF7B1F23FDDE38A95F7C68B84E6D335F")
SENTINEL_HEADER_END = bytes.fromhex("3084E0DC0221C756A0839747B192CCA0")
SENTINEL_CLASSES = bytes.fromhex("8DA1C4B8C4A9F8C5C0DCF45FE7CFB68A")
SENTINEL_CLASSES_END = bytes.fromhex("725E3B473B56073A3F230BA018304975")
SENTINEL_PREVIEW = bytes.fromhex("1F256D07D43628289D57CA3F9D44102B")
SENTINEL_PREVIEW_END = bytes.fromhex("E0DA92F82BC9D7D762A835C062BBEFD4")

CLASSES = [
    (500, 0, "ObjectDBX Classes", "AcDbDictionaryWithDefault", "ACDBDICTIONARYWDFLT", 0x1F3),
    (501, 0, "ObjectDBX Classes", "AcDbLayout", "LAYOUT", 0x1F3),
    (502, 0x481, "ObjectDBX Classes", "AcDbWipeout", "WIPEOUT", 0x1F2),
]

# (handle, type)
OBJECTS = [
    (0x01, 0x30),  # BLOCK_CONTROL
    (0x02, 0x32),  # LAYER_CONTROL
    (0x05, 0x38),  # LTYPE_CONTROL
    (0x10, 0x33),  # LAYER
    (0x11, 0x33),  # LAYER
    (0x1F, 0x13),  # LINE
    (0x20, 0x13),  # LINE
    (0x21, 0x12),  # CIRCLE
    (0x22, 0x11),  # ARC
    (0x30, 500),  # ACDBDICTIONARYWDFLT
    (0x31, 501),  # LAYOUT
    (0x200, 0x2A),  # DICTIONARY
]


def header_vars(ver):
    """Stand-in header variables: a bit-coded run that is not decoded."""
    b = Bits()
    for v in (412148.0, 0.0, 0.0, 0.0):
        b.bd(v)
    if ver >= "AC1021":
        b.tu("fillyfoal")
    else:
        b.tv("fillyfoal")
    b.bl(24)
    b.bl(0)
    b.bs(1)
    b.h(5, 0x1F)
    return b.bytes()


def sentinel_section(start, end, data, high):
    size = struct.pack("<I", len(data))
    if high:
        size += struct.pack("<I", 0)
    crc = crc16(size + data)
    return start + size + data + struct.pack("<H", crc) + end


def classes_section(ver, high):
    r2004 = ver >= "AC1018"
    r2007 = ver >= "AC1021"
    main = Bits()
    strings = Bits()
    if r2004:
        main.bs(max(c[0] for c in CLASSES))
        main.rc(0)
        main.rc(0)
        main.b(1)
    for number, proxy, app, cpp, dxf, item in CLASSES:
        main.bs(number)
        main.bs(proxy)
        for s in (app, cpp, dxf):
            (strings.tu if r2007 else main.tv)(s)
        main.b(0)
        main.bs(item)
        if r2004:
            main.bl(3 if item == 0x1F3 else 0)
            main.bl(31 if r2007 else 25)
            main.bl(0)
            main.bl(0)
            main.bl(0)
    if r2007:
        data = Bits()
        total = 32 + len(main) + len(strings) + 16 + 1
        data.rl(total)
        data.extend(main)
        data.extend(strings)
        data.rs(len(strings))
        data.b(1)
        assert len(data) == total
        body = data.bytes()
    else:
        body = main.bytes()
    return sentinel_section(SENTINEL_CLASSES, SENTINEL_CLASSES_END, body, high)


def object_bytes(ver, handle, kind):
    def build(size_in_bits):
        b = Bits()
        if ver >= "AC1024":
            b.ot(kind)
        else:
            b.bs(kind)
        if "AC1015" <= ver < "AC1024":
            # R2000 to R2007: the size in bits of the data before the handle
            # stream (all of it here: these objects refer to no handles).
            b.rl(size_in_bits)
        b.h(0, handle)
        b.bd(1.5 * handle)
        b.b(0)
        return b

    b = build(0)
    b = build(len(b))
    data = b.bytes()
    if ver >= "AC1024":
        data += b"\0"  # the handle stream: 8 bits
    head = modular_short(len(data))
    if ver >= "AC1024":
        head += modular_char(8)  # handle stream size in bits
    obj = head + data
    return obj + struct.pack("<H", crc16(obj))


def objects_blob(ver, base):
    """Objects concatenated from `base`; returns (bytes, [(handle, location)])."""
    blob = bytearray()
    locs = []
    for handle, kind in OBJECTS:
        locs.append((handle, base + len(blob)))
        blob += object_bytes(ver, handle, kind)
    return bytes(blob), locs


def object_map(locs, per_block=5):
    out = bytearray()
    for i in range(0, len(locs), per_block):
        body = bytearray()
        last_h, last_l = 0, 0
        for h, l in locs[i : i + per_block]:
            body += modular_char(h - last_h)
            body += modular_char(l - last_l, signed=True)
            last_h, last_l = h, l
        block = struct.pack(">H", len(body) + 2) + body
        out += block + struct.pack(">H", crc16(block))
    final = struct.pack(">H", 2)
    out += final + struct.pack(">H", crc16(final))
    return bytes(out)


def dib():
    """A 4x2 24-bit DIB (BITMAPINFOHEADER and rows, no file header)."""
    header = struct.pack("<IiiHHIIiiII", 40, 4, 2, 1, 24, 0, 24, 2835, 2835, 0, 0)
    rows = bytes([0, 0, 255] * 4) + bytes([255, 255, 255, 0, 128, 0] * 2)
    return header + rows


def png():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    raw = b"".join(b"\0" + bytes([200, 30, 30] * 4) for _ in range(2))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 2, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def preview(images, address):
    """The preview section at file offset `address` (its sentinel)."""
    count = len(images)
    data_start = 16 + 4 + 1 + 9 * count
    directory = bytearray()
    data = bytearray()
    for code, image in images:
        directory += struct.pack("<BII", code, address + data_start + len(data), len(image))
        data += image
    body = bytes([count]) + directory + data
    return SENTINEL_PREVIEW + struct.pack("<I", len(body)) + body + SENTINEL_PREVIEW_END


# ---------------------------------------------------------------------------
# R2000


def r2000():
    ver = "AC1015"
    head_len = 0x19 + 6 * 9 + 2 + 16
    sections = {}
    pos = head_len
    body = bytearray()

    def place(number, data):
        nonlocal pos
        sections[number] = (pos, len(data))
        body.extend(data)
        pos += len(data)

    place(0, sentinel_section(SENTINEL_HEADER, SENTINEL_HEADER_END, header_vars(ver), False))
    place(1, classes_section(ver, False))
    objects, locs = objects_blob(ver, pos)
    body.extend(objects)
    pos += len(objects)
    place(2, object_map(locs))
    place(3, struct.pack("<IIII", 0, 0, 0, 0))  # object free space (not decoded)
    place(4, struct.pack("<HH", 0, 0))  # template: MEASUREMENT and padding
    place(5, bytes.fromhex("FF7766554433") + bytes(20))  # second header (raw)
    preview_at = pos
    header_data = bytes(range(80))
    body.extend(preview([(1, header_data), (2, dib())], preview_at))
    head = bytearray(b"AC1015" + bytes(5) + bytes([0, 1]))
    head += struct.pack("<I", preview_at)
    head += bytes([0x1F, 0x08]) + struct.pack("<H", 30)
    head += struct.pack("<I", 6)
    for number in range(6):
        seeker, size = sections[number]
        head += struct.pack("<BII", number, seeker, size)
    head += struct.pack("<H", crc16(head) ^ 0x8461)
    head += SENTINEL_FILE
    assert len(head) == head_len
    return bytes(head + body)


# ---------------------------------------------------------------------------
# R2004 and later

PAGE_SIZE = 0x7400


def pad(data, align=0x20):
    return data + bytes(-len(data) % align)


def r2004(ver):
    r2007 = ver >= "AC1021"
    high = ver >= "AC1032"
    maint = 0 if ver == "AC1018" else 4
    pages = []  # (number, bytes) in file order, starting at 0x100
    address = 0x100
    descriptions = []
    preview_address = 0
    summary_address = 0

    def add_page(data):
        nonlocal address
        number = len(pages) + 1
        pages.append((number, data))
        at = address
        address += len(data)
        return number, at

    def string(s):
        if r2007:
            units = s.encode("utf-16-le") + b"\0\0"
            return struct.pack("<H", len(units) // 2) + units
        data = s.encode("cp1252") + b"\0"
        return struct.pack("<H", len(data)) + data

    def section(name, data, section_id, compressed):
        nonlocal preview_address, summary_address
        page_entries = []
        for start in range(0, max(len(data), 1), PAGE_SIZE):
            chunk = data[start : start + PAGE_SIZE]
            packed = compress(chunk) if compressed else chunk
            number = len(pages) + 1
            at = address
            data_checksum = page_checksum(0, packed)
            fields = [0x4163043B, section_id, len(packed), len(chunk), start, 0, data_checksum, 0]
            header = struct.pack("<8I", *fields)
            fields[5] = page_checksum(data_checksum, header)
            header = struct.pack("<8I", *fields)
            key = 0x4164536B ^ at
            header = struct.pack("<8I", *(f ^ key for f in fields))
            add_page(pad(header + packed))
            page_entries.append((number, len(packed), start))
            if name == "AcDb:Preview":
                preview_address = at + 32
            if name == "AcDb:SummaryInfo":
                summary_address = at + 32
        descriptions.append((name, len(data), section_id, compressed, page_entries))

    objects_data, locs = objects_blob(ver, 4)
    objects_data = struct.pack("<I", 0x0DCA) + objects_data
    section("AcDb:Header", sentinel_section(SENTINEL_HEADER, SENTINEL_HEADER_END, header_vars(ver), high), 1, True)
    section("AcDb:Classes", classes_section(ver, high), 2, True)
    section("AcDb:Handles", object_map(locs), 3, True)
    section("AcDb:AcDbObjects", objects_data, 4, True)
    # The preview's addresses are file offsets: the page goes next, its
    # data 32 bytes after the page address.
    image = (6, png()) if r2007 else (2, dib())
    section("AcDb:Preview", preview([(1, bytes(range(80))), image], address + 32), 5, False)
    summary = b"".join(
        string(s)
        for s in ("Floor plan", "fillyfoal fixture", "Tibor", "dwg; test", "synthetic", "Tibor", "3", "")
    )
    summary += struct.pack("<II", 0, 3_600_000)  # editing time: 1 hour
    summary += struct.pack("<II", 2460000, 43_200_000)  # created
    summary += struct.pack("<II", 2460001, 0)  # modified
    summary += struct.pack("<H", 1) + string("Project") + string("Filly")
    summary += struct.pack("<II", 0, 0)
    section("AcDb:SummaryInfo", summary, 6, False)
    product = '<ProductInformation name ="fillyfoal" build_version="0.1" registry_version="24.1" install_id_string="ACAD-1" registry_localeID="1033"/>'
    if r2007:
        appinfo = struct.pack("<I", 2) + string("AppInfoDataList") + struct.pack("<I", 3)
        for s in ("4001", "fixture", product):
            appinfo += bytes(16) + string(s)
    else:
        appinfo = struct.pack("<I", 2) + string("AppInfoDataList") + struct.pack("<I", 3)
        for s in ("4001", "fixture", product):
            appinfo += string(s)
    section("AcDb:AppInfo", appinfo, 7, False)

    # The section map, then the page map, as system pages.
    sm = struct.pack("<5I", len(descriptions) + 1, 2, PAGE_SIZE, 0, len(descriptions) + 1)
    sm += struct.pack("<QIIIIII", 0, 0, PAGE_SIZE, 1, 1, 0, 0) + bytes(64)
    for name, size, section_id, compressed, entries in descriptions:
        sm += struct.pack("<QIIIIII", size, len(entries), PAGE_SIZE, 1, 2 if compressed else 1, section_id, 0)
        sm += name.encode().ljust(64, b"\0")
        for number, data_size, start in entries:
            sm += struct.pack("<IIQ", number, data_size, start)

    def system_page(kind, data):
        packed = compress(data)
        header = struct.pack("<5I", kind, len(data), len(packed), 2, 0)
        checksum = page_checksum(page_checksum(0, header), packed)
        header = struct.pack("<5I", kind, len(data), len(packed), 2, checksum)
        return pad(header + packed)

    section_map_id, _ = add_page(system_page(0x4163003B, sm))
    page_map_id = len(pages) + 1
    page_map_address = address
    # The page map lists every page including itself; its size depends on
    # the entries, not on its own compressed size... which it lists. Iterate.
    own_size = 0x20
    for _ in range(10):
        entries = b"".join(struct.pack("<iI", number, len(data)) for number, data in pages)
        entries += struct.pack("<iI", page_map_id, own_size)
        page = system_page(0x41630E3B, entries)
        if len(page) == own_size:
            break
        own_size = len(page)
    pages.append((page_map_id, page))
    end = page_map_address + len(page)

    header = bytearray(b"AcFssFcAJMB\0")
    header += struct.pack("<III", 0, 0x6C, 4)
    header += struct.pack("<IIII", 0, 0, 0, 1)
    header += struct.pack("<IQQ", page_map_id, end, end)
    header += struct.pack("<II", 0, len(pages))
    header += struct.pack("<III", 0x20, 0x80, 0x40)
    header += struct.pack("<IQ", page_map_id, page_map_address - 0x100)
    header += struct.pack("<III", section_map_id, len(pages), 0)
    header += struct.pack("<I", 0)
    assert len(header) == 0x6C
    header[0x68:0x6C] = struct.pack("<I", zlib.crc32(bytes(header)))
    encrypted = bytes(a ^ b for a, b in zip(header, mask(0x6C)))

    head = bytearray(ver.encode() + bytes(5) + bytes([maint, 3]))
    head += struct.pack("<I", preview_address)
    head += bytes([33 if r2007 else 25, 0]) + struct.pack("<H", 30)
    head += bytes(3)
    head += struct.pack("<IIIII", 0, 0, summary_address, 0, 0x80)
    head += bytes(0x80 - len(head))
    head += encrypted
    head += mask(0x80)[0x6C:]
    head += bytes(0x100 - len(head))
    assert len(head) == 0x100
    return bytes(head) + b"".join(data for _, data in pages)


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "r2000.dwg").write_bytes(r2000())
    (out / "r2004.dwg").write_bytes(r2004("AC1018"))
    (out / "r2018.dwg").write_bytes(r2004("AC1032"))


if __name__ == "__main__":
    main(sys.argv[1])
