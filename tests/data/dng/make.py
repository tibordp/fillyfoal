"""Writes a synthetic little-endian DNG from our reading of the DNG 1.7 and
TIFF/EP specifications: IFD0 is a 4x4 RGB preview with the DNG colour tags,
an Exif IFD, IPTC records and an XMP packet; its SubIFD is the 4x4 16-bit
Bayer raw image with CFA, black/white level, crop and an OpcodeList2
(FixBadPixelsConstant and GainMap). All values are made up.

    python3 tests/data/dng/make.py tests/fixtures/synthetic/dng/colour.dng
"""

import os
import struct
import sys

TYPES = {
    "B": (1, 1),
    "A": (2, 1),
    "H": (3, 2),
    "L": (4, 4),
    "R": (5, 8),
    "U": (7, 1),
    "r": (10, 8),
}
E = "<"


def encode(kind, values):
    code, _ = TYPES[kind]
    if kind in "ABU":
        return code, len(values), bytes(values)
    if kind in "Rr":
        fmt = "L" if kind == "R" else "l"
        return code, len(values), b"".join(struct.pack(E + fmt + fmt, n, d) for n, d in values)
    return code, len(values), b"".join(struct.pack(E + kind, v) for v in values)


def ifd(at, entries, next_ifd=0):
    entries = sorted(entries, key=lambda x: x[0])
    data_at = at + 2 + 12 * len(entries) + 4
    body, data = b"", b""
    for tag, kind, values in entries:
        code, count, raw = encode(kind, values)
        if len(raw) <= 4:
            field = raw.ljust(4, b"\0")
        else:
            field = struct.pack(E + "L", data_at + len(data))
            data += raw + (b"\0" if len(raw) % 2 else b"")
        body += struct.pack(E + "HHL", tag, code, count) + field
    return struct.pack(E + "H", len(entries)) + body + struct.pack(E + "L", next_ifd) + data


def opcode(op, version, flags, params):
    return struct.pack(">LLLL", op, version, flags, len(params)) + params


def opcode_list():
    bad_pixels = opcode(4, 0x01030000, 1, struct.pack(">LL", 0, 1))
    area = struct.pack(">8L", 0, 0, 4, 4, 0, 1, 1, 1)
    gain = struct.pack(">LLddddL", 2, 2, 1.0, 1.0, 0.0, 0.0, 1) + struct.pack(">4f", 1.0, 1.02, 1.01, 1.03)
    gain_map = opcode(9, 0x01030000, 0, area + gain)
    return struct.pack(">L", 2) + bad_pixels + gain_map


def iptc():
    def ds(record, dataset, value):
        return struct.pack(">BBBH", 0x1C, record, dataset, len(value)) + value

    return (
        ds(1, 90, b"\x1b%G")
        + ds(2, 0, b"\x00\x04")
        + ds(2, 5, b"Fixture DNG")
        + ds(2, 25, b"test")
        + ds(2, 25, b"filly")
        + ds(2, 55, b"20240501")
        + ds(2, 80, b"A. Photographer")
        + ds(2, 116, "© 2024 A. Photographer".encode())
    )


HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "../../fixtures/synthetic/xmp/photo.xmp"), "rb") as f:
    XMP = f.read()

matrix = [(6722, 10000), (-635, 10000), (-963, 10000), (-4287, 10000), (12460, 10000),
          (2028, 10000), (-908, 10000), (2162, 10000), (5668, 10000)]
forward = [(7978, 10000), (1352, 10000), (313, 10000), (2880, 10000), (7105, 10000),
           (15, 10000), (0, 10000), (-411, 10000), (8662, 10000)]


def ifd0(sub_at, exif_at, strip_at):
    return [
        (0x00FE, "L", [1]),
        (0x0100, "H", [4]),
        (0x0101, "H", [4]),
        (0x0102, "H", [8, 8, 8]),
        (0x0103, "H", [1]),
        (0x0106, "H", [2]),
        (0x010F, "A", b"Filly\0"),
        (0x0110, "A", b"Raw Two\0"),
        (0x0111, "L", [strip_at]),
        (0x0112, "H", [1]),
        (0x0115, "H", [3]),
        (0x0116, "H", [4]),
        (0x0117, "L", [48]),
        (0x011C, "H", [1]),
        (0x0131, "A", b"make.py\0"),
        (0x0132, "A", b"2024:05:01 12:00:00\0"),
        (0x014A, "L", [sub_at]),
        (0x02BC, "B", XMP),
        (0x83BB, "U", iptc()),
        (0x8769, "L", [exif_at]),
        (0xC612, "B", [1, 4, 0, 0]),
        (0xC613, "B", [1, 1, 0, 0]),
        (0xC614, "A", b"Filly Raw Two\0"),
        (0xC621, "r", matrix),
        (0xC628, "R", [(4732, 10000), (10000, 10000), (6491, 10000)]),
        (0xC62A, "r", [(-50, 100)]),
        (0xC62F, "A", b"FR2-000042\0"),
        (0xC630, "R", [(24, 1), (70, 1), (28, 10), (28, 10)]),
        (0xC65A, "H", [21]),
        (0xC6F8, "A", b"Adobe Standard\0"),
        (0xC6FD, "L", [3]),
        (0xC714, "r", forward),
    ]


def sub(raw_at):
    return [
        (0x00FE, "L", [0]),
        (0x0100, "H", [4]),
        (0x0101, "H", [4]),
        (0x0102, "H", [16]),
        (0x0103, "H", [1]),
        (0x0106, "H", [32803]),
        (0x0111, "L", [raw_at]),
        (0x0115, "H", [1]),
        (0x0116, "H", [4]),
        (0x0117, "L", [32]),
        (0x828D, "H", [2, 2]),
        (0x828E, "B", [0, 1, 1, 2]),
        (0xC616, "B", [0, 1, 2]),
        (0xC617, "H", [1]),
        (0xC619, "H", [2, 2]),
        (0xC61A, "L", [64, 64, 64, 64]),
        (0xC61D, "H", [4095]),
        (0xC61E, "R", [(1, 1), (1, 1)]),
        (0xC61F, "R", [(0, 1), (0, 1)]),
        (0xC620, "R", [(4, 1), (4, 1)]),
        (0xC68D, "L", [0, 0, 4, 4]),
        (0xC741, "U", opcode_list()),
    ]


def exif():
    return [
        (0x829A, "R", [(1, 60)]),
        (0x829D, "R", [(28, 10)]),
        (0x8827, "H", [100]),
        (0x9000, "U", b"0232"),
        (0x9003, "A", b"2024:05:01 12:00:00\0"),
        (0x920A, "R", [(35, 1)]),
    ]


a = 8 + len(ifd(8, ifd0(0, 0, 0)))
b = a + len(ifd(a, sub(0)))
c = b + len(ifd(b, exif()))
d = c + 48
preview = bytes(range(48))
raw = b"".join(struct.pack("<H", 64 + 250 * i) for i in range(16))
data = (
    b"II*\0" + struct.pack("<L", 8)
    + ifd(8, ifd0(a, b, c))
    + ifd(a, sub(d))
    + ifd(b, exif())
    + preview
    + raw
)
with open(sys.argv[1], "wb") as out:
    out.write(data)
