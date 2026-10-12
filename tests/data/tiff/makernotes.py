"""Writes synthetic Exif blocks (TIFF streams as found after "Exif\\0\\0" in
a JPEG APP1 segment) carrying maker notes in each maker's layout, from our
reading of the layouts ExifTool and exiv2 document. Tag values are made up.

    python3 tests/data/tiff/makernotes.py tests/fixtures/synthetic/tiff

Writes makernote-{canon,nikon,sony,fujifilm,olympus,panasonic,apple}.tif
and makernote-{huawei,leica,casio,ricoh,sigma,dji}.tif.
"""

import os
import plistlib
import struct
import sys

TYPES = {
    "B": (1, 1),
    "A": (2, 1),
    "H": (3, 2),
    "L": (4, 4),
    "R": (5, 8),
    "U": (7, 1),
    "h": (8, 2),
    "l": (9, 4),
    "r": (10, 8),
    "I": (13, 4),
    "f": (11, 4),
}

# An 8x8 baseline JPEG for previews: the repository's tiny.jpg fixture.
HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "../../fixtures/synthetic/jpeg/tiny.jpg"), "rb") as f:
    JPEG = f.read()


def encode(e, kind, values):
    code, size = TYPES[kind]
    if kind in "ABU":
        return code, len(values), bytes(values)
    if kind in "Rr":
        fmt = "L" if kind == "R" else "l"
        raw = b"".join(struct.pack(e + fmt + fmt, n, d) for n, d in values)
        return code, len(values), raw
    fmt = {"H": "H", "L": "L", "h": "h", "l": "l", "I": "L", "f": "f"}[kind]
    return code, len(values), b"".join(struct.pack(e + fmt, v) for v in values)


def ifd(e, at, entries, base=0, next_ifd=0):
    """An IFD at position `at`, its out-of-line values right after it;
    offsets are written relative to `base`. Returns the bytes and where
    each tag's value went."""
    entries = sorted(entries, key=lambda x: x[0])
    data_at = at + 2 + 12 * len(entries) + 4
    body, data, where = b"", b"", {}
    for tag, kind, values in entries:
        code, count, raw = encode(e, kind, values)
        if len(raw) <= 4:
            field = raw.ljust(4, b"\0")
            where[tag] = None
        else:
            where[tag] = data_at + len(data)
            field = struct.pack(e + "L", data_at + len(data) - base)
            data += raw + (b"\0" if len(raw) % 2 else b"")
        body += struct.pack(e + "HHL", tag, code, count) + field
    return struct.pack(e + "H", len(entries)) + body + struct.pack(e + "L", next_ifd) + data, where


def exif_stream(e, make, model, exif_entries, note):
    """IFD0 (Make, Model, DateTime, Exif pointer), then the Exif IFD whose
    last value is the maker note `note(position)`."""
    order = b"II" if e == "<" else b"MM"
    ifd0 = [
        (0x010F, "A", make + b"\0"),
        (0x0110, "A", model + b"\0"),
        (0x0132, "A", b"2024:05:01 12:00:00\0"),
        (0x8769, "L", [0]),
    ]
    size0 = len(ifd(e, 8, ifd0)[0])
    exif_at = 8 + size0
    ifd0[-1] = (0x8769, "L", [exif_at])
    first, _ = ifd(e, 8, ifd0)
    placeholder = note(0)
    entries = exif_entries + [(0x927C, "U", placeholder)]
    _, where = ifd(e, exif_at, entries)
    entries[-1] = (0x927C, "U", note(where[0x927C]))
    exif, _ = ifd(e, exif_at, entries)
    return order + struct.pack(e + "HL", 42, 8) + first + exif


COMMON = [
    (0x829A, "R", [(1, 250)]),
    (0x829D, "R", [(56, 10)]),
    (0x8827, "H", [400]),
    (0x9003, "A", b"2024:05:01 12:00:00\0"),
    (0x920A, "R", [(50, 1)]),
]


def canon(at):
    e = "<"
    settings = [0] * 47
    settings[0] = 94
    settings[1], settings[3], settings[5], settings[7] = 2, 4, 0, 1
    settings[17], settings[20] = 3, 3
    settings[22], settings[23], settings[24], settings[25] = 61182, 105, 24, 1
    shot = [0] * 34
    shot[0], shot[2], shot[21], shot[22] = 68, 192, 160, 256
    entries = [
        (0x0001, "H", settings),
        (0x0002, "H", [2, 50, 3600, 2400]),
        (0x0004, "H", shot),
        (0x0006, "A", b"Canon EOS R5\0"),
        (0x0007, "A", b"Firmware Version 1.8.1\0"),
        (0x0010, "L", [0x80000421]),
        (0x0095, "A", b"RF24-105mm F4 L IS USM\0"),
    ]
    return ifd(e, at, entries)[0]


def nikon(at):
    e = ">"
    inner = 10
    preview_at = 8 + len(ifd(e, 8, NIKON_MAIN(0))[0])
    main, _ = ifd(e, 8, NIKON_MAIN(preview_at))
    preview_entries = [
        (0x0103, "H", [6]),
        (0x0201, "L", [0]),
        (0x0202, "L", [len(JPEG)]),
    ]
    size = len(ifd(e, preview_at, preview_entries)[0])
    preview_entries[1] = (0x0201, "L", [preview_at + size])
    preview, _ = ifd(e, preview_at, preview_entries)
    tiff = b"MM" + struct.pack(">HL", 42, 8) + main + preview + JPEG
    return b"Nikon\0\x02\x10\0\0" + tiff


def NIKON_MAIN(preview_at):
    return [
        (0x0001, "U", b"0211"),
        (0x0002, "H", [0, 400]),
        (0x0004, "A", b"RAW\0"),
        (0x0011, "L", [preview_at]),
        (0x001D, "A", b"7654321\0"),
        (0x0084, "R", [(24, 1), (70, 1), (28, 10), (28, 10)]),
        (0x00A7, "L", [12345]),
    ]


def sony(at):
    e = "<"
    head = b"SONY DSC \0\0\0"
    entries = [
        (0x0102, "L", [5]),
        (0x2001, "U", JPEG),
        (0xB001, "H", [362]),
        (0xB027, "L", [32784]),
    ]
    return head + ifd(e, at + len(head), entries)[0]


def fujifilm(at):
    e = "<"
    entries = [
        (0x0000, "U", b"0130"),
        (0x1000, "A", b"NORMAL \0"),
        (0x1401, "H", [0x600]),
        (0x1404, "R", [(18, 1)]),
        (0x1405, "R", [(55, 1)]),
    ]
    return b"FUJIFILM" + struct.pack("<L", 12) + ifd(e, 12, entries)[0]


def olympus(at):
    e = "<"
    equipment = [
        (0x0000, "U", b"0100"),
        (0x0201, "B", [0, 1, 0x10, 0, 0, 0]),
        (0x0203, "A", b"M.Zuiko Digital ED 12-40mm F2.8 PRO\0"),
        (0x0207, "H", [12]),
        (0x0208, "H", [40]),
    ]
    camera = [(0x0000, "U", b"0100"), (0x0200, "H", [3, 0]), (0x0301, "H", [0])]
    main = [(0x0000, "U", b"0100"), (0x2010, "I", [0]), (0x2020, "I", [0])]
    main_size = len(ifd(e, 12, main)[0])
    eq_at = 12 + main_size
    eq_size = len(ifd(e, eq_at, equipment)[0])
    cam_at = eq_at + eq_size
    main = [(0x0000, "U", b"0100"), (0x2010, "I", [eq_at]), (0x2020, "I", [cam_at])]
    return (
        b"OLYMPUS\0II\x03\0"
        + ifd(e, 12, main)[0]
        + ifd(e, eq_at, equipment)[0]
        + ifd(e, cam_at, camera)[0]
    )


def panasonic(at):
    e = "<"
    head = b"Panasonic\0\0\0"
    entries = [
        (0x0001, "H", [2]),
        (0x0002, "U", b"\x00\x01\x00\x02"),
        (0x0025, "U", b"F541203150123\0\0\0"),
        (0x0051, "A", b"LUMIX G VARIO 12-35/F2.8\0"),
    ]
    return head + ifd(e, at + len(head), entries)[0]


def apple(at):
    e = ">"
    runtime = plistlib.dumps(
        {"flags": 1, "value": 123456789, "timescale": 1000000000, "epoch": 0},
        fmt=plistlib.FMT_BINARY,
    )
    entries = [
        (0x0001, "l", [14]),
        (0x0003, "U", runtime),
        (0x000A, "l", [3]),
        (0x0011, "A", b"0E3F5C2A-1B2C-4D5E-8F90-A1B2C3D4E5F6\0"),
    ]
    return b"Apple iOS\0\0\x01MM" + ifd(e, 14, entries)[0]


def huawei(at):
    # "HUAWEI\0\0", then a TIFF header of the note's own; offsets are
    # relative to it.
    e = ">"
    entries = [
        (0x0200, "L", [1]),
        (0x0201, "A", b"fillyfoal scene\0"),
        (0x0202, "L", [0, 0, 0, 0]),
    ]
    return b"HUAWEI\0\0" + b"MM" + struct.pack(">HL", 42, 8) + ifd(e, 8, entries)[0]


def leica(at):
    # Leica Q-type: "LEICA\0\x08\0", the IFD after it, offsets relative to
    # the Exif TIFF header.
    e = "<"
    head = b"LEICA\0\x08\0"
    entries = [
        (0x0300, "A", b"Leica Summilux 1:1.7/28 ASPH.\0"),
        (0x0301, "L", [3]),
        (0x0304, "L", [42]),
    ]
    return head + ifd(e, at + len(head), entries)[0]


def casio(at):
    # Casio type 2: "QVC\0\0\0", the IFD at +6, offsets relative to the
    # Exif TIFF header.
    e = ">"
    head = b"QVC\0\0\0"
    entries = [
        (0x0008, "H", [2]),
        (0x0009, "L", [8]),
        (0x0014, "H", [100]),
        (0x2001, "A", b"2024:05:01 12:00:00\0"),
        (0x3006, "A", b"Reykjavik\0"),
    ]
    return head + ifd(e, at + len(head), entries)[0]


def ricoh(at):
    # Ricoh: "Ricoh\0\0\0", the IFD at +8, offsets relative to the Exif
    # TIFF header.
    e = "<"
    head = b"Ricoh\0\0\0"
    entries = [
        (0x0001, "A", b"Rdc\0"),
        (0x0002, "A", b"Rev1.00\0"),
        (0x0005, "U", b"0123456789ABCDEF"),
        (0x1307, "L", [5200]),
    ]
    return head + ifd(e, at + len(head), entries)[0]


def sigma(at):
    # Sigma: "SIGMA\0\0\0" and a version word, the IFD at +10.
    e = "<"
    head = b"SIGMA\0\0\0\x01\0"
    entries = [
        (0x0002, "A", b"9876543\0"),
        (0x0003, "A", b"SINGLE\0"),
        (0x0005, "A", b"AF-S\0"),
        (0x0018, "A", b"SIGMA Photo Pro\0"),
    ]
    return head + ifd(e, at + len(head), entries)[0]


def dji(at):
    # DJI drones: a bare IFD (no header) of floats.
    e = "<"
    entries = [
        (0x0001, "A", b"DJI\0"),
        (0x0006, "f", [1.5]),
        (0x0007, "f", [-120.25]),
        (0x0008, "f", [0.75]),
        (0x0009, "f", [-90.0]),
    ]
    return ifd(e, at, entries)[0]


FILES = {
    "canon": ("<", b"Canon", b"Canon EOS R5", canon),
    "nikon": (">", b"NIKON CORPORATION", b"NIKON Z 6", nikon),
    "sony": ("<", b"SONY", b"ILCE-7M3", sony),
    "fujifilm": (">", b"FUJIFILM", b"X-T3", fujifilm),
    "olympus": ("<", b"OM Digital Solutions", b"OM-1", olympus),
    "panasonic": ("<", b"Panasonic", b"DC-GH5", panasonic),
    "apple": (">", b"Apple", b"iPhone 15 Pro", apple),
    "huawei": ("<", b"HUAWEI", b"ELS-NX9", huawei),
    "leica": ("<", b"LEICA CAMERA AG", b"LEICA Q (Typ 116)", leica),
    "casio": (">", b"CASIO COMPUTER CO.,LTD.", b"EX-ZR100", casio),
    "ricoh": ("<", b"RICOH", b"Caplio GX100", ricoh),
    "sigma": ("<", b"SIGMA", b"SIGMA DP2 Merrill", sigma),
    "dji": ("<", b"DJI", b"FC3170", dji),
}

out = sys.argv[1]
for name, (e, make, model, note) in FILES.items():
    with open(os.path.join(out, f"makernote-{name}.tif"), "wb") as f:
        f.write(exif_stream(e, make, model, list(COMMON), note))
