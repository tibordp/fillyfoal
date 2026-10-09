"""Builds tests/fixtures/synthetic/wmf/records.wmf.

    python3 tests/data/wmf/gen.py

Written from [MS-WMF] as remembered: an Aldus placeable header (with its
XOR checksum), the metafile header, then mapping, object, text
(META_TEXTOUT, META_EXTTEXTOUT with a clipping rectangle) and bitmap
(META_STRETCHDIB with a 2x1 24-bit DIB) records and META_EOF.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "wmf")


def rec(function, params=b""):
    params += b"\0" * (len(params) % 2)
    return struct.pack("<IH", 3 + len(params) // 2, function) + params


def main():
    records = [
        rec(0x0103, struct.pack("<H", 8)),  # MM_ANISOTROPIC
        rec(0x020B, struct.pack("<hh", 0, 0)),
        rec(0x020C, struct.pack("<hh", 800, 1000)),  # y, x
        rec(
            0x02FB,
            struct.pack("<hhhhh8B", -16, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0)
            + b"Arial".ljust(32, b"\0"),
        ),
        rec(0x012D, struct.pack("<H", 0)),
        rec(0x02FA, struct.pack("<Hhh4B", 0, 3, 0, 0, 0, 255, 0)),
        rec(0x02FC, struct.pack("<H4BH", 0, 0, 255, 0, 0, 0)),
        rec(0x0209, struct.pack("<4B", 255, 0, 0, 0)),
        rec(0x0521, struct.pack("<H", 5) + b"Hello\0" + struct.pack("<hh", 100, 50)),
        rec(
            0x0A32,
            struct.pack("<hhHH", 200, 50, 3, 0x0004)
            + struct.pack("<hhhh", 40, 190, 300, 210)
            + b"abc\0",
        ),
        rec(
            0x0F43,
            struct.pack("<IH8h", 0x00CC0020, 0, 1, 2, 0, 0, 1, 2, 0, 0)
            + struct.pack("<IiiHHIIiiII", 40, 2, 1, 1, 24, 0, 8, 2835, 2835, 0, 0)
            + bytes([0, 0, 255, 0, 255, 0, 0, 0]),
        ),
        rec(0x041B, struct.pack("<hhhh", 700, 900, 100, 100)),  # bottom, right, top, left
        rec(0x01F0, struct.pack("<H", 0)),
        rec(0x0000),
    ]
    body = b"".join(records)
    largest = max(len(r) for r in records) // 2
    header = struct.pack("<HHHIHIH", 1, 9, 0x0300, (18 + len(body)) // 2, 3, largest, 0)
    words = struct.unpack("<10H", struct.pack("<IHhhhhHI", 0x9AC6CDD7, 0, 0, 0, 1000, 800, 1440, 0))
    checksum = 0
    for w in words:
        checksum ^= w
    placeable = struct.pack("<IHhhhhHIH", 0x9AC6CDD7, 0, 0, 0, 1000, 800, 1440, 0, checksum)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "records.wmf"), "wb") as f:
        f.write(placeable + header + body)


if __name__ == "__main__":
    main()
