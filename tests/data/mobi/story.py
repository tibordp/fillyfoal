#!/usr/bin/env python3
"""Writes the synthetic tests/fixtures/synthetic/mobi/story.mobi:

    python3 tests/data/mobi/story.py [OUT]

A Palm database (BOOKMOBI) with record 0 holding an uncompressed PalmDOC
header, a 232-byte MOBI 6 header (UTF-8) and EXTH (author, publisher,
ASIN, language), and one text record of HTML. Hand-assembled from the
MobileRead MOBI layout; no Mobipocket tool was involved. Palm dates are
1904-based (top bit set).
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "mobi", "story.mobi")

TEXT = b"<html><body>Hello, Fillyfoal!</body></html>"
TITLE = b"The Fillyfoal Story"


def exth(records):
    body = b"".join(struct.pack(">II", k, len(v) + 8) + v for k, v in records)
    return b"EXTH" + struct.pack(">II", len(body) + 12, len(records)) + body


def main(out):
    ex = exth([
        (100, b"Fillyfoal Author"),
        (101, b"Fillyfoal Press"),
        (113, b"B000FFOL01"),
        (524, b"en"),
    ])
    mobi = bytearray(0xE8)
    mobi[0:4] = b"MOBI"
    struct.pack_into(">IIII", mobi, 4, 0xE8, 2, 65001, 0x1234)
    struct.pack_into(">I", mobi, 0x14, 6)
    title_at = 16 + len(mobi) + len(ex)
    struct.pack_into(">II", mobi, 0x44, title_at, len(TITLE))
    struct.pack_into(">I", mobi, 0x70, 0x50)
    palmdoc = struct.pack(">HHIHHHH", 1, 0, len(TEXT), 1, 4096, 0, 0)
    record0 = palmdoc + bytes(mobi) + ex + TITLE
    record0 += b"\0" * (-len(record0) % 4)
    first = 78 + 2 * 8 + 2
    header = TITLE.replace(b" ", b"_").ljust(32, b"\0")
    header += struct.pack(">HHIIIIII", 0, 1, 0xE1B2C3D4, 0xE1B2C3D4, 0, 0, 0, 0)
    header += b"BOOKMOBI" + struct.pack(">IIH", 0, 0, 2)
    header += struct.pack(">II", first, 0) + struct.pack(">II", first + len(record0), 1)
    header += b"\0\0"
    with open(out, "wb") as f:
        f.write(header + record0 + TEXT)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else OUT)
