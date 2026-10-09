"""Writes two Word 95 documents (nFib 0x68) for the synthetic fixtures, from
memory of the Word 6/95 layout: a 0x192-byte FIB with fcMin/fcMac, story
character counts and fc/lcb pairs into the WordDocument stream (there is no
table stream), 8-bit text in Windows-1250, a font table whose "CE" font
names that code page, associated strings and a DOP.

    python tests/data/doc/make_word95.py tests/fixtures/synthetic/doc

`word95.doc` keeps its text in one run (fcMin..fcMac); `word95-fastsaved.doc`
was "fast saved": its text is in two pieces stored out of order, located by a
piece table (CLX). No stylesheet or formatting pages: the dissector does not
decode Word 6 sprms.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cfb"))
import cfbwriter  # noqa: E402

# CLSID_WordDocument6, {00020900-0000-0000-C000-000000000046}.
WORD6 = struct.pack("<IHH", 0x00020900, 0, 0) + bytes([0xC0, 0, 0, 0, 0, 0, 0, 0x46])

TEXT = "Hitri konj in ukradeni totem.\rŠumniki: č, š, ž; Č, Š, Ž.\r".encode("cp1250")

# Pair indices (Word 97 numbering, shared with Word 6).
STTBF_FFN, DOP, STTBF_ASSOC, CLX = 15, 31, 32, 33


def dttm(year, month, day, hour, minute, weekday):
    return minute | hour << 6 | day << 11 | month << 16 | (year - 1900) << 20 | weekday << 29


def ffn(name, chs, flags):
    body = struct.pack("<BhBB", flags, 400, chs, 0) + name.encode("cp1252") + b"\0"
    return bytes([len(body)]) + body


def sttb(strings):
    body = b"".join(bytes([len(s)]) + s for s in strings)
    return struct.pack("<H", len(body) + 2) + body


def dop():
    settings = bytes(0x14)
    stats = struct.pack(
        "<IIIHIIIHI",
        dttm(2001, 2, 3, 4, 5, 6),  # created: Saturday 2001-02-03 04:05
        dttm(2001, 2, 3, 4, 9, 6),  # revised
        0,  # never printed
        2,  # nRevision
        3,  # tmEdited
        9,  # cWords
        len(TEXT),
        1,  # cPg
        2,  # cParas
    )
    return (settings + stats).ljust(88, b"\0")


def document(fast_saved):
    wd = bytearray(4608)
    fc_min = 0x200
    if fast_saved:
        # The second half first, as an incremental save appends edits.
        cut = TEXT.index(b"\r") + 1
        first, second = TEXT[:cut], TEXT[cut:]
        wd[0x200 : 0x200 + len(second)] = second
        at_first = 0x200 + len(second)
        wd[at_first : at_first + len(first)] = first
        fc_mac = 0x200 + len(TEXT)
        cps = [0, len(first), len(TEXT)]
        pcds = [(at_first, 0), (0x200, 0)]
        plc = b"".join(struct.pack("<I", cp) for cp in cps)
        plc += b"".join(struct.pack("<HIH", 0, fc, prm) for fc, prm in pcds)
        clx = b"\x02" + struct.pack("<I", len(plc)) + plc
    else:
        wd[fc_min : fc_min + len(TEXT)] = TEXT
        fc_mac = fc_min + len(TEXT)
        clx = b""

    structures = {
        STTBF_FFN: struct.pack("<H", 0)
        + ffn("Times New Roman", 0, 0x12)
        + ffn("Symbol", 2, 0x10)
        + ffn("Times New Roman CE", 238, 0x12),
        STTBF_ASSOC: sttb([b"", b"", b"Synthetic Word 95", b"", b"", b"", b"fillyfoal", b"fillyfoal"]),
        DOP: dop(),
    }
    fonts = structures[STTBF_FFN]
    structures[STTBF_FFN] = struct.pack("<H", len(fonts)) + fonts[2:]
    if clx:
        structures[CLX] = clx
    pairs = [(0, 0)] * 38
    at = 0x400
    for index in sorted(structures):
        data = structures[index]
        wd[at : at + len(data)] = data
        pairs[index] = (at, len(data))
        at += len(data)

    flags = 0x0014 if fast_saved else 0  # fComplex, cQuickSaves 1
    fib = struct.pack(
        "<HHHHHHHIBBHHIII",
        0xA5DC,  # wIdent
        0x68,  # nFib: Word 95
        0,  # nProduct
        0x0424,  # lid: Slovenian
        0,  # pnNext
        flags,
        0x65,  # nFibBack
        0,  # lKey
        0,  # envr: Windows
        0,
        0,  # chse: Windows ANSI
        0,  # chseTables
        fc_min,
        fc_mac,
        len(wd),  # cbMac
    )
    fib += bytes(16)  # fcSpare0..3
    fib += struct.pack("<9I", len(TEXT), 0, 0, 0, 0, 0, 0, 0, 0)
    fib += b"".join(struct.pack("<II", fc, lcb) for fc, lcb in pairs)
    fib += bytes(10)  # wSpare4Fib, pnChpFirst, pnPapFirst, cpnBteChp, cpnBtePap
    assert len(fib) == 0x192
    wd[: len(fib)] = fib
    return bytes(wd)


out = sys.argv[1]
for name, fast in [("word95.doc", False), ("word95-fastsaved.doc", True)]:
    cfbwriter.write(os.path.join(out, name), {"WordDocument": document(fast)}, root_clsid=WORD6)
