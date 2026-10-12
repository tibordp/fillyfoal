#!/usr/bin/env python3
"""Writes tests/fixtures/synthetic/tes-plugin/nested.esp: a Skyrim-style
(24-byte record headers) plugin laid out from UESP's "Mod File Format" pages,
with what the walker must handle:

- the TES4 header record (HEDR, CNAM, MAST/DATA);
- a top group of GMST with a record carrying an XXXX subrecord (the next
  subrecord's size in 32 bits, its own 16-bit size 0);
- a top group of CELL nesting an interior cell block (type 2), a sub-block
  (type 3), a CELL record, its cell children group (type 6) and a temporary
  children group (type 9) holding a REFR;
- a WEAP record compressed with zlib (flag 0x40000: u32 decompressed size,
  then the zlib stream of its subrecords).

It also writes morrowind.esp, a TES3 plugin (16-byte record and 8-byte
subrecord headers). No open tool writes plugins, so these are synthetic.

    python3 tests/data/tes-plugin/make.py OUTDIR
    gzip -9 -n OUTDIR/nested.esp     # 75 KiB, for the XXXX subrecord
"""
import struct
import sys
import zlib
from pathlib import Path


def sub(kind, data):
    return kind + struct.pack("<H", len(data)) + data


def zstr(s):
    return s.encode("ascii") + b"\0"


def record(kind, form_id, body, flags=0):
    if flags & 0x40000:
        body = struct.pack("<I", len(body)) + zlib.compress(body, 9)
    return kind + struct.pack("<IIIIHH", len(body), flags, form_id, 0, 44, 0) + body


def group(label, kind, children):
    body = b"".join(children)
    return b"GRUP" + struct.pack("<I", 24 + len(body)) + label + struct.pack("<iII", kind, 0, 0) + body


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    header = record(
        b"TES4",
        0,
        sub(b"HEDR", struct.pack("<fIi", 1.71, 5, 0x800))
        + sub(b"CNAM", zstr("fillyfoal"))
        + sub(b"MAST", zstr("Skyrim.esm"))
        + sub(b"DATA", b"\0" * 8),
    )
    big = bytes(range(256)) * 300  # 76,800 bytes: too long for a u16 size
    gmst = record(
        b"GMST",
        0x01000800,
        sub(b"EDID", zstr("sFillyfoalNote"))
        + sub(b"XXXX", struct.pack("<I", len(big)))
        + b"DATA" + struct.pack("<H", 0) + big,
    )
    refr = record(b"REFR", 0x01000803, sub(b"EDID", zstr("FillyfoalChest")) + sub(b"NAME", struct.pack("<I", 0x01000804)))
    cell = record(b"CELL", 0x01000802, sub(b"EDID", zstr("FillyfoalRoom")) + sub(b"DATA", b"\x01\x00"))
    cells = group(
        b"CELL",
        0,
        [
            group(
                struct.pack("<I", 2),
                2,
                [
                    group(
                        struct.pack("<I", 7),
                        3,
                        [
                            cell,
                            group(struct.pack("<I", 0x01000802), 6, [group(struct.pack("<I", 0x01000802), 9, [refr])]),
                        ],
                    )
                ],
            )
        ],
    )
    weap = record(
        b"WEAP",
        0x01000804,
        sub(b"EDID", zstr("FillyfoalSword")) + sub(b"FULL", zstr("Sword of Tests")) + sub(b"DATA", struct.pack("<IfH", 25, 9.0, 7)),
        flags=0x40000,
    )
    data = header + group(b"GMST", 0, [gmst]) + cells + group(b"WEAP", 0, [weap])
    (out / "nested.esp").write_bytes(data)
    (out / "morrowind.esp").write_bytes(tes3())


def tes3():
    """A Morrowind plugin: 16-byte record headers, 8-byte subrecord headers."""

    def sub3(kind, data):
        return kind + struct.pack("<I", len(data)) + data

    def rec3(kind, body, flags=0):
        return kind + struct.pack("<III", len(body), 0, flags) + body

    hedr = struct.pack("<fI", 1.3, 0) + b"fillyfoal".ljust(32, b"\0") + b"A test plugin.".ljust(256, b"\0") + struct.pack("<I", 1)
    header = rec3(b"TES3", sub3(b"HEDR", hedr) + sub3(b"MAST", zstr("Morrowind.esm")) + sub3(b"DATA", struct.pack("<Q", 0)))
    gmst = rec3(b"GMST", sub3(b"NAME", zstr("sFillyfoal")) + sub3(b"STRV", b"Hello"))
    return header + gmst


if __name__ == "__main__":
    main()
