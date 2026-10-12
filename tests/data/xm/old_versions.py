#!/usr/bin/env python3
"""Writes v102.xm and v103.xm: XM files in FastTracker 2's pre-2.0x layouts.

No tool we can run writes these versions, so they are built from the layout
libxmp 4.6.2 reads (src/loaders/xm_load.c):

- version <= 0x0103: all instrument headers (with their sample headers)
  come first, then the patterns, then the sample data of every instrument
  in order;
- version <= 0x0102: pattern headers are 8 bytes, with a one-byte row
  count stored minus one instead of a 16-bit count.

Each file has two channels, one 16-row pattern with a few packed cells and
one instrument with one 16-byte delta-coded sample.

Usage: old_versions.py OUTDIR
"""
import os
import struct
import sys


def header(version, patterns, instruments, channels=2):
    out = bytearray(b"Extended Module: ")
    out += b"old layout".ljust(20, b"\0")
    out += b"\x1a"
    out += b"FastTracker v2.00   "
    out += struct.pack("<H", version)
    out += struct.pack("<I", 20 + 256)  # header size, from this field
    out += struct.pack("<8H", 1, 0, channels, patterns, instruments, 1, 6, 125)
    out += bytes([0] + [0] * 255)  # order table: pattern 0
    return bytes(out)


def packed_rows(rows, channels=2):
    data = bytearray()
    for r in range(rows):
        for c in range(channels):
            if r == 0 and c == 0:
                data += bytes([49, 1, 0x40, 0x0F, 0x06])  # C-4, ins 1, vol 48, F06
            elif r == 4 and c == 1:
                data += bytes([0x80 | 0x01 | 0x02, 61, 1])  # C-5, ins 1
            elif r == 8 and c == 0:
                data += bytes([0x80 | 0x01, 97])  # key off
            elif r == 12 and c == 1:
                data += bytes([0x80 | 0x08 | 0x10, 0x0A, 0x02])  # A02
            else:
                data += b"\x80"
    return bytes(data)


def pattern(version, rows=16):
    data = packed_rows(rows)
    if version <= 0x0102:
        return struct.pack("<IBBH", 8, 0, rows - 1, len(data)) + data
    return struct.pack("<IBHH", 9, 0, rows, len(data)) + data


def instrument():
    sample = bytes([0x10] * 8 + [0xF0] * 8)  # deltas of a square wave
    size = 263
    head = struct.pack("<I", size) + b"square".ljust(22, b"\0") + b"\0"
    head += struct.pack("<HI", 1, 40)
    head += bytes(96)  # note-to-sample map
    head += bytes(48 + 48)  # envelopes
    head += bytes(14)  # envelope counts, points, types, vibrato
    head += struct.pack("<H", 0)  # fadeout
    head += bytes(size - len(head))  # reserved
    sh = struct.pack("<III", len(sample), 0, 0)
    sh += bytes([64, 0, 0, 128, 0, 0])
    sh += b"square".ljust(22, b"\0")
    return head + sh, sample


def write(path, version):
    headers, data = instrument()
    body = header(version, 1, 1)
    body += headers + pattern(version) + data
    with open(path, "wb") as f:
        f.write(body)


def main():
    out = sys.argv[1]
    write(os.path.join(out, "v102.xm"), 0x0102)
    write(os.path.join(out, "v103.xm"), 0x0103)


if __name__ == "__main__":
    main()
