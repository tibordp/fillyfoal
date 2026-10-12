#!/usr/bin/env python3
"""Writes it215.it: an Impulse Tracker module whose one sample is stored
IT 2.15-compressed (sample flags 0x0b, convert 0x05), to exercise the
compressed-block walk.

The blocks follow the framing libxmp's itsex.c and Schism Tracker read (a
16-bit byte count, then the bit stream; 0x4000 samples per block for
16-bit samples), but their bit streams are filler: the dissector only
walks the framing. 0x5000 samples need two blocks.

Usage: compressed.py OUT.it
"""
import struct
import sys


def main():
    orders = bytes([0, 255])
    n_ins, n_smp, n_pat = 0, 1, 1
    header = bytearray(b"IMPM")
    header += b"compressed".ljust(26, b"\0")
    header += struct.pack("<H", 0x1004)  # row highlight
    header += struct.pack("<4H", len(orders), n_ins, n_smp, n_pat)
    header += struct.pack("<HHHH", 0x0215, 0x0214, 0x0009, 0x0000)  # cwt, cmwt, flags, special
    header += bytes([128, 48, 6, 125, 128, 0])
    header += struct.pack("<HII", 0, 0, 0)  # message length, offset, reserved
    header += bytes([32] * 2 + [0xA0] * 62)  # channel panning
    header += bytes([64] * 64)  # channel volume
    assert len(header) == 0xC0

    tables_end = 0xC0 + len(orders) + 4 * (n_ins + n_smp + n_pat)
    sample_at = tables_end
    pattern_at = sample_at + 0x50
    rows = bytes([0x81, 0x0F, 60, 1, 64, 1, 6, 0]) + bytes(63)  # row 0, then 63 empty rows
    pattern = struct.pack("<HH4x", len(rows), 64) + rows
    data_at = pattern_at + len(pattern)

    blocks = b""
    for length in (0x40, 0x22):
        blocks += struct.pack("<H", length) + bytes((i * 37 + length) & 0xFF for i in range(length))

    sample = bytearray(b"IMPS")
    sample += b"it215.raw".ljust(12, b"\0")
    sample += bytes([0, 64, 0x01 | 0x02 | 0x08, 64])  # zero, global volume, flags, volume
    sample += b"compressed 16-bit".ljust(26, b"\0")
    sample += bytes([0x05, 32])  # convert: signed, delta (IT 2.15); panning
    sample += struct.pack("<7I", 0x5000, 0, 0, 22050, 0, 0, data_at)
    sample += bytes(4)  # vibrato
    assert len(sample) == 0x50

    out = bytes(header) + orders
    out += struct.pack("<I", sample_at) + struct.pack("<I", pattern_at)
    out += bytes(sample) + pattern + blocks
    with open(sys.argv[1], "wb") as f:
        f.write(out)


if __name__ == "__main__":
    main()
