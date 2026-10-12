#!/usr/bin/env python3
"""Writes fake-page-tail.ogg: the external vorbis.ogg followed by 27 bytes
that look like an Ogg page header (capture pattern, version 0, the
stream's serial, a granule position of 60 s) but whose CRC is wrong and
whose header-type byte has undefined bits set. A duration taken from it
would be 60 s instead of 200 ms.

Usage: fake_tail.py IN.ogg OUT.ogg
"""
import struct
import sys


def main():
    data = open(sys.argv[1], "rb").read()
    serial = struct.unpack_from("<I", data, 14)[0]
    fake = b"OggS" + bytes([0, 0x04]) + struct.pack("<QIII", 8000 * 60, serial, 99, 0xDEADBEEF)
    fake += bytes([0])  # no segments
    with open(sys.argv[2], "wb") as f:
        f.write(data + fake)


if __name__ == "__main__":
    main()
