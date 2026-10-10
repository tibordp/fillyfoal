"""Writes a small RGBA PNG (a diagonal gradient) with the standard library.

    python3 -I png.py OUT.png SIZE
"""
import struct
import sys
import zlib


def chunk(kind, data):
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))


def main():
    out, size = sys.argv[1], int(sys.argv[2])
    rows = b""
    for y in range(size):
        rows += b"\0" + b"".join(
            bytes((x * 255 // size, y * 255 // size, 160, 255)) for x in range(size)
        )
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(rows, 9))
    png += chunk(b"IEND", b"")
    with open(out, "wb") as f:
        f.write(png)


main()
