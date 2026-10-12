"""Writes a tiny little-endian TIFF whose text tags use the UTF-8 field type
(129) that Exif 3.0 (CIPA DC-008-2023) adds next to ASCII: ImageDescription
and Artist in IFD0, an Exif IFD with a UTF-8 CameraOwnerName,
and an ASCII Software tag for comparison. One 2x2 8-bit grey strip.

    python3 tests/data/tiff/utf8_exif3.py tests/fixtures/synthetic/tiff

Writes exif3-utf8.tif. ExifTool 13.25 reads the UTF-8 tags back as text.
"""

import os
import struct
import sys


def ifd(entries, start, next_ifd=0):
    """Serialises an IFD placed at `start`; returns (bytes, data area)."""
    entries = sorted(entries)
    head = struct.pack("<H", len(entries))
    data_at = start + 2 + 12 * len(entries) + 4
    data = b""
    for tag, kind, count, payload in entries:
        if len(payload) <= 4:
            field = payload.ljust(4, b"\0")
        else:
            field = struct.pack("<L", data_at + len(data))
            data += payload + (b"\0" if len(payload) % 2 else b"")
        head += struct.pack("<HHL", tag, kind, count) + field
    return head + struct.pack("<L", next_ifd) + data


def text(tag, kind, s):
    raw = s.encode("utf-8") + b"\0"
    return (tag, kind, len(raw), raw)


def short(tag, v):
    return (tag, 3, 1, struct.pack("<H", v))


def long(tag, v):
    return (tag, 4, 1, struct.pack("<L", v))


def main(out_dir):
    pixels = bytes([0x00, 0x55, 0xAA, 0xFF])
    pixel_at = 8
    exif_at = pixel_at + len(pixels)
    exif = ifd([text(0xA430, 129, "Zoë Ångström")], exif_at)
    ifd0_at = exif_at + len(exif)
    ifd0_at += ifd0_at % 2
    entries = [
        long(0x0100, 2),
        long(0x0101, 2),
        short(0x0102, 8),
        short(0x0103, 1),
        short(0x0106, 1),
        long(0x0111, pixel_at),
        short(0x0115, 1),
        long(0x0116, 2),
        long(0x0117, len(pixels)),
        text(0x010E, 129, "Grüße aus Zürich — 東京"),
        text(0x0131, 2, "fillyfoal"),
        text(0x013B, 129, "Ægir Þórsson"),
        long(0x8769, exif_at),
    ]
    out = b"II*\0" + struct.pack("<L", ifd0_at) + pixels + exif
    out = out.ljust(ifd0_at, b"\0") + ifd(entries, ifd0_at)
    with open(os.path.join(out_dir, "exif3-utf8.tif"), "wb") as f:
        f.write(out)


if __name__ == "__main__":
    main(sys.argv[1])
