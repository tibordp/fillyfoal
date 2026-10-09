"""Synthetic PNG fixtures for chunks no tool at hand writes:

- ancillary.png: an indexed image with sRGB, cHRM, gAMA, sBIT, bKGD, hIST,
  sPLT, oFFs, sCAL, sTER, pCAL, tIME, an ImageMagick-style "Raw profile
  type exif" zTXt (hexadecimal Exif), a private ancillary chunk and a tEXt
  chunk with a wrong CRC.
- cgbi.png: Apple's iOS variant: a CgBI chunk before IHDR and image data
  as raw deflate (no zlib header), BGRA.

    python3 tests/data/png/synthetic.py

Written from the PNG specification (third edition), the PNG extensions
document and descriptions of CgBI and ImageMagick's raw profiles.
"""

import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "png")


def chunk(kind, data, crc=None):
    if crc is None:
        crc = zlib.crc32(kind + data)
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def ihdr(w, h, depth, color, interlace=0):
    return chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, color, 0, 0, interlace))


def tiff_exif():
    # Big-endian TIFF, one IFD with Make and Model (ASCII, stored after the IFD).
    make = b"fillyfoal\x00"
    model = b"synthetic\x00"
    ifd_off = 8
    entries = 2
    data_off = ifd_off + 2 + entries * 12 + 4
    out = b"MM\x00\x2a" + struct.pack(">I", ifd_off)
    out += struct.pack(">H", entries)
    out += struct.pack(">HHII", 0x010F, 2, len(make), data_off)
    out += struct.pack(">HHII", 0x0110, 2, len(model), data_off + len(make))
    out += struct.pack(">I", 0)
    return out + make + model


def raw_profile(kind, data):
    hexed = data.hex()
    lines = "\n".join(hexed[i : i + 72] for i in range(0, len(hexed), 72))
    return f"\n{kind}\n{len(data):8d}\n{lines}\n".encode()


def ancillary():
    w, h = 4, 2
    pixels = b"".join(b"\x00" + bytes((x + y) % 4 for x in range(w)) for y in range(h))
    out = b"\x89PNG\r\n\x1a\n"
    out += ihdr(w, h, 8, 3)
    out += chunk(b"sRGB", b"\x00")
    out += chunk(b"gAMA", struct.pack(">I", 45455))
    out += chunk(b"cHRM", struct.pack(">8I", 31270, 32900, 64000, 33000, 30000, 60000, 15000, 6000))
    out += chunk(b"sBIT", b"\x05\x06\x05")
    out += chunk(b"PLTE", bytes([0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255]))
    out += chunk(b"bKGD", b"\x02")
    out += chunk(b"hIST", struct.pack(">4H", 2, 2, 2, 2))
    entries = b"".join(struct.pack(">4BH", r, g, b, 255, f) for r, g, b, f in [(255, 0, 0, 10), (0, 255, 0, 5), (0, 0, 255, 1)])
    out += chunk(b"sPLT", b"suggested\x00\x08" + entries)
    out += chunk(b"oFFs", struct.pack(">iiB", 100, -20, 0))
    out += chunk(b"sCAL", b"\x01" + b"0.0254\x00" + b"0.0254")
    out += chunk(b"sTER", b"\x00")
    out += chunk(b"pCAL", b"temperature\x00" + struct.pack(">iiBB", 0, 255, 0, 2) + b"K\x00" + b"273.15\x00" + b"0.5")
    out += chunk(b"tIME", struct.pack(">HBBBBB", 2026, 10, 9, 12, 30, 45))
    out += chunk(b"zTXt", b"Raw profile type exif\x00\x00" + zlib.compress(raw_profile("exif", b"Exif\x00\x00" + tiff_exif())))
    out += chunk(b"prVt", b"private data")
    out += chunk(b"tEXt", b"Comment\x00bad checksum", crc=0x12345678)
    out += chunk(b"IDAT", zlib.compress(pixels))
    out += chunk(b"IEND", b"")
    return out


def cgbi():
    w, h = 3, 2
    rows = []
    for y in range(h):
        row = b"\x00"
        for x in range(w):
            row += bytes([x * 80, y * 120, 200, 255])  # B, G, R, A
        rows.append(row)
    raw = zlib.compressobj(9, zlib.DEFLATED, -15)
    data = raw.compress(b"".join(rows)) + raw.flush()
    out = b"\x89PNG\r\n\x1a\n"
    out += chunk(b"CgBI", struct.pack(">I", 0x50002006))
    out += ihdr(w, h, 8, 6)
    out += chunk(b"IDAT", data)
    out += chunk(b"IEND", b"")
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "ancillary.png"), "wb") as f:
        f.write(ancillary())
    with open(os.path.join(OUT, "cgbi.png"), "wb") as f:
        f.write(cgbi())


if __name__ == "__main__":
    main()
