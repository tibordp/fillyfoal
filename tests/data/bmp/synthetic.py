"""Synthetic BMP fixtures for structures no tool at hand writes:

- rle8.bmp, rle4.bmp: BI_RLE8 / BI_RLE4 with encoded runs, literal runs
  (one with a pad byte), a delta, end-of-line and end-of-bitmap escapes.
- os2-rle24.bmp: a 64-byte OS/2 2.x header with RLE24 compression.
- os2-array.bmp: an OS/2 bitmap array (BA) of a color icon (CI: a 1-bit
  AND/XOR mask bitmap, then a 4-bit color bitmap) and a 1.x bitmap.
- png-in-bmp.bmp: BI_PNG, the pixels an embedded PNG stream.
- v5-linked.bmp: a top-down BITMAPV5HEADER with a linked ICC profile name.

    python3 tests/data/bmp/synthetic.py

Written from the Windows GDI documentation (BITMAPINFOHEADER through
BITMAPV5HEADER, bitmap compression) and the OS/2 Presentation Manager
bitmap file format description.
"""

import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "bmp")


def file_header(kind, size, x, y, offset):
    return kind + struct.pack("<IhhI", size, x, y, offset)


def info40(w, h, bits, compression, size_image, colors=0):
    return struct.pack("<IiiHHIIiiII", 40, w, h, 1, bits, compression, size_image, 2835, 2835, colors, 0)


def bmp(info, palette, pixels):
    offset = 14 + len(info) + len(palette)
    total = offset + len(pixels)
    return file_header(b"BM", total, 0, 0, offset) + info + palette + pixels


def rle8():
    palette = b"".join(bytes([b, g, r, 0]) for r, g, b in [(0, 0, 0), (255, 0, 0), (0, 255, 0), (0, 0, 255)])
    data = b""
    data += b"\x06\x01" + b"\x00\x00"  # row 0: 6 x index 1, end of line
    data += b"\x00\x03\x02\x03\x02\x00" + b"\x03\x01" + b"\x00\x00"  # row 1: literal 2 3 2 (+pad), 3 x 1, EOL
    data += b"\x00\x02\x02\x01" + b"\x04\x03" + b"\x00\x00"  # row 2: delta (2, 1) then 4 x 3, EOL
    data += b"\x00\x01"  # end of bitmap
    info = info40(6, 4, 8, 1, len(data), colors=4)
    return bmp(info, palette, data)


def rle4():
    palette = b"".join(bytes([i * 16, 255 - i * 16, i * 8, 0]) for i in range(16))
    data = b""
    data += b"\x08\x12" + b"\x00\x00"  # row 0: 8 pixels alternating 1, 2
    data += b"\x00\x06\x34\x56\x78\x00" + b"\x02\xff" + b"\x00\x00"  # literal 3 4 5 6 7 8 (+pad), 2 x 15
    data += b"\x00\x01"
    info = info40(8, 2, 4, 2, len(data), colors=16)
    return bmp(info, palette, data)


def os2_rle24():
    data = b"\x03" + bytes([10, 20, 30]) + b"\x00\x00"  # 3 pixels of one color, EOL
    data += b"\x00\x03" + bytes([1, 2, 3, 4, 5, 6, 7, 8, 9]) + b"\x00" + b"\x00\x00"  # literal 3 (9 bytes + pad)
    data += b"\x00\x01"
    header = struct.pack("<IiiHHIIIIII", 64, 3, 2, 1, 24, 4, len(data), 0, 0, 0, 0)
    header += struct.pack("<HHHHIIII", 0, 0, 0, 0, 0, 0, 0, 0x1234)
    return bmp(header, b"", data)


def core(w, h, bits):
    return struct.pack("<IHHHH", 12, w, h, 1, bits)


def os2_array():
    # Entry 0 (display 1024x768): a CI color icon, 4x4.
    mask_hdr = core(4, 8, 1)
    mask_pal = bytes([0, 0, 0, 255, 255, 255])
    color_hdr = core(4, 4, 4)
    color_pal = b"".join(bytes([i * 16, i * 16, 255 - i * 16]) for i in range(16))
    entry0 = 14 + 14 + len(mask_hdr) + len(mask_pal) + 14 + len(color_hdr) + len(color_pal)
    # Entry 1 (any display): a 2x2 24-bit bitmap.
    bm_hdr = core(2, 2, 24)
    entry1 = 14 + 14 + len(bm_hdr)
    headers = entry0 + entry1
    mask_bits = bytes([0x00, 0, 0, 0] * 4 + [0xF0, 0, 0, 0] * 4)  # AND rows, then XOR rows
    color_bits = bytes([0x01, 0x23, 0, 0, 0x45, 0x67, 0, 0, 0x89, 0xAB, 0, 0, 0xCD, 0xEF, 0, 0])
    bm_bits = bytes([0, 0, 255, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0])
    mask_off = headers
    color_off = mask_off + len(mask_bits)
    bm_off = color_off + len(color_bits)
    out = b"BA" + struct.pack("<IIHH", 40, entry0, 1024, 768)
    out += file_header(b"CI", 26, 2, 2, mask_off) + mask_hdr + mask_pal
    out += file_header(b"CI", 26, 2, 2, color_off) + color_hdr + color_pal
    assert len(out) == entry0
    out += b"BA" + struct.pack("<IIHH", 40, 0, 0, 0)
    out += file_header(b"BM", 26, 0, 0, bm_off) + bm_hdr
    assert len(out) == headers
    return out + mask_bits + color_bits + bm_bits


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png_in_bmp():
    raw = b"\x00\xff\x00\x00\x00\x00\xff" + b"\x00\x00\x00\xff\xff\xff\xff"
    png = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
    png += png_chunk(b"IDAT", zlib.compress(raw)) + png_chunk(b"IEND", b"")
    info = info40(2, 2, 0, 5, len(png))
    return bmp(info, b"", png)


def v5_linked():
    w, h = 2, 2
    pixels = bytes([0, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 255, 255, 255, 255, 255])
    name = b"C:\\Windows\\System32\\spool\\drivers\\color\\sRGB Color Space Profile.icm\x00"
    header = struct.pack("<IiiHHIIiiII", 124, w, -h, 1, 32, 0, len(pixels), 3780, 3780, 0, 0)
    header += struct.pack("<IIII", 0, 0, 0, 0)  # masks (unused with BI_RGB)
    header += struct.pack("<I", 0x4C494E4B)  # PROFILE_LINKED ('LINK')
    header += b"\x00" * 36 + b"\x00" * 12  # endpoints, gamma
    profile_offset = 124 + len(pixels)
    header += struct.pack("<IIII", 4, profile_offset, len(name), 0)
    assert len(header) == 124
    offset = 14 + 124
    total = offset + len(pixels) + len(name)
    return file_header(b"BM", total, 0, 0, offset) + header + pixels + name


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, data in [
        ("rle8.bmp", rle8()),
        ("rle4.bmp", rle4()),
        ("os2-rle24.bmp", os2_rle24()),
        ("os2-array.bmp", os2_array()),
        ("png-in-bmp.bmp", png_in_bmp()),
        ("v5-linked.bmp", v5_linked()),
    ]:
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main()
