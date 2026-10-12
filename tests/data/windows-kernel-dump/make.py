"""Writes synthetic Windows kernel dumps from the DUMP_HEADER32/64 layout
(as libkdumpfile, kdmp-parser and Volatility read it; no Windows writer was
available):

  bitmap64.dmp  PAGEDU64, DumpType 6 (bitmap kernel): the SDMP bitmap header
                at 0x2000 marks pages 1 and 3 of 16 present, page data from
                FirstPage 0x3000.
  full32.dmp    PAGEDUMP, DumpType 1 (full): two physical memory runs of one
                page each, stored after the 0x1000-byte header.

    python3 -I tests/data/windows-kernel-dump/make.py OUTDIR
"""
import os
import struct
import sys

out = sys.argv[1]
FILETIME = 133_000_000_000_000_000  # 2022-06-15


def page(text):
    data = (text.encode() * 4096)[:4096]
    return data


def bitmap64():
    h = bytearray(0x2000)
    struct.pack_into('<4s4sII', h, 0, b'PAGE', b'DU64', 15, 19045)
    struct.pack_into('<QQQQ', h, 0x10, 0x1aa000, 0xfffffa8000000000,
                     0xfffff80000000000, 0xfffff80000001000)
    struct.pack_into('<III', h, 0x30, 0x8664, 4, 0xd1)
    struct.pack_into('<QQQQ', h, 0x40, 0x28, 2, 0, 0xfffff80012345678)
    h[0x60:0x80] = b'fillyfoal'.ljust(32, b'\0')
    struct.pack_into('<Q', h, 0x80, 0xfffff80000002000)
    # PHYSICAL_MEMORY_DESCRIPTOR64: one run of 16 pages from page 0.
    struct.pack_into('<IIQQQ', h, 0x88, 1, 0, 16, 0, 16)
    struct.pack_into('<I', h, 0xf00, 0x80000003)  # exception code
    struct.pack_into('<I', h, 0xf98, 6)
    struct.pack_into('<QQ', h, 0xfa0, 0x5000, FILETIME)
    h[0xfb0:0x1030] = b'fillyfoal test dump'.ljust(128, b'\0')
    struct.pack_into('<QIIIII', h, 0x1030, 3600 * 10**7, 0, 0, 1, 0x100, 0)
    bmp = bytearray(0x1000)
    struct.pack_into('<4s4s', bmp, 0, b'SDMP', b'DUMP')
    struct.pack_into('<QQQ', bmp, 0x20, 0x3000, 2, 16)
    bmp[0x38:0x3a] = bytes([0b00001010, 0])
    return bytes(h) + bytes(bmp) + page('physical page 1 ') + page('physical page 3 ')


def full32():
    h = bytearray(0x1000)
    struct.pack_into('<4s4sII', h, 0, b'PAGE', b'DUMP', 15, 2600)
    struct.pack_into('<IIII', h, 0x10, 0x185000, 0x80000000, 0x80550000, 0x80560000)
    struct.pack_into('<III', h, 0x20, 0x14c, 1, 0xe2)
    struct.pack_into('<IIII', h, 0x2c, 0, 0, 0, 0)
    h[0x3c:0x5c] = b'fillyfoal'.ljust(32, b'\0')
    struct.pack_into('<BB', h, 0x5c, 1, 0)
    struct.pack_into('<I', h, 0x60, 0x80545000)
    # PHYSICAL_MEMORY_DESCRIPTOR32: two runs of one page.
    struct.pack_into('<IIIIII', h, 0x64, 2, 2, 0x10, 1, 0x20, 1)
    struct.pack_into('<I', h, 0x7d0, 0xc0000005)
    struct.pack_into('<IIIIII', h, 0xf88, 1, 0, 0, 1, 0x100, 0)
    struct.pack_into('<Q', h, 0xfa0, 0x3000)
    struct.pack_into('<QQ', h, 0xfb8, 60 * 10**7, FILETIME)
    return bytes(h) + page('run 0 page 0x10 ') + page('run 1 page 0x20 ')


os.makedirs(out, exist_ok=True)
with open(os.path.join(out, 'bitmap64.dmp'), 'wb') as f:
    f.write(bitmap64())
with open(os.path.join(out, 'full32.dmp'), 'wb') as f:
    f.write(full32())
