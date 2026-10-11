"""Writes tests/fixtures/synthetic/iso9660/multi-extent.iso.

    python3 tests/data/iso9660/multi-extent.py OUT.iso

An ISO 9660 level 3 image with a file recorded in three sections (three
directory records with the same name, MULTI_EXTENT (0x80) set on all but
the last), the way mkisofs and xorriso record files of 4 GiB and more,
here with small sections (2 KiB, 2 KiB, 1000 bytes) so the image stays
small. The sections are not stored in order: the second one comes last on
the image, so the content is only right if the sections are joined in
record order. Written from ECMA-119; no tool writes multi-extent files
this small.
"""

import struct
import sys

SECTOR = 2048


def both16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)


def both32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)


DATE = bytes([123, 11, 14, 22, 13, 20, 0])  # 2023-11-14 22:13:20 UTC


def record(extent, size, flags, name):
    pad = 1 if len(name) % 2 == 0 else 0
    length = 33 + len(name) + pad
    r = bytes([length, 0]) + both32(extent) + both32(size) + DATE
    r += bytes([flags, 0, 0]) + both16(1) + bytes([len(name)]) + name
    return r + bytes(pad)


def text(tag, n):
    out = b""
    i = 0
    while len(out) < n:
        out += b"%s line %04d\n" % (tag, i)
        i += 1
    return out[:n]


def main():
    out = sys.argv[1]
    # Layout: 16 system sectors, PVD (16), terminator (17), path tables
    # (18, 19), root directory (20), file data from 21.
    root = 20
    sections = [text(b"section 1", 2048), text(b"section 2", 2048), text(b"section 3", 1000)]
    small = b"a small file\n"
    # On the image: section 1 at 21, section 3 at 22, small at 23,
    # section 2 at 24.
    where = [21, 24, 22]
    small_at = 23
    total = 25
    img = bytearray(total * SECTOR)
    for data, at in zip(sections, where):
        img[at * SECTOR : at * SECTOR + len(data)] = data
    img[small_at * SECTOR : small_at * SECTOR + len(small)] = small

    d = record(root, SECTOR, 2, b"\x00") + record(root, SECTOR, 2, b"\x01")
    for i, (data, at) in enumerate(zip(sections, where)):
        flags = 0x80 if i < len(sections) - 1 else 0
        d += record(at, len(data), flags, b"BIG.BIN;1")
    d += record(small_at, len(small), 0, b"SMALL.TXT;1")
    img[root * SECTOR : root * SECTOR + len(d)] = d

    path_l = bytes([1, 0]) + struct.pack("<IH", root, 1) + b"\x00\x00"
    path_m = bytes([1, 0]) + struct.pack(">IH", root, 1) + b"\x00\x00"
    img[18 * SECTOR : 18 * SECTOR + len(path_l)] = path_l
    img[19 * SECTOR : 19 * SECTOR + len(path_m)] = path_m

    pvd = bytearray(SECTOR)
    pvd[0:7] = b"\x01CD001\x01"
    pvd[8:40] = b"LINUX".ljust(32)
    pvd[40:72] = b"MULTI_EXTENT".ljust(32)
    pvd[80:88] = both32(total)
    pvd[120:124] = both16(1)
    pvd[124:128] = both16(1)
    pvd[128:132] = both16(SECTOR)
    pvd[132:140] = both32(len(path_l))
    pvd[140:144] = struct.pack("<I", 18)
    pvd[148:152] = struct.pack(">I", 19)
    pvd[156:190] = record(root, SECTOR, 2, b"\x00")
    pvd[190:813] = b" " * 623
    stamp = b"2023111422132000\x00"
    for at in (813, 830):
        pvd[at : at + 17] = stamp
    pvd[847:864] = b"0" * 16 + b"\x00"
    pvd[864:881] = b"0" * 16 + b"\x00"
    pvd[881] = 1
    img[16 * SECTOR : 17 * SECTOR] = pvd
    img[17 * SECTOR : 17 * SECTOR + 7] = b"\xffCD001\x01"
    open(out, "wb").write(img)


main()
