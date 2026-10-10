"""Writes a small differencing VHD (synthetic: QEMU reads but does not
create them): footer copy, dynamic header with a parent name and two
parent locators (W2ku absolute, W2ru relative), a BAT with one allocated
32 KiB block whose sector bitmap marks only some sectors present, the
locator data, and the footer.

usage: python3 vhd-diff.py <out.vhd>
"""

import struct
import sys

SECTOR = 512
BLOCK = 32 * 1024
DISK = 256 * 1024
EPOCH = 946684800
STAMP = 1700000000 - EPOCH
PARENT_ID = bytes.fromhex("0123456789abcdef0123456789abcdef")
UNIQUE_ID = bytes.fromhex("fedcba9876543210fedcba9876543210")


def checksum(b):
    return (~sum(b)) & 0xFFFFFFFF


def footer():
    f = bytearray(
        struct.pack(
            ">8sIIQI4sI4sQQHBBII16sB",
            b"conectix",
            2,
            0x00010000,
            SECTOR,  # dynamic header right after the footer copy
            STAMP,
            b"fill",
            0x00010000,
            b"Wi2k",
            DISK,
            DISK,
            8,
            4,
            16,
            4,  # differencing
            0,
            UNIQUE_ID,
            0,
        ).ljust(SECTOR, b"\0")
    )
    struct.pack_into(">I", f, 64, checksum(f))
    return bytes(f)


def main():
    parent_abs = "C:\\vms\\parent.vhd".encode("utf-16-le")
    parent_rel = ".\\parent.vhd".encode("utf-16-le")
    bat_at = 3 * SECTOR
    entries = DISK // BLOCK
    loc1 = 4 * SECTOR
    loc2 = 5 * SECTOR
    block1 = 6 * SECTOR
    header = bytearray(
        struct.pack(
            ">8sQQIII I16sII",
            b"cxsparse",
            0xFFFFFFFFFFFFFFFF,
            bat_at,
            0x00010000,
            entries,
            BLOCK,
            0,
            PARENT_ID,
            STAMP,
            0,
        )
    )
    header += "parent.vhd".encode("utf-16-be").ljust(512, b"\0")
    locators = [
        (b"W2ku", 1, len(parent_abs), loc1),
        (b"W2ru", 1, len(parent_rel), loc2),
    ]
    for code, space, length, offset in locators:
        header += struct.pack(">4sIIIQ", code, space, length, 0, offset)
    header += b"\0" * (24 * (8 - len(locators)))
    header += b"\0" * 256
    assert len(header) == 1024
    struct.pack_into(">I", header, 36, checksum(header))

    bat = [0xFFFFFFFF] * entries
    bat[1] = block1 // SECTOR
    out = bytearray(footer())
    out += header
    out += struct.pack(f">{entries}I", *bat).ljust(SECTOR, b"\xff")
    out += parent_abs.ljust(SECTOR, b"\0")
    out += parent_rel.ljust(SECTOR, b"\0")
    # Sector bitmap: sectors 0-7 and 9 present (most significant bit first).
    bitmap = bytes([0xFF, 0x40]).ljust(SECTOR, b"\0")
    data = bytearray(BLOCK)
    for s in list(range(8)) + [9]:
        data[s * SECTOR:(s + 1) * SECTOR] = bytes([0xA0 + s]) * SECTOR
    out += bitmap + data
    out += footer()
    open(sys.argv[1], "wb").write(out)


main()
