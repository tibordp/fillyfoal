"""Writes tests/fixtures/synthetic/jfs/super.img: a 64 KiB JFS stub.

Only the primary (at 32 KiB) and secondary (at 60 KiB) superblocks of a
64 MiB aggregate with 4 KiB blocks are filled in (`struct jfs_superblock`,
jfs_filsys.h / jfs_superblock.h); the aggregate inode map and table they
point to are left empty. The flags are GROUPCOMMIT | DIR_INDEX | LINUX
(0x10200100): what Linux mkfs.jfs sets, without INLINELOG, as the stub has
no log. Usage: python3 tests/data/jfs/super.py OUT
"""

import struct
import sys

img = bytearray(64 * 1024)
sb = bytearray(0xa8)
struct.pack_into(
    "<4sIqIhhIhhII",
    sb,
    0,
    b"JFS1",  # s_magic
    2,  # s_version
    131072,  # s_size, in physical (512-byte) blocks: 64 MiB
    4096,  # s_bsize
    12,  # s_l2bsize
    3,  # s_l2bfactor
    512,  # s_pbsize
    9,  # s_l2pbsize
    0,  # pad
    8192,  # s_agsize
    0x10200100,  # s_flag: GROUPCOMMIT | DIR_INDEX | LINUX
)
struct.pack_into("<I", sb, 0x58, 0x66475DA6)  # s_time: 2024-05-17 13:37:42 UTC
sb[0x88:0x98] = bytes.fromhex("4a465331000040008000000000000003")  # s_uuid
sb[0x98:0xA8] = b"jfsvol".ljust(16, b"\0")  # s_label
img[0x8000:0x8000 + len(sb)] = sb
img[0xF000:0xF000 + len(sb)] = sb
open(sys.argv[1], "wb").write(img)
