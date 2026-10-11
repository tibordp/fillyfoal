"""A hand-assembled MP4 whose sample table carries `sgpd` boxes in every
version ISO/IEC 14496-12 §8.9.3 defines, with matching `sbgp` boxes:

- version 0 `roll` (entry size known from the grouping type),
- version 1 `roll` with default_length 2,
- version 1 `rap ` with default_length 0 (each entry has its own length),
- version 2 `sync` with default_length 1 and a default group description
  index.

FFmpeg writes version 1 only, hence the hand-made file. One video track of
three 4-byte samples, no real media.

    python3 tests/data/mp4/sample-groups.py

Writes `tests/fixtures/synthetic/mp4/sample-groups.mp4`.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "mp4", "sample-groups.mp4")


def box(kind, body):
    return struct.pack(">I", 8 + len(body)) + kind + body


def full(kind, version, flags, body):
    return box(kind, struct.pack(">I", (version << 24) | flags) + body)


def u32(*v):
    return struct.pack(">" + "I" * len(v), *v)


MATRIX = u32(0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)
SAMPLES = 3
SAMPLE = b"\0\0\0\0"


def stbl(mdat_data_offset):
    stsd = full(b"stsd", 0, 0, u32(0))
    stts = full(b"stts", 0, 0, u32(1, SAMPLES, 1000))
    stsc = full(b"stsc", 0, 0, u32(1, 1, SAMPLES, 1))
    stsz = full(b"stsz", 0, 0, u32(len(SAMPLE), SAMPLES))
    stco = full(b"stco", 0, 0, u32(1, mdat_data_offset))
    # Version 0: no default_length; a roll entry is an int16.
    sgpd0 = full(b"sgpd", 0, 0, b"roll" + u32(1) + struct.pack(">h", -1))
    # Version 1: default_length 2.
    sgpd1 = full(b"sgpd", 1, 0, b"prol" + u32(2) + u32(2) + struct.pack(">hh", 1, 2))
    # Version 1, default_length 0: description_length before each entry.
    sgpd1v = full(b"sgpd", 1, 0, b"rap " + u32(0) + u32(2) + u32(1) + b"\x82" + u32(1) + b"\x00")
    # Version 2: default_length, then default_group_description_index.
    sgpd2 = full(b"sgpd", 2, 0, b"sync" + u32(1) + u32(1) + u32(2) + b"\x13\x01")
    sbgp_roll = full(b"sbgp", 0, 0, b"roll" + u32(1) + u32(SAMPLES, 1))
    sbgp_sync = full(b"sbgp", 0, 0, b"sync" + u32(2) + u32(1, 1, 2, 2))
    return box(b"stbl", stsd + stts + stsc + stsz + stco + sgpd0 + sgpd1 + sgpd1v + sgpd2
               + sbgp_roll + sbgp_sync)


def moov(mdat_data_offset):
    duration = SAMPLES * 1000
    mvhd = full(b"mvhd", 0, 0, u32(0, 0, 25000, duration, 0x10000) + struct.pack(">H", 0x100)
                + b"\0" * 10 + MATRIX + b"\0" * 24 + u32(2))
    tkhd = full(b"tkhd", 0, 3, u32(0, 0, 1, 0, duration) + b"\0" * 8 + struct.pack(">hhH", 0, 0, 0)
                + b"\0\0" + MATRIX + u32(16 << 16, 16 << 16))
    mdhd = full(b"mdhd", 0, 0, u32(0, 0, 25000, duration) + struct.pack(">HH", 0x55C4, 0))
    hdlr = full(b"hdlr", 0, 0, u32(0) + b"vide" + b"\0" * 12 + b"VideoHandler\0")
    vmhd = full(b"vmhd", 0, 1, b"\0" * 8)
    dref = full(b"dref", 0, 0, u32(1) + full(b"url ", 0, 1, b""))
    minf = box(b"minf", vmhd + box(b"dinf", dref) + stbl(mdat_data_offset))
    trak = box(b"trak", tkhd + box(b"mdia", mdhd + hdlr + minf))
    return box(b"moov", mvhd + trak)


ftyp = box(b"ftyp", b"isom" + u32(0x200) + b"isomiso2mp41")
size = len(moov(0))
mdat_data_offset = len(ftyp) + size + 8
data = ftyp + moov(mdat_data_offset) + box(b"mdat", SAMPLE * SAMPLES)
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "wb") as f:
    f.write(data)
print(os.path.relpath(OUT), len(data))
