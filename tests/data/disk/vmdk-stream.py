"""Writes a stream-optimized VMDK the way VMware tools lay it out: the grain
directory at the end (gdOffset = GD_AT_END), every grain compressed behind
a grain marker, then GT, GD, footer and end-of-stream markers (VMware
Virtual Disk Format 1.1, section "Stream-Optimized Compressed Sparse
Extents"). QEMU's own streamOptimized writer keeps the tables up front, so
this one is synthetic; `qemu-img compare` checks it against its source.

usage: python3 vmdk-stream.py <raw image> <out.vmdk>
"""

import struct
import sys
import zlib

SECTOR = 512
GRAIN_SECTORS = 128  # 64 KiB grains
GTES = 512
GD_AT_END = 0xFFFFFFFFFFFFFFFF


def header(capacity, gd_offset, desc_sectors):
    h = struct.pack(
        "<4sIIQQQQIQQQB4sH",
        b"KDMV",
        3,  # version
        0x30001,  # valid newline test, compressed grains, markers
        capacity,
        GRAIN_SECTORS,
        1,  # descriptor offset
        desc_sectors,
        GTES,
        0,  # no redundant grain directory
        gd_offset,
        1 + desc_sectors,  # overhead: header and descriptor
        0,
        b"\n \r\n",
        1,  # deflate
    )
    return h.ljust(SECTOR, b"\0")


def marker(sectors, kind):
    return struct.pack("<QII", sectors, 0, kind).ljust(SECTOR, b"\0")


def pad(b):
    return b + b"\0" * (-len(b) % SECTOR)


def main():
    raw = open(sys.argv[1], "rb").read()
    capacity = len(raw) // SECTOR
    descriptor = (
        "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n"
        'createType="streamOptimized"\n\n# Extent description\n'
        f'RDONLY {capacity} SPARSE "stream-markers.vmdk"\n\n'
        "# The Disk Data Base\n#DDB\n\n"
        'ddb.adapterType = "lsilogic"\nddb.virtualHWVersion = "4"\n'
        'ddb.geometry.cylinders = "0"\nddb.geometry.heads = "255"\n'
        'ddb.geometry.sectors = "63"\n'
    ).encode()
    desc = pad(descriptor)
    desc_sectors = len(desc) // SECTOR
    out = bytearray(header(capacity, GD_AT_END, desc_sectors) + desc)
    grains = capacity // GRAIN_SECTORS
    gt = [0] * (((grains + GTES - 1) // GTES) * GTES)
    for g in range(grains):
        data = raw[g * GRAIN_SECTORS * SECTOR:(g + 1) * GRAIN_SECTORS * SECTOR]
        if not any(data):
            continue
        z = zlib.compress(data, 9)
        gt[g] = len(out) // SECTOR
        out += pad(struct.pack("<QI", g * GRAIN_SECTORS, len(z)) + z)
    gd = []
    for t in range(len(gt) // GTES):
        table = gt[t * GTES:(t + 1) * GTES]
        if not any(table):
            gd.append(0)
            continue
        body = pad(struct.pack(f"<{GTES}I", *table))
        out += marker(len(body) // SECTOR, 1)
        gd.append(len(out) // SECTOR)
        out += body
    body = pad(struct.pack(f"<{len(gd)}I", *gd))
    out += marker(len(body) // SECTOR, 2)
    gd_sector = len(out) // SECTOR
    out += body
    out += marker(1, 3)
    out += header(capacity, gd_sector, desc_sectors)
    out += marker(0, 0)
    open(sys.argv[2], "wb").write(out)


main()
