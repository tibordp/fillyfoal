"""Writes tests/fixtures/synthetic/hdf4/raster.hdf: an HDF4 file with file
and data annotations, an 8-bit raster with palette (RI8/ID8/IP8) and a
24-bit raster image group (RIG/ID/RI). Built byte by byte from our memory
of the HDF4 layouts (pyhdf has no GR or AN interface), so it is synthetic.

python3 tests/data/hdf4/synthetic.py   (from the repository root)
"""

import struct

objects = []  # (tag, ref, bytes)


def add(tag, ref, data):
    objects.append((tag, ref, data))


version = struct.pack(">III", 4, 2, 15) + b"HDF Version 4.2 Release 15 (synthetic)".ljust(80, b"\0")
add(30, 1, version)
add(100, 1, b"fillyfoal raster sample")
add(101, 1, b"Two small images and their annotations.")
# 8-bit image, 4x2, with a grey palette.
add(200, 1, struct.pack(">HH", 4, 2))
add(201, 1, bytes(b for i in range(256) for b in (i, i, i)))
add(202, 1, bytes(range(0, 64, 8)))
add(104, 1, struct.pack(">HH", 202, 1) + b"grey ramp")
# 24-bit image group: 2x2 RGB, pixel interlace, uint8 components.
add(106, 3, bytes([1, 21, 8, 1]))
add(300, 2, struct.pack(">iiHHhhHH", 2, 2, 106, 3, 3, 0, 0, 0))
add(302, 2, bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255]))
add(306, 2, struct.pack(">HHHH", 300, 2, 302, 2))
add(105, 1, struct.pack(">HH", 306, 2) + b"red, green, blue and white pixels")

slots = len(objects) + 2  # two empty descriptors
header = 4 + 6 + 12 * slots
dds = []
data = b""
for tag, ref, body in objects:
    dds.append(struct.pack(">HHII", tag, ref, header + len(data), len(body)))
    data += body
for _ in range(slots - len(objects)):
    dds.append(struct.pack(">HHII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF))
out = b"\x0e\x03\x13\x01" + struct.pack(">HI", slots, 0) + b"".join(dds) + data
with open("tests/fixtures/synthetic/hdf4/raster.hdf", "wb") as f:
    f.write(out)
