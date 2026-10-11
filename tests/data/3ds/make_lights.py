"""A 3DS scene with a spotlight and a camera, built chunk by chunk.

    python3 tests/data/3ds/make_lights.py OUT.3ds

From the chunk layout lib3ds reads (lib3ds_light.c, lib3ds_camera.c):
- Light (0x4600): position (3 floats), then sub-chunks: Spotlight
  (0x4610: target (3 floats), hotspot, falloff, then sub-chunks) and
  Light off (0x4620, empty).
- Camera (0x4700): position, target (3 floats each), bank angle and lens
  (floats), then sub-chunks: Camera ranges (0x4720, near and far).
Synthetic: written by this script.
"""

import struct
import sys


def chunk(cid, payload=b"", *children):
    body = payload + b"".join(children)
    return struct.pack("<HI", cid, 6 + len(body)) + body


def floats(*v):
    return struct.pack(f"<{len(v)}f", *v)


light = chunk(
    0x4600,
    floats(1.0, 2.0, 3.0),
    chunk(0x4610, floats(0.0, 0.0, 0.0, 30.0, 45.0)),
    chunk(0x4620),
)
camera = chunk(
    0x4700,
    floats(10.0, 10.0, 10.0, 0.0, 0.0, 0.0, 0.0, 35.0),
    chunk(0x4720, floats(0.5, 100.0)),
)
editor = chunk(
    0x3D3D,
    b"",
    chunk(0x3D3E, struct.pack("<I", 3)),
    chunk(0x4000, b"Lamp\0", light),
    chunk(0x4000, b"Camera\0", camera),
)
data = chunk(0x4D4D, b"", chunk(0x0002, struct.pack("<I", 3)), editor)
with open(sys.argv[1], "wb") as f:
    f.write(data)
