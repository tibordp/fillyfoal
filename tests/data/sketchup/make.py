"""Synthetic SketchUp model, written from memory of the format.

SketchUp is not available here, so this is our own reconstruction: the MFC
CArchive header strings, eight bytes we do not understand, a CVersionMap
object (class name / version pairs up to "End-Of-Version-Map"), a few
objects introduced by MFC new-class tags with made-up payloads and
back-references, and a PNG preview. It locks in the dissector's behaviour;
it is not evidence that real files look exactly like this.

    python3 tests/data/sketchup/make.py
"""

import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "synthetic", "sketchup", "Cube.skp")


def cstring(s):
    """MFC CString, Unicode: FF FEFF, length, UTF-16LE."""
    raw = s.encode("utf-16-le")
    n = len(s)
    if n < 0xFF:
        return b"\xff\xfe\xff" + bytes([n]) + raw
    return b"\xff\xfe\xff\xff" + struct.pack("<H", n) + raw


def new_class(name, schema):
    return b"\xff\xff" + struct.pack("<HH", schema, len(name)) + name.encode("ascii")


def png(w=4, h=4):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    raw = b"".join(b"\0" + b"".join(bytes([0x40 * x, 0x80, 0x40 * y]) for x in range(w)) for y in range(h))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def main():
    d = cstring("SketchUp Model") + cstring("{20.0.373}")
    d += bytes.fromhex("0c7f5ca300000000")  # unknown
    versions = [
        ("CArcCurve", 3), ("CAttributeContainer", 0), ("CComponentDefinition", 11),
        ("CComponentInstance", 3), ("CEdge", 2), ("CEdgeUse", 2), ("CFace", 4),
        ("CLayer", 4), ("CLoop", 1), ("CMaterial", 13), ("CVertex", 0),
    ]
    d += new_class("CVersionMap", 1)
    for name, v in versions:
        d += cstring(name) + struct.pack("<I", v)
    d += cstring("End-Of-Version-Map")
    # Made-up objects. MFC map indices: 1 CVersionMap class, 2 its object,
    # then each new class and object takes the next index.
    d += new_class("CMaterial", 13) + struct.pack("<I", 0xFF8080C0) + cstring("Pony pink")
    d += png()  # the preview, as a scan would meet it
    d += new_class("CVertex", 0) + struct.pack("<ddd", 0.0, 0.0, 0.0)
    d += struct.pack("<H", 0x8000 | 5) + struct.pack("<ddd", 1.0, 0.0, 0.0)  # another CVertex
    d += new_class("CEdge", 2) + struct.pack("<HH", 6, 7)
    d += new_class("CFace", 4) + struct.pack("<I", 1) + struct.pack("<H", 4)
    d += new_class("CLayer", 4) + cstring("Layer0")
    d += b"\0" * 4
    with open(OUT, "wb") as f:
        f.write(d)


if __name__ == "__main__":
    main()
