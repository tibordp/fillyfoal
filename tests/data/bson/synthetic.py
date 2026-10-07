"""Synthetic BSON fixture with the deprecated element types PyMongo no
longer writes: undefined (0x06), DBPointer (0x0C) and symbol (0x0E), plus
an array whose keys are out of sequence.

    python3 tests/data/bson/synthetic.py

Written from the BSON specification (bsonspec.org).
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "bson", "deprecated.bson")


def cstring(s):
    return s.encode() + b"\x00"


def string(s):
    b = s.encode() + b"\x00"
    return struct.pack("<i", len(b)) + b


def document(elements):
    body = b"".join(bytes([t]) + cstring(name) + value for t, name, value in elements) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


doc = document(
    [
        (0x10, "_id", struct.pack("<i", 7)),
        (0x06, "undefined", b""),
        (0x0C, "pointer", string("db.people") + bytes.fromhex("68e4f2a01a2b3c4d5e000001")),
        (0x0E, "symbol", string("a symbol")),
        (0x04, "odd array", document([(0x10, "0", struct.pack("<i", 1)), (0x10, "5", struct.pack("<i", 2))])),
    ]
)
with open(OUT, "wb") as f:
    f.write(doc)
