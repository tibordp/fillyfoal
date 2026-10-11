"""Writes tests/fixtures/synthetic/ms-propstore/named.propstore, a serialized
property store built from MS-PROPSTORE 2.2-2.3 and MS-OLEPS 2.15: a storage
keyed by integer ID (System.ItemNameDisplay, System.FileAttributes, a vector
of strings) and one keyed by name (D5CDD505-2E9C-101B-9397-08002B2CF9AE).

    python3 tests/data/ms-propstore/make.py
"""

import os
import struct
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "ms-propstore", "named.propstore")


def pad4(b):
    return b + bytes(-len(b) % 4)


def lpwstr(s):
    return pad4(struct.pack("<I", len(s) + 1) + (s + "\0").encode("utf-16-le"))


def typed(vt, body):
    return struct.pack("<HH", vt, 0) + body


def by_id(pid, value):
    return struct.pack("<IIB", 9 + len(value), pid, 0) + value


def by_name(name, value):
    raw = (name + "\0").encode("utf-16-le")
    return struct.pack("<IIB", 9 + len(raw) + len(value), len(raw), 0) + raw + value


def storage(fmtid, values):
    body = uuid.UUID(fmtid).bytes_le + b"".join(values) + struct.pack("<I", 0)
    return struct.pack("<I", 8 + len(body)) + b"1SPS" + body


store = (
    storage(
        "B725F130-47EF-101A-A5F1-02608C9EEBAC",
        [
            by_id(10, typed(0x1F, lpwstr("notes.txt"))),
            by_id(13, typed(0x13, struct.pack("<I", 0x20))),
            by_id(2, typed(0x101F, struct.pack("<I", 2) + lpwstr("Documents") + lpwstr("fillyfoal"))),
        ],
    )
    + storage(
        "D5CDD505-2E9C-101B-9397-08002B2CF9AE",
        [
            by_name("fillyfoal.note", typed(0x1F, lpwstr("hello"))),
            by_name("fillyfoal.count", typed(0x03, struct.pack("<i", 7))),
        ],
    )
    + struct.pack("<I", 0)
)
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "wb") as f:
    f.write(store)
