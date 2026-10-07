"""Writes tests/fixtures/synthetic/capnp/far-and-caps.bin by hand from the
encoding specification: what pycapnp's builder does not produce for small
messages (a double-far landing pad, a capability pointer, a list of VOID).

    python3 synthetic.py
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "capnp", "far-and-caps.bin")


def struct_ptr(offset, data, ptrs):
    return ((offset << 2) & 0xFFFFFFFF) | (data << 32) | (ptrs << 48)


def list_ptr(offset, elem, count):
    return ((offset << 2) & 0xFFFFFFFF) | 1 | ((count << 3 | elem) << 32)


def far_ptr(double, offset, segment):
    return 2 | (4 if double else 0) | (offset << 3) | (segment << 32)


def cap_ptr(index):
    return 3 | (index << 32)


seg0 = [
    struct_ptr(0, 1, 5),  # root: 1 data word, 5 pointers
    0x0000_0001_0000_002A,  # data
    far_ptr(True, 0, 1),  # pointer 0: double far, pad at segment 1 word 0
    cap_ptr(3),  # pointer 1: capability 3
    list_ptr(0, 0, 5),  # pointer 2: 5 VOIDs
    list_ptr(1, 5, 2),  # pointer 3: 2 EIGHT_BYTES at word 7
    0,  # pointer 4: null
    struct.unpack("<Q", struct.pack("<q", -5))[0],
    struct.unpack("<Q", struct.pack("<d", 2.5))[0],
]
seg1 = [
    far_ptr(False, 2, 1),  # landing pad: content at segment 1 word 2
    struct_ptr(0, 1, 1),  # tag: 1 data word, 1 pointer
    0x1234,
    list_ptr(0, 2, 3),  # text "hi"
    int.from_bytes(b"hi\0".ljust(8, b"\0"), "little"),
]
table = struct.pack("<III", 1, len(seg0), len(seg1)) + b"\0" * 4
data = table + b"".join(struct.pack("<Q", w) for w in seg0 + seg1)
with open(OUT, "wb") as f:
    f.write(data)
