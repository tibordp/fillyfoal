"""Writes tests/fixtures/synthetic/mat/vars.mat, a little-endian MAT-file
Level 5 built element by element from the format description.

    python3 -I make_vars.py tests/fixtures/synthetic/mat/vars.mat

Plain miMATRIX elements (double, char as miUTF16, a cell holding a double
and a uint8 with a zero, a struct with a miUTF8 char field), then two
miCOMPRESSED elements back to back (a logical int32 array and a char
array stored as miUINT16, as MATLAB writes char). Uncompressed data is
padded to 8 bytes; compressed elements are not padded, like MATLAB, SciPy
and matio write them.
"""

import struct
import sys
import zlib

MI_INT8, MI_UINT8, MI_INT16, MI_UINT16, MI_INT32, MI_UINT32 = 1, 2, 3, 4, 5, 6
MI_DOUBLE, MI_MATRIX, MI_COMPRESSED, MI_UTF8, MI_UTF16 = 9, 14, 15, 16, 17
CELL, STRUCT, CHAR, DOUBLE, UINT8, INT32 = 1, 2, 4, 6, 9, 12
LOGICAL = 0x02


def element(kind, data, small=True):
    if small and len(data) <= 4 and kind != MI_MATRIX:
        return struct.pack("<HH", kind, len(data)) + data.ljust(4, b"\0")
    pad = b"\0" * (-len(data) % 8)
    return struct.pack("<II", kind, len(data)) + data + pad


def matrix(cls, dims, name, *parts, flags=0):
    body = element(MI_UINT32, struct.pack("<II", cls | flags << 8, 0))
    body += element(MI_INT32, struct.pack(f"<{len(dims)}i", *dims), small=False)
    body += element(MI_INT8, name.encode())
    for p in parts:
        body += p
    return element(MI_MATRIX, body)


def compressed(data):
    z = zlib.compress(data, 6)
    return struct.pack("<II", MI_COMPRESSED, len(z)) + z


def doubles(*v):
    return element(MI_DOUBLE, struct.pack(f"<{len(v)}d", *v))


header = (
    b"MATLAB 5.0 MAT-file, Platform: fillyfoal, Created on: Thu Jan  1 00:00:00 2026"
).ljust(116, b" ")
header += b"\0" * 8 + struct.pack("<H", 0x0100) + b"IM"

out = header
out += matrix(DOUBLE, [2, 3], "x", doubles(1, 2, 3, 4, 5, 6))
out += matrix(CHAR, [1, 5], "greeting", element(MI_UTF16, "hello".encode("utf-16-le")))
out += matrix(
    CELL,
    [1, 2],
    "c",
    matrix(DOUBLE, [1, 1], "", doubles(3.5)),
    matrix(UINT8, [1, 3], "", element(MI_UINT8, bytes([7, 0, 8]))),
)
out += matrix(
    STRUCT,
    [1, 1],
    "st",
    element(MI_INT32, struct.pack("<i", 8)),
    element(MI_INT8, b"a".ljust(8, b"\0") + b"b".ljust(8, b"\0")),
    matrix(DOUBLE, [1, 1], "", doubles(1)),
    matrix(CHAR, [1, 2], "", element(MI_UTF8, b"hi")),
)
out += compressed(
    matrix(
        INT32,
        [1, 4],
        "z",
        element(MI_INT32, struct.pack("<4i", -1, 0, 1, 2)),
        flags=LOGICAL,
    )
)
out += compressed(matrix(CHAR, [1, 3], "w", element(MI_UINT16, "héj".encode("utf-16-le"))))

open(sys.argv[1], "wb").write(out)
