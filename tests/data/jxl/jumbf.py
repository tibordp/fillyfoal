"""Writes a synthetic JPEG XL container carrying a JUMBF (C2PA) superbox
twice: as a plain `jumb` box and Brotli-compressed in a `brob` box (ISO/IEC
18181-2 9.1). The codestream is the repository's small-codestream.jxl, the
JUMBF box its c2pa.jumbf.

    uv run --with brotli python3 tests/data/jxl/jumbf.py tests/fixtures/synthetic/jxl/jumbf.jxl
"""

import os
import struct
import sys

import brotli

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "../../fixtures/synthetic")
with open(os.path.join(FIXTURES, "jxl/small-codestream.jxl"), "rb") as f:
    CODESTREAM = f.read()
with open(os.path.join(FIXTURES, "jumbf/c2pa.jumbf"), "rb") as f:
    JUMBF = f.read()
assert JUMBF[4:8] == b"jumb"


def box(kind, payload):
    return struct.pack(">I", 8 + len(payload)) + kind + payload


out = b"".join(
    [
        box(b"JXL ", b"\r\n\x87\n"),
        box(b"ftyp", b"jxl \0\0\0\0jxl "),
        box(b"jxlc", CODESTREAM),
        JUMBF,
        box(b"brob", b"jumb" + brotli.compress(JUMBF[8:], quality=11)),
    ]
)
with open(sys.argv[1], "wb") as f:
    f.write(out)
