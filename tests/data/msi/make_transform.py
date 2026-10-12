"""Writes tests/fixtures/synthetic/msi/transform.mst: a minimal Windows
Installer transform (root CLSID {000C1082-0000-0000-C000-000000000046})
with its own string pool and a Property table stream holding one changed
row as transforms store it (a column mask, then the row's values), and an
embedded transform storage the way patches carry them. The table data is
plausible, not produced by Windows: it pins that transform tables are not
decoded column by column with a package's schema.

    python3 tests/data/msi/make_transform.py <out>
"""

import os
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cfb"))
import cfbwriter  # noqa: E402

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def msi_name(name, table=True):
    """MSI's stream name encoding: two base-64 characters per code point."""
    out = "䡀" if table else ""
    i = 0
    while i < len(name):
        a = ALPHABET.index(name[i])
        if i + 1 < len(name) and name[i + 1] in ALPHABET:
            b = ALPHABET.index(name[i + 1])
            out += chr(0x3800 + a + (b << 6))
            i += 2
        else:
            out += chr(0x4800 + a)
            i += 1
    return out


strings = [b"ProductVersion", b"2.0.0"]
pool = struct.pack("<I", 1252) + b"".join(struct.pack("<HH", len(s), 1) for s in strings)
data = b"".join(strings)
# One Property row: mask 0x3 (both columns), Property = string 1, Value = 2.
row = struct.pack("<HHH", 0x0003, 1, 2)

TRANSFORM_CLSID = struct.pack("<IHH", 0x000C1082, 0, 0) + bytes([0xC0, 0, 0, 0, 0, 0, 0, 0x46])
inner = {
    msi_name("_StringPool"): pool,
    msi_name("_StringData"): data,
    msi_name("Property"): row,
}
cfbwriter.write(sys.argv[1], {
    msi_name("_StringPool"): pool,
    msi_name("_StringData"): data,
    msi_name("Property"): row,
    "#Embedded": inner,
}, root_clsid=TRANSFORM_CLSID)
