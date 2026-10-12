"""Writes tests/fixtures/synthetic/msi/transform.mst: a minimal Windows
Installer transform (root CLSID {000C1082-0000-0000-C000-000000000046})
with its own string pool and table streams stored as transforms store
them, row by row, each row a 16-bit column mask and the values it gives
(Wine's msi_table_load_transform): with bit 0 set the high byte counts the
leading columns of a whole row; otherwise bit i marks column i as given,
keys always being given; mask 0 deletes the row with the given keys.

It adds a table (a _Tables row, three _Columns rows with their numbers
and types, two whole rows), changes ProductVersion in the Property table
and deletes a property; an embedded transform storage carries the same
streams, the way patches carry transforms. No tool at hand writes
transforms (msitools only applies them), so the layout follows Wine's
reader; the data is plausible, not produced by Windows.

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


strings = [b"ProductVersion", b"2.0.0", b"Fillyfoal", b"Key", b"Count", b"Note",
           b"first", b"second", b"a note", b"OldProperty"]
pool = struct.pack("<I", 1252) + b"".join(struct.pack("<HH", len(s), 1) for s in strings)
data = b"".join(strings)
S = {s.decode(): i for i, s in enumerate(strings, start=1)}


def i16(v):
    return struct.pack("<H", (v + 0x8000) & 0xFFFF)


def ref(name):
    return struct.pack("<H", S[name])


def whole(*cells):
    """A whole row: bit 0 set, the number of columns in the high byte."""
    return struct.pack("<H", (len(cells) << 8) | 1) + b"".join(cells)


# _Tables: insert Fillyfoal. _Columns (Table, Number, Name, Type): its
# columns, a key string(72), a non-null int16 and a nullable localizable
# string(0).
tables = whole(ref("Fillyfoal"))
columns = (
    whole(ref("Fillyfoal"), i16(1), ref("Key"), i16(0x2D48))
    + whole(ref("Fillyfoal"), i16(2), ref("Count"), i16(0x0502))
    + whole(ref("Fillyfoal"), i16(3), ref("Note"), i16(0x1F00))
)
rows = whole(ref("first"), i16(7), ref("a note")) + whole(ref("second"), i16(-3), b"\0\0")
# Property: set Value of ProductVersion (mask bit 1; the key is implied),
# then delete OldProperty (mask 0, the key only).
prop = struct.pack("<H", 0x0002) + ref("ProductVersion") + ref("2.0.0")
prop += struct.pack("<H", 0) + ref("OldProperty")

TRANSFORM_CLSID = struct.pack("<IHH", 0x000C1082, 0, 0) + bytes([0xC0, 0, 0, 0, 0, 0, 0, 0x46])
streams = {
    msi_name("_StringPool"): pool,
    msi_name("_StringData"): data,
    msi_name("_Tables"): tables,
    msi_name("_Columns"): columns,
    msi_name("Fillyfoal"): rows,
    msi_name("Property"): prop,
}
cfbwriter.write(sys.argv[1], {**streams, "#Embedded": dict(streams)}, root_clsid=TRANSFORM_CLSID)
