"""Writes tests/fixtures/synthetic/android-xml/attr-count-overflow.xml.

The aapt2 layout external/android-xml/main-layout.xml with the first
START_ELEMENT's attributeCount (u16 at body offset 12) raised from 4 to
0xffff: the chunk still holds only 4 attribute records, so a reader must
not walk 65535 records past the chunk's end.

    python3 tests/data/android-xml/attr-overflow.py
"""

import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "tests/fixtures/external/android-xml/main-layout.xml"
OUT = ROOT / "tests/fixtures/synthetic/android-xml/attr-count-overflow.xml"

data = bytearray(SRC.read_bytes())
_, header, size = struct.unpack_from("<HHI", data, 0)
at = header
while at + 8 <= size:
    kind, chunk_header, chunk_size = struct.unpack_from("<HHI", data, at)
    if kind == 0x0102:
        count_at = at + chunk_header + 12
        assert struct.unpack_from("<H", data, count_at)[0] == 4
        struct.pack_into("<H", data, count_at, 0xFFFF)
        break
    at += chunk_size
else:
    raise SystemExit("no START_ELEMENT chunk")
OUT.write_bytes(bytes(data))
print(OUT, len(data))
