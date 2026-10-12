"""A minimal compact DEX file (`cdex001`) for
tests/fixtures/synthetic/dex/compact.cdex: two strings, one type and one
class definition, with the string data in the data section and its offsets
counting from data_off, as ART's CompactDexFile reads them
(`DexFile::DataBegin`, compact_dex_file.h).

    python3 tests/data/dex/compact.py
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "dex", "compact.cdex")
NO_INDEX = 0xFFFFFFFF


def string_data(s):
    b = s.encode()
    return bytes([len(s)]) + b + b"\0"


def main():
    strings = ["Lnet/fillyfoal/Compact;", "Compact.java"]
    header_size = 0x88
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings)
    class_defs_off = type_ids_off + 4
    data_off = class_defs_off + 32
    data = b""
    offsets = []
    for s in strings:
        offsets.append(len(data))  # relative to data_off
        data += string_data(s)
    data += b"\0" * (-len(data) % 4)
    file_size = data_off + len(data)

    h = b"cdex001\0"
    h += struct.pack("<I", 0)  # checksum (not checked for compact DEX)
    h += b"\0" * 20  # signature
    h += struct.pack("<III", file_size, header_size, 0x12345678)
    h += struct.pack("<II", 0, 0)  # link
    h += struct.pack("<I", 0)  # map_off: none
    h += struct.pack("<II", len(strings), string_ids_off)
    h += struct.pack("<II", 1, type_ids_off)
    h += struct.pack("<II", 0, 0)  # protos
    h += struct.pack("<II", 0, 0)  # fields
    h += struct.pack("<II", 0, 0)  # methods
    h += struct.pack("<II", 1, class_defs_off)
    h += struct.pack("<II", len(data), data_off)
    h += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)  # compact fields
    assert len(h) == header_size

    body = b"".join(struct.pack("<I", o) for o in offsets)
    body += struct.pack("<I", 0)  # type 0: string 0
    body += struct.pack("<IIIIIIII", 0, 1, NO_INDEX, 0, 1, 0, 0, 0)
    with open(OUT, "wb") as f:
        f.write(h + body + data)


if __name__ == "__main__":
    main()
