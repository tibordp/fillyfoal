"""Synthetic Unreal Engine pak footers (FPakInfo) for the newer versions:

- v8a.pak: version 8 with four compression method names (magic 172 bytes
  from the end).
- v9.pak: version 9 (FrozenIndex) with the frozen-index byte (205).
- v11.pak: version 11 with five compression method names (204).

    python3 tests/data/unreal-pak/synthetic.py

Written from FPakInfo::Serialize in UE4/UE5's IPlatformFilePak.h (and
repak's footer reader): from v7 the encryption key GUID and from v4 the
encrypted-index byte come before the magic; then version, index offset and
size, the SHA-1 of the index, the frozen-index byte (v9 only) and, from v8,
32-byte compression method names. Data and index are placeholders.
"""

import hashlib
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "unreal-pak")


def fstring(s):
    b = s.encode() + b"\0"
    return struct.pack("<i", len(b)) + b


def pak(version, names, frozen=False):
    data = b"fillyfoal pak payload\n" * 3
    index = fstring("../../../Game/") + struct.pack("<I", 0)
    info = b"\x11" * 16  # encryption key GUID
    info += b"\0"  # encrypted index
    info += struct.pack("<IIQQ", 0x5A6F12E1, version, len(data), len(index))
    info += hashlib.sha1(index).digest()
    if frozen:
        info += b"\0"
    for name in names:
        info += name.encode().ljust(32, b"\0")
    return data + index + info


def main():
    os.makedirs(OUT, exist_ok=True)
    files = {
        "v8a.pak": pak(8, ["Zlib", "", "", ""]),
        "v9.pak": pak(9, ["Zlib", "Oodle", "", "", ""], frozen=True),
        "v11.pak": pak(11, ["Zlib", "Oodle", "", "", ""]),
    }
    for name, content in files.items():
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(content)


if __name__ == "__main__":
    main()
