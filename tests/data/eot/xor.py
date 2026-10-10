"""Writes tests/fixtures/synthetic/eot/xor-obfuscated.eot: our
fillyfoal-sans.eot with the TTEMBED_XORENCRYPTDATA flag (0x10000000) set
and its font data, which ends the file, XORed with 0x50.

    python3 tests/data/eot/xor.py tests/fixtures/synthetic/eot/fillyfoal-sans.eot tests/fixtures/synthetic/eot/xor-obfuscated.eot
"""

import struct
import sys

src, dst = sys.argv[1:3]
data = bytearray(open(src, "rb").read())
eot_size, font_size, _version, flags = struct.unpack_from("<4I", data)
assert eot_size == len(data) and flags & 0x10000004 == 0
struct.pack_into("<I", data, 12, flags | 0x10000000)
start = len(data) - font_size
data[start:] = bytes(b ^ 0x50 for b in data[start:])
open(dst, "wb").write(bytes(data))
