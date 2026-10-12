"""Zeroes the app id in every com.apple.provenance attribute of an APFS image.

The macOS sandbox tags files written by a sandboxed process with this
attribute (two version bytes, a flag byte, then an 8-byte id of the writing
app in the machine's execution policy database) and will not let it be
removed. The id says something about the machine that built the image, so it
is replaced by zeros in every embedded attribute value (`j_xattr_val_t`:
flags XATTR_DATA_EMBEDDED, length 11), and the Fletcher-64 checksum of each
4 KiB object touched is recomputed (only where it was valid before).
"""

import re
import sys

BLOCK = 4096


def fletcher64(data):
    lo = hi = 0
    for i in range(0, len(data), 4):
        lo = (lo + int.from_bytes(data[i:i + 4], "little")) % 0xFFFFFFFF
        hi = (hi + lo) % 0xFFFFFFFF
    c1 = 0xFFFFFFFF - ((lo + hi) % 0xFFFFFFFF)
    c2 = 0xFFFFFFFF - ((lo + c1) % 0xFFFFFFFF)
    return (c2 << 32) | c1


def valid(d, b):
    blk = d[b * BLOCK:(b + 1) * BLOCK]
    return int.from_bytes(blk[:8], "little") == fletcher64(blk[8:])


path = sys.argv[1]
d = bytearray(open(path, "rb").read())
value = re.compile(re.escape(bytes.fromhex("0200 0b00 010200")))
touched = {}
for m in value.finditer(d):
    b = m.start() // BLOCK
    if b not in touched:
        touched[b] = valid(d, b)
    d[m.end():m.end() + 8] = bytes(8)
fixed = 0
for b, was_valid in sorted(touched.items()):
    if was_valid:
        blk = d[b * BLOCK:(b + 1) * BLOCK]
        d[b * BLOCK:b * BLOCK + 8] = fletcher64(blk[8:]).to_bytes(8, "little")
        assert valid(d, b)
        fixed += 1
assert touched, "no provenance attribute found"
open(path, "wb").write(d)
print(f"scrubbed provenance attributes in {len(touched)} blocks, {fixed} checksums fixed")
