"""Zeroes the app id in every com.apple.provenance attribute of an HFS+ image.

The macOS sandbox tags files written by a sandboxed process with this
attribute (two version bytes, a flag byte, then an 8-byte id of the writing
app in the machine's execution policy database) and will not let it be
removed. The id says something about the machine that built the image, so it
is replaced by zeros; the attribute records stay as written.
"""

import re
import sys

path = sys.argv[1]
d = bytearray(open(path, "rb").read())
key = "com.apple.provenance".encode("utf-16-be")
# HFSPlusAttrData after the key: type 0x10, 8 reserved bytes, size 11.
head = bytes.fromhex("00000010 00000000 00000000 0000000b")
n = 0
for m in re.finditer(re.escape(key), d):
    at = m.end()
    if d[at:at + 16] == head:
        d[at + 19:at + 27] = bytes(8)
        n += 1
assert n > 0, "no provenance attribute found"
open(path, "wb").write(d)
print(f"scrubbed {n} provenance attributes")
