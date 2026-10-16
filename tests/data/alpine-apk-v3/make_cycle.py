"""Synthetic ADB package whose root object refers to itself.

Copies the real `hello-plain.apk` (apk-tools 3.0.7) and points the root
object's `info` slot back at the root object, so expanding the tree must
stop at the cycle. Run from the repository root:

    python3 tests/data/alpine-apk-v3/make_cycle.py
"""

import struct

src = "tests/fixtures/external/alpine-apk-v3/hello-plain.apk"
dst = "tests/fixtures/synthetic/alpine-apk-v3/cycle.apk"

data = bytearray(open(src, "rb").read())
adb = 12  # the ADB block's payload: after the file header and the block tag
root = struct.unpack_from("<I", data, adb + 4)[0]
assert root >> 28 == 0xE, "root is an object"
slots = adb + (root & 0x0FFFFFFF)
# slot 0 is the count; slot 1 is `info`
struct.pack_into("<I", data, slots + 4, root)
open(dst, "wb").write(bytes(data))
