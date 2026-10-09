"""Copies an ICC profile and fills in its MD5 profile ID (ICC.1:2022 7.2.18:
the MD5 of the profile with the flags, rendering intent and profile ID
fields zeroed).

    python3 tests/data/icc/add_id.py tests/fixtures/external/icc/lcms-srgb.icc \
        tests/fixtures/synthetic/icc/lcms-srgb-id.icc
"""

import hashlib
import sys

data = bytearray(open(sys.argv[1], "rb").read())
masked = bytearray(data)
for start, end in ((44, 48), (64, 68), (84, 100)):
    masked[start:end] = bytes(end - start)
data[84:100] = hashlib.md5(masked).digest()
with open(sys.argv[2], "wb") as out:
    out.write(data)
