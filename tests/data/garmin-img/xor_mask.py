"""Writes tests/fixtures/synthetic/garmin-img/xor-masked.img: our
gmapsupp.img with every byte XORed with a mask, as Garmin IMG files store
it in their first byte (which is 0 before masking).

    python3 tests/data/garmin-img/xor_mask.py tests/fixtures/synthetic/garmin-img/gmapsupp.img tests/fixtures/synthetic/garmin-img/xor-masked.img
"""

import sys

MASK = 0x96

src, dst = sys.argv[1:3]
data = open(src, "rb").read()
assert data[0] == 0
open(dst, "wb").write(bytes(b ^ MASK for b in data))
