"""Writes tests/fixtures/synthetic/n64/test.n64: our test.z64 (big-endian,
the console's order) with each 32-bit word's bytes reversed, the
"little-endian" .n64 dump order.

    python3 tests/data/n64/swap.py tests/fixtures/synthetic/n64/test.z64 tests/fixtures/synthetic/n64/test.n64
"""

import sys

src, dst = sys.argv[1:3]
data = open(src, "rb").read()
assert len(data) % 4 == 0
open(dst, "wb").write(b"".join(data[i : i + 4][::-1] for i in range(0, len(data), 4)))
