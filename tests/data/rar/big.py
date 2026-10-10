"""Writes crates/codec/src/codec/testdata/rar5-text-5m.bin with our test
encoder (`rarenc.py`): the packed data of one RAR 5 file of 5,200,000 bytes
(252 copies of 20,000 bytes of text, each with 8 bytes changed, then 160,000
bytes of text), more than the 4 MiB of history the decoder keeps, for the
checkpoint test in
`crates/codec/src/codec/rar/tests.rs`:

    uv run --with pyppmd==1.3.1 python tests/data/rar/big.py
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "..", "crates", "codec", "src", "codec", "testdata", "rar5-text-5m.bin")
sys.path.insert(0, HERE)

import make  # noqa: E402
import rarenc  # noqa: E402

rng = random.Random(50)
base = make.text(rng, 20_000)
data = bytearray()
for i in range(252):
    part = bytearray(base)
    at = rng.randrange(len(part) - 64)
    part[at : at + 8] = b"%08d" % i
    data += part
# Then fresh text: many short symbols, so the decoder's batches (32K
# symbols each) end past 4 MiB.
data += make.text(rng, 5_200_000 - len(data))
packed = rarenc.compress5([bytes(data)], False, rng, block_tokens=3000)[0]
with open(OUT, "wb") as f:
    f.write(packed)
print(len(data), len(packed))
