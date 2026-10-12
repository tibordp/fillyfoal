"""Writes PPMd variant I (rev. 1) streams with 7-Zip's encoder (via pyppmd,
which wraps the LZMA SDK's Ppmd8 C code and its range coder) for the model
tests in `crates/codec/src/codec/ppmd8.rs`:

    uv run --with pyppmd==1.3.1 python tests/data/zip/ppmd8.py

Each `ppmd8-<order>-<mem>-<restore>.bin` encodes
`crates/codec/src/codec/testdata/words.txt` (no end marker, no ZIP
parameter word). The small memory sizes run the model out of memory, so
both restoration methods (0 restart, 1 cut off) and the allocator's
glueing of free blocks are exercised.
"""

import os

import pyppmd

HERE = os.path.dirname(os.path.abspath(__file__))
TESTDATA = os.path.join(HERE, "..", "..", "..", "crates", "codec", "src", "codec", "testdata")

CASES = [(6, 1 << 20, 0), (16, 1 << 16, 0), (16, 1 << 16, 1), (8, 3 << 15, 1), (2, 1 << 16, 0)]

if __name__ == "__main__":
    data = open(os.path.join(TESTDATA, "words.txt"), "rb").read()
    for order, mem, restore in CASES:
        enc = pyppmd.Ppmd8Encoder(order, mem, restore)
        out = enc.encode(data) + enc.flush(endmark=False)
        name = f"ppmd8-{order}-{mem}-{restore}.bin"
        with open(os.path.join(TESTDATA, name), "wb") as f:
            f.write(out)
        print(name, len(out))
