"""Writes PPMd variant H streams with 7-Zip's encoder (via pyppmd, which
wraps 7-Zip's Ppmd7 C code and its 7z range coder) for the model tests in
`crates/codec/src/codec/rar/tests.rs`:

    uv run --with pyppmd==1.3.1 python tests/data/rar/ppmd.py

Each `ppmd7-<order>-<mem>.bin` encodes `crates/codec/src/codec/testdata/words.txt`. The
small memory sizes run the model out of memory, so its allocator (glueing
free blocks, restarts) is exercised too.
"""

import os

import pyppmd

HERE = os.path.dirname(os.path.abspath(__file__))
TESTDATA = os.path.join(HERE, "..", "..", "..", "src", "codec", "testdata")

CASES = [(6, 1 << 20), (16, 1 << 16), (64, 1 << 20), (2, 1 << 16)]

if __name__ == "__main__":
    data = open(os.path.join(TESTDATA, "words.txt"), "rb").read()
    for order, mem in CASES:
        enc = pyppmd.Ppmd7Encoder(order, mem)
        out = enc.encode(data) + enc.flush(endmark=False)
        name = f"ppmd7-{order}-{mem}.bin"
        with open(os.path.join(TESTDATA, name), "wb") as f:
            f.write(out)
        print(name, len(out))
