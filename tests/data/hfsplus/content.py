"""Writes the files make.sh copies onto the HFS+ volume into the given directory.

The data is binary (NUL-separated) so that the snapshot shows it as data
rather than every line of text; each 4 KiB block of frag.bin starts with
its block number, so the order of the extents shows in the content.
"""

import os
import random
import sys

out = sys.argv[1]
r = random.Random(7)
words = [b"filly", b"foal", b"mare", b"colt", b"hay", b"oats", b"barn", b"field",
         b"gallop", b"trot", b"canter", b"saddle", b"bridle", b"stable", b"meadow"]
with open(os.path.join(out, "small.dat"), "wb") as f:
    for i in range(1400):
        f.write(b"record %06d\0\0\0" % i)
with open(os.path.join(out, "words.dat"), "wb") as f:
    f.write(b"\0".join(r.choice(words) for _ in range(30000)))
with open(os.path.join(out, "frag.bin"), "wb") as f:
    for i in range(12):
        f.write((b"block %02d\n" % i).ljust(4096, b"\0"))
