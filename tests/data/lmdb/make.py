# Regenerates the external LMDB fixture with py-lmdb (bundled liblmdb
# 0.9.x). LMDB uses the OS page size; run it as an x86_64 process so pages
# are 4 KiB even on Apple Silicon (16 KiB pages would make the file large):
#
#   uv run --python cpython-3.12-macos-x86_64-none --with lmdb==1.6.2 \
#       python tests/data/lmdb/make.py multi.mdb
#   gzip -9 -n multi.mdb   # -> tests/fixtures/external/lmdb/multi.mdb.gz
import os
import random
import struct
import sys
import zlib

import lmdb

out = sys.argv[1]
for p in (out, out + "-lock"):
    if os.path.exists(p):
        os.remove(p)


def png(w, h, seed):
    rnd = random.Random(seed)
    raw = b"".join(b"\0" + bytes(rnd.randrange(256) for _ in range(w * 3)) for _ in range(h))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


env = lmdb.open(out, subdir=False, lock=False, max_dbs=8, map_size=1 << 20)
users = env.open_db(b"users")
tags = env.open_db(b"tags", dupsort=True)
fixed = env.open_db(b"fixed", dupsort=True, dupfixed=True, integerdup=True)
blobs = env.open_db(b"blobs")

with env.begin(write=True) as t:
    t.put(b"config/name", b"fillyfoal test database")
    t.put(b"config/json", b'{"version": 3, "tags": ["a", "b"]}')
    t.put(b"\x00\x01\x02binary", bytes(range(24)))
    for i in range(70):
        value = b"name=User %d;email=user%d@example.com;role=member" % (i, i)
        t.put(b"user:%04d" % i, value, db=users)
    # A few duplicates stay in a sub-page; many become a sub-database.
    for v in (b"red", b"green", b"blue"):
        t.put(b"color", v, db=tags)
    for i in range(160):
        t.put(b"many", b"dup-%04d" % i, db=tags)
    t.put(b"single", b"only one", db=tags)
    # Fixed-size duplicates: a LEAF2 sub-page.
    for i in (5, 1, 300, 42, 7):
        t.put(b"ints", struct.pack("=I", i), db=fixed)
    # Larger than a node may be: stored on an overflow page.
    t.put(b"image.png", png(30, 30, 1), db=blobs)
    t.put(b"small", b"tiny", db=blobs)

# A later transaction frees pages, so the free DB has a record.
with env.begin(write=True) as t:
    for i in (3, 4, 50):
        t.delete(b"user:%04d" % i, db=users)
    t.put(b"config/name", b"fillyfoal test database (updated)")

env.close()
