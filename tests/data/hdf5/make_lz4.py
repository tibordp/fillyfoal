"""Writes HDF5 LZ4 filter (32004) data with hdf5plugin's H5Zlz4:

  OUT/lz4.h5         -> tests/fixtures/external/hdf5/lz4.h5: a small file
                        with an LZ4-filtered dataset (two 512-byte blocks of
                        text, then incompressible bytes stored raw) and one
                        with shuffle then LZ4
  OUT/words8.hdf5-lz4 -> crates/codec/src/codec/testdata/: one raw chunk
                        (read back with read_direct_chunk) of text and
                        noise in 32 KiB blocks

    uv run --with h5py==3.16.0 --with hdf5plugin==6.0.0 --with numpy \\
        python3 -I make_lz4.py WORDS_TXT OUT

WORDS_TXT is crates/codec/src/codec/testdata/words.txt.
"""

import random
import sys

import h5py
import hdf5plugin
import numpy as np

words = open(sys.argv[1], "rb").read()
out = sys.argv[2]
rnd = random.Random(1)

# The small fixture: text compresses, the trailing noise block is stored.
text = words[:1024]
noise = bytes(rnd.randrange(256) for _ in range(256))
small = np.frombuffer(text + noise, dtype=np.uint8)
with h5py.File(f"{out}/lz4.h5", "w", libver="latest", track_order=False) as f:
    f.create_dataset(
        "text",
        data=small,
        chunks=(small.size,),
        track_times=False,
        **hdf5plugin.LZ4(nbytes=512),
    )
    ints = np.arange(96, dtype="<i4")
    f.create_dataset(
        "shuffled",
        data=ints,
        chunks=(96,),
        track_times=False,
        shuffle=True,
        **hdf5plugin.LZ4(nbytes=256),
    )

# The codec test vector: three 32 KiB blocks of text, one of noise (stored
# raw), then a short final block of text.
rnd = random.Random(1)
corpus = words[:98304] + bytes(rnd.randrange(256) for _ in range(32768)) + words[:5000]
big = np.frombuffer(corpus, dtype=np.uint8)
with h5py.File(f"{out}/big.h5", "w") as f:
    ds = f.create_dataset(
        "corpus", data=big, chunks=(big.size,), **hdf5plugin.LZ4(nbytes=32768)
    )
    _, raw = ds.id.read_direct_chunk((0,))
open(f"{out}/words8.hdf5-lz4", "wb").write(raw)
open(f"{out}/words8.hdf5-lz4.expect", "wb").write(corpus)
print(h5py.version.hdf5_version, hdf5plugin.version)
