"""Writes the HDF5 fixtures in tests/fixtures/external/hdf5/ with h5py.

    cd /tmp/fixtures/hdf5 && uv run --with h5py==3.16.0 --with numpy \
        python3 -I make_fixtures.py

h5py 3.16.0 bundles HDF5 2.0.0. Run it in a neutral directory: the external
link stores the target file name as given. Datasets created with
track_times=True, and those created through the low-level API (which tracks
times by default), carry their creation time, so those bytes differ per run.
"""

import h5py
import numpy as np


def earliest(path):
    """Superblock 0, version 1 object headers, symbol-table groups, v1
    B-trees and local heaps, every datatype class h5py writes."""
    with h5py.File(path, "w", libver="earliest") as f:
        f.attrs["title"] = np.bytes_("fillyfoal test")
        f.attrs["version"] = np.int32(3)
        f.attrs["scale"] = np.array([0.5, 1.5, 2.5])
        f.attrs.create("note", "variable-length text", dtype=h5py.string_dtype())
        f.attrs["empty"] = h5py.Empty("f4")
        ints = f.create_dataset("ints", data=np.arange(20, dtype="<i4").reshape(4, 5))
        ints.attrs["units"] = np.bytes_("m")
        f.create_dataset(
            "chunked",
            data=np.arange(400, dtype="<f4").reshape(20, 20),
            chunks=(10, 10),
            compression="gzip",
            compression_opts=6,
            shuffle=True,
            fletcher32=True,
            fillvalue=-1.0,
            track_times=True,
        )
        f.create_dataset(
            "scaled",
            data=np.arange(64, dtype="<i4"),
            chunks=(32,),
            scaleoffset=0,
            maxshape=(None,),
        )
        dcpl = h5py.h5p.create(h5py.h5p.DATASET_CREATE)
        dcpl.set_layout(h5py.h5d.COMPACT)
        space = h5py.h5s.create_simple((6,))
        h5py.h5d.create(f.id, b"compact", h5py.h5t.STD_I16BE, space, dcpl=dcpl).write(
            h5py.h5s.ALL, h5py.h5s.ALL, np.arange(6, dtype=">i2")
        )
        compound = np.dtype([("id", "<i4"), ("x", "<f8"), ("name", "S8")])
        f.create_dataset(
            "compound",
            data=np.array([(1, 1.5, b"one"), (2, 2.5, b"two"), (3, 3.5, b"three")], compound),
        )
        colours = h5py.enum_dtype({"RED": 0, "GREEN": 1, "BLUE": 2}, basetype="i1")
        f.create_dataset("enum", data=np.array([0, 2, 1, 2], "i1"), dtype=colours)
        f.create_dataset(
            "strings", data=["alpha", "beta", "gamma"], dtype=h5py.string_dtype()
        )
        ragged = f.create_dataset("ragged", (3,), dtype=h5py.vlen_dtype("<i4"))
        ragged[0] = [1]
        ragged[1] = [2, 3]
        ragged[2] = [4, 5, 6]
        arr = f.create_dataset("array", (2,), dtype=np.dtype("(2,3)<i4"))
        arr[...] = np.arange(12, dtype="<i4").reshape(2, 2, 3)
        f.create_dataset("opaque", data=np.array([b"\x01\x02\x03\x04"], "V4"))
        f.create_dataset("bools", data=np.array([True, False, True]))
        grp = f.create_group("group")
        sub = grp.create_group("sub")
        sub.create_dataset("scalar", data=np.float64(6.25))
        refs = f.create_dataset("refs", (2,), dtype=h5py.ref_dtype)
        refs[0] = f["ints"].ref
        refs[1] = grp.ref
        f["soft"] = h5py.SoftLink("/ints")
        f["external"] = h5py.ExternalLink("other.h5", "/data")


def latest(path):
    """Superblock 3, version 2 object headers, compact and dense links and
    attributes (fractal heaps, v2 B-trees), every chunk index."""
    with h5py.File(path, "w", libver="latest") as f:
        f.attrs["created_by"] = np.bytes_("fillyfoal")
        dense = f.create_group("dense", track_order=True)
        for i in range(10):
            dense.create_group(f"g{i:02}")
        compact = f.create_group("compact")
        compact.create_dataset("single", data=np.arange(8, dtype="<i8"), chunks=(8,), compression="gzip")
        dcpl = h5py.h5p.create(h5py.h5p.DATASET_CREATE)
        dcpl.set_chunk((4,))
        dcpl.set_alloc_time(h5py.h5d.ALLOC_TIME_EARLY)
        space = h5py.h5s.create_simple((16,))
        h5py.h5d.create(compact.id, b"implicit", h5py.h5t.STD_U8LE, space, dcpl=dcpl).write(
            h5py.h5s.ALL, h5py.h5s.ALL, np.arange(16, dtype="u1")
        )
        compact.create_dataset("fixed", data=np.arange(48, dtype="<u2"), chunks=(8,), compression="gzip", shuffle=True)
        compact.create_dataset("extensible", data=np.arange(24, dtype="<i2"), chunks=(6,), maxshape=(None,))
        compact.create_dataset(
            "btree2", data=np.arange(36, dtype="<f8").reshape(6, 6), chunks=(3, 3), maxshape=(None, None)
        )
        contiguous = f.create_dataset("contiguous", data=np.linspace(0, 1, 5), track_order=True)
        for i in range(10):
            contiguous.attrs[f"a{i}"] = np.int16(i)
        contiguous.attrs["label"] = "dense attribute storage"


def v108(path):
    """Superblock 2 after a 512-byte user block."""
    with h5py.File(path, "w", libver=("v108", "v108"), userblock_size=512) as f:
        f.create_dataset("values", data=np.arange(6, dtype=">f4"))
        f.create_group("empty")
    with open(path, "r+b") as raw:
        raw.write(b"fillyfoal user block\n")


earliest("earliest.h5")
latest("latest.h5")
v108("userblock-v2.h5")
