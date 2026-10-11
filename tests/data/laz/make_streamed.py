"""A LAZ file in the layout LASzip uses when it cannot seek back.

    uv run --with laspy==2.6.1 --with lazrs==0.7.0 --with numpy==2.3.4 python tests/data/laz/make_streamed.py OUT.laz

laspy (lazrs backend) writes a small LAS 1.2 / point format 1 file with
the chunk table offset (the 8 bytes at the start of the point data) set to
the real table. A compressor writing to a pipe cannot go back to fill that
in: LASzip then writes -1 there and appends the offset as the last 8 bytes
of the file (lasreadpoint.cpp, read_chunk_table). This script rewrites the
lazrs output into that layout and checks that laspy/lazrs still reads all
points back. Synthetic: the rewrite is ours.
"""

import struct
import sys

import laspy
import numpy as np

out = sys.argv[1]
h = laspy.LasHeader(point_format=1, version="1.2")
h.scales = np.array([0.01, 0.01, 0.01])
h.offsets = np.zeros(3)
h.system_identifier = "fillyfoal"
h.generating_software = "laspy"
las = laspy.LasData(h)
las.x = np.arange(20.0) * 0.5
las.y = np.arange(20.0) * 0.25
las.z = np.arange(20.0)
las.write(out, do_compress=True, laz_backend=laspy.LazBackend.Lazrs)

with open(out, "rb") as f:
    data = bytearray(f.read())
points_at = struct.unpack_from("<I", data, 96)[0]
(table_at,) = struct.unpack_from("<q", data, points_at)
struct.pack_into("<q", data, points_at, -1)
data += struct.pack("<q", table_at)
with open(out, "wb") as f:
    f.write(data)

back = laspy.read(out, laz_backend=laspy.LazBackend.Lazrs)
assert list(back.z) == list(range(20)), list(back.z)
