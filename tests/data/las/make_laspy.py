"""LAS 1.4 point clouds written by laspy.

    uv run --with laspy==2.6.1 --with lazrs==0.7.0 --with numpy==2.3.4 python tests/data/las/make_laspy.py OUTDIR

Writes, in OUTDIR:
- las14.las: LAS 1.4, point data record format 6, five points, one VLR
  and one extended VLR (after the points). In LAS 1.4 the legacy 32-bit
  point count is 0 for format 6; the real count is the 64-bit field at
  offset 247.
- las12.las: LAS 1.2, point format 1, the same five points.
- las14.laz: las14.las compressed by laspy's lazrs backend (LASzip
  layered chunked compression; the EVLR follows the chunk table).
The creation date is fixed and laspy's GUID is zero, so both reproduce
byte for byte.
"""

import datetime
import sys

import laspy
from laspy.vlrs.vlrlist import VLRList
import numpy as np

out = sys.argv[1]
xs = np.array([1.0, 2.5, 3.0, 4.25, 5.5])
ys = np.array([10.0, 11.0, 12.5, 13.0, 14.75])
zs = np.array([100.0, 100.5, 101.0, 99.75, 98.5])


def make(path, version, point_format, evlr, compress=False):
    header = laspy.LasHeader(point_format=point_format, version=version)
    header.scales = np.array([0.01, 0.01, 0.01])
    header.offsets = np.array([0.0, 0.0, 0.0])
    header.creation_date = datetime.date(2024, 2, 29)
    header.system_identifier = "fillyfoal"
    header.generating_software = "laspy"
    header.vlrs.append(
        laspy.VLR(user_id="fillyfoal", record_id=1, description="test vlr", record_data=b"hello")
    )
    if evlr:
        header.evlrs = VLRList(
            [laspy.VLR(user_id="fillyfoal", record_id=2, description="test evlr", record_data=b"world!")]
        )
    las = laspy.LasData(header)
    las.x = xs
    las.y = ys
    las.z = zs
    las.intensity = np.array([10, 20, 30, 40, 50], dtype=np.uint16)
    las.classification = np.array([2, 2, 5, 6, 2], dtype=np.uint8)
    las.gps_time = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
    if compress:
        las.write(path, do_compress=True, laz_backend=laspy.LazBackend.Lazrs)
    else:
        las.write(path)


make(f"{out}/las14.las", "1.4", 6, True)
make(f"{out}/las12.las", "1.2", 1, False)
make(f"{out}/las14.laz", "1.4", 6, True, compress=True)
