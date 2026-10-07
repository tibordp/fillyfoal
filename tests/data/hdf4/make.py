"""Regenerates the external HDF4 fixtures with pyhdf (which bundles the
HDF4 C library).

uv run --with pyhdf==0.11.6 --with numpy python tests/data/hdf4/make.py
(run from the repository root)
"""

import os

import numpy as np
from pyhdf.HDF import HC, HDF
from pyhdf.SD import SD, SDC
import pyhdf.V  # noqa: F401  (used by HDF.vgstart)
import pyhdf.VS  # noqa: F401  (used by HDF.vstart)

out = "tests/fixtures/external/hdf4"
os.makedirs(out, exist_ok=True)

# Scientific datasets: a float32 grid with named dimensions, dimension
# scales and attributes, and a deflate-compressed int16 dataset.
path = os.path.join(out, "grid.hdf")
if os.path.exists(path):
    os.remove(path)
sd = SD(path, SDC.WRITE | SDC.CREATE)
sd.title = "fillyfoal HDF4 sample"
sd.history = "written by pyhdf"
t = sd.create("temperature", SDC.FLOAT32, (3, 4))
t.units = "K"
t.long_name = "air temperature"
t.setfillvalue(-999.0)
lat = t.dim(0)
lat.setname("lat")
lat.setscale(SDC.FLOAT32, [10.0, 20.0, 30.0])
lat.units = "degrees_north"
lon = t.dim(1)
lon.setname("lon")
lon.setscale(SDC.FLOAT32, [0.0, 90.0, 180.0, 270.0])
t[:] = (np.arange(12, dtype=np.float32) * 0.5 + 270.0).reshape(3, 4)
t.endaccess()
c = sd.create("counts", SDC.INT16, (8, 8))
c.setcompress(SDC.COMP_DEFLATE, 6)
c[:] = (np.arange(64, dtype=np.int16) % 5).reshape(8, 8)
c.endaccess()
sd.end()

# Vdata (a small table) and a vgroup holding it, through the low-level API.
path = os.path.join(out, "table.hdf")
if os.path.exists(path):
    os.remove(path)
f = HDF(path, HC.WRITE | HC.CREATE)
vs = f.vstart()
vd = vs.create("stations", (("id", HC.INT32, 1), ("temp", HC.FLOAT32, 1), ("name", HC.CHAR8, 6)))
vd._class = "observations"
vd.write([[1, 281.5, "bern  "], [2, 283.25, "zurich"], [3, 279.0, "chur  "]])
ref = vd._refnum
vd.detach()
vs.end()
v = f.vgstart()
g = v.create("network")
g._class = "stations"
g.add(HC.DFTAG_VH, ref)
g.detach()
v.end()
f.close()

# A vdata appended to after another object was written: the library turns
# its records into a linked-block special element.
path = os.path.join(out, "linked.hdf")
if os.path.exists(path):
    os.remove(path)
f = HDF(path, HC.WRITE | HC.CREATE)
vs = f.vstart()
a = vs.create("log", (("t", HC.INT32, 1), ("v", HC.FLOAT32, 1)))
a.write([[1, 0.5], [2, 1.5]])
ref = a._refnum
a.detach()
b = vs.create("other", (("x", HC.INT16, 1),))
b.write([[7]])
b.detach()
a = vs.attach(ref, write=1)
a.seek(2)
a.write([[3, 2.5], [4, 3.5]])
a.detach()
vs.end()
f.close()
