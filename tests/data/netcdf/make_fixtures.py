"""Writes the NetCDF fixtures in tests/fixtures/external/netcdf/ (classic
formats) and tests/fixtures/external/hdf5/ (NetCDF-4, which is HDF5).

    cd /tmp/fixtures/netcdf && uv run --with netCDF4==1.7.4 --with scipy==1.18.1 \
        --with numpy python3 -I make_fixtures.py

netCDF4 1.7.4 bundles netCDF-C 4.9.3 and HDF5 1.14.6. The classic files are
reproducible byte for byte; the NetCDF-4 file is not (HDF5 object headers
carry no times here, but netCDF-C records its library versions).
"""

import netCDF4
import numpy as np
from scipy.io import netcdf_file


def fill(ds, wide):
    ds.title = "fillyfoal test"
    ds.history = "made by tests/data/netcdf/make_fixtures.py"
    ds.setncattr("version", np.int32(2))
    ds.setncattr("ratios", np.array([0.25, 0.5], "f8"))
    ds.createDimension("time", None)
    ds.createDimension("lat", 3)
    ds.createDimension("lon", 4)
    lat = ds.createVariable("lat", "f4", ("lat",))
    lat.units = "degrees_north"
    lat[:] = [-10.0, 0.0, 10.0]
    lon = ds.createVariable("lon", "f4", ("lon",))
    lon.units = "degrees_east"
    lon[:] = [0.0, 90.0, 180.0, 270.0]
    time = ds.createVariable("time", "f8", ("time",))
    time.units = "hours since 2000-01-01 00:00:00"
    temp = ds.createVariable("temp", "i2", ("time", "lat", "lon"), fill_value=np.int16(-999))
    temp.scale_factor = np.float32(0.1)
    temp.long_name = "temperature"
    flag = ds.createVariable("flag", "i1", ("time",))
    flag.valid_range = np.array([0, 1], "i1")
    label = ds.createVariable("label", "S1", ("lon",))
    label[:] = np.array([b"N", b"E", b"S", b"W"])
    if wide:
        big = ds.createVariable("count", "u8", ("lat",))
        big[:] = [1, 2**40, 2**63]
        small = ds.createVariable("level", "u2", ("lat",))
        small[:] = [1, 2, 65535]
    for t in range(2):
        time[t] = t * 6.0
        temp[t, :, :] = np.arange(12, dtype="i2").reshape(3, 4) + t * 100
        flag[t] = t


def netcdf4(path):
    with netCDF4.Dataset(path, "w", format="NETCDF4") as ds:
        fill(ds, True)
        grp = ds.createGroup("forecast")
        grp.createDimension("step", 2)
        step = grp.createVariable("step", "i4", ("step",), zlib=True, complevel=4, shuffle=True)
        step[:] = [6, 12]
        names = grp.createVariable("station", str, ("step",))
        names[0] = "north"
        names[1] = "south"
        point = ds.createCompoundType(np.dtype([("x", "f4"), ("y", "f4")]), "point_t")
        pts = grp.createVariable("points", point, ("step",))
        pts[:] = np.array([(1.0, 2.0), (3.0, 4.0)], np.dtype([("x", "f4"), ("y", "f4")]))


for fmt, name in [
    ("NETCDF3_CLASSIC", "classic.nc"),
    ("NETCDF3_64BIT_OFFSET", "offset64.nc"),
    ("NETCDF3_64BIT_DATA", "cdf5.nc"),
]:
    with netCDF4.Dataset(name, "w", format=fmt) as ds:
        fill(ds, fmt == "NETCDF3_64BIT_DATA")

with netcdf_file("scipy.nc", "w", version=1) as f:
    f.title = b"fillyfoal test"
    f.createDimension("t", None)
    f.createDimension("x", 5)
    x = f.createVariable("x", "f8", ("x",))
    x[:] = np.linspace(0, 1, 5)
    x.units = b"m"
    v = f.createVariable("v", "i4", ("t", "x"))
    v[0, :] = np.arange(5)
    v[1, :] = np.arange(5) * 2

netcdf4("netcdf4.nc")
