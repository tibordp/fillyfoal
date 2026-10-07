"""Regenerates the external GRIB fixtures with ecCodes (Python bindings,
which bundle the ecCodes C library and its samples).

uv run --with eccodes==2.49.0 python tests/data/grib/make.py
(run from the repository root)
"""

import os

import eccodes as ec

out = "tests/fixtures/external/grib"
os.makedirs(out, exist_ok=True)


def regional(h, ni, nj, first_lat, first_lon, inc):
    ec.codes_set(h, "Ni", ni)
    ec.codes_set(h, "Nj", nj)
    ec.codes_set(h, "latitudeOfFirstGridPointInDegrees", first_lat)
    ec.codes_set(h, "longitudeOfFirstGridPointInDegrees", first_lon)
    ec.codes_set(h, "latitudeOfLastGridPointInDegrees", first_lat - inc * (nj - 1))
    ec.codes_set(h, "longitudeOfLastGridPointInDegrees", first_lon + inc * (ni - 1))
    ec.codes_set(h, "iDirectionIncrementInDegrees", inc)
    ec.codes_set(h, "jDirectionIncrementInDegrees", inc)


# GRIB2: two messages in one file.
with open(os.path.join(out, "forecast.grib2"), "wb") as f:
    # 2 m temperature, analysis 2024-01-01 00 UTC, +6 h, PDT 4.0, simple packing.
    h = ec.codes_grib_new_from_samples("regular_ll_sfc_grib2")
    ec.codes_set(h, "centre", "ecmf")
    ec.codes_set(h, "dataDate", 20240101)
    ec.codes_set(h, "dataTime", 0)
    ec.codes_set(h, "shortName", "2t")
    ec.codes_set(h, "stepUnits", "h")
    ec.codes_set(h, "forecastTime", 6)
    regional(h, 6, 4, 50.0, 10.0, 0.25)
    ec.codes_set(h, "bitsPerValue", 12)
    ec.codes_set_values(h, [270.0 + 0.5 * i for i in range(24)])
    ec.codes_write(h, f)
    ec.codes_release(h)

    # Total precipitation accumulated over 0-12 h (PDT 4.8) with a bitmap.
    h = ec.codes_grib_new_from_samples("regular_ll_sfc_grib2")
    ec.codes_set(h, "centre", "ecmf")
    ec.codes_set(h, "dataDate", 20240101)
    ec.codes_set(h, "dataTime", 1200)
    ec.codes_set(h, "productDefinitionTemplateNumber", 8)
    # WMO tables 30, no local tables: ecCodes encodes this "tp" as
    # moisture / total precipitation rate (0/1/52) accumulated.
    ec.codes_set(h, "tablesVersion", 30)
    ec.codes_set(h, "localTablesVersion", 0)
    ec.codes_set(h, "paramId", 228228)
    ec.codes_set(h, "stepRange", "0-12")
    regional(h, 5, 3, 45.0, 0.0, 0.5)
    ec.codes_set(h, "bitmapPresent", 1)
    ec.codes_set(h, "missingValue", 9999)
    ec.codes_set(h, "bitsPerValue", 10)
    vals = [0.001 * i for i in range(15)]
    vals[3] = 9999
    vals[7] = 9999
    ec.codes_set_values(h, vals)
    ec.codes_write(h, f)
    ec.codes_release(h)

# GRIB1: mean sea level pressure on a 1-degree regional grid.
with open(os.path.join(out, "msl.grib1"), "wb") as f:
    h = ec.codes_grib_new_from_samples("GRIB1")
    ec.codes_set(h, "centre", "ecmf")
    ec.codes_set(h, "dataDate", 20231225)
    ec.codes_set(h, "dataTime", 1800)
    ec.codes_set(h, "typeOfLevel", "surface")
    ec.codes_set(h, "level", 0)
    ec.codes_set(h, "shortName", "msl")
    ec.codes_set(h, "stepRange", "3")
    regional(h, 4, 3, 60.0, -10.0, 1.0)
    ec.codes_set(h, "bitsPerValue", 16)
    ec.codes_set_values(h, [101325.0 + 10 * i for i in range(12)])
    ec.codes_write(h, f)
    ec.codes_release(h)
