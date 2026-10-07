"""Regenerates the external BUFR fixtures with ecCodes (Python bindings,
which bundle the ecCodes C library and its samples).

uv run --with eccodes==2.49.0 python tests/data/bufr/make.py
(run from the repository root)
"""

import os

import eccodes as ec

out = "tests/fixtures/external/bufr"
os.makedirs(out, exist_ok=True)


def observation(sample, path, edition_specific):
    h = ec.codes_bufr_new_from_samples(sample)
    ec.codes_set(h, "bufrHeaderCentre", 98)
    ec.codes_set(h, "dataCategory", 0)  # surface data - land
    ec.codes_set(h, "localTablesVersionNumber", 0)
    edition_specific(h)
    ec.codes_set(h, "typicalMonth", 3)
    ec.codes_set(h, "typicalDay", 14)
    ec.codes_set(h, "typicalHour", 12)
    ec.codes_set(h, "typicalMinute", 30)
    ec.codes_set(h, "numberOfSubsets", 2)
    ec.codes_set(h, "observedData", 1)
    ec.codes_set(h, "compressedData", 0)
    if sample == "BUFR4_local":
        ec.codes_set(h, "compressedData", 1)
    # WMO block/station, date, time, lat/lon, then a few elements.
    ec.codes_set_array(
        h,
        "unexpandedDescriptors",
        [301001, 301011, 301012, 5001, 6001, 7030, 12101, 10004, 11001, 11002],
    )
    ec.codes_set_array(h, "blockNumber", [6, 6])
    ec.codes_set_array(h, "stationNumber", [610, 700])
    ec.codes_set_array(h, "year", [2024, 2024])
    ec.codes_set_array(h, "month", [3, 3])
    ec.codes_set_array(h, "day", [14, 14])
    ec.codes_set_array(h, "hour", [12, 12])
    ec.codes_set_array(h, "minute", [30, 30])
    ec.codes_set_array(h, "latitude", [46.81, 47.48])
    ec.codes_set_array(h, "longitude", [6.94, 8.54])
    ec.codes_set_array(h, "heightOfStationGroundAboveMeanSeaLevel", [490.0, 426.0])
    ec.codes_set_array(h, "airTemperature", [281.15, 283.35])
    ec.codes_set_array(h, "nonCoordinatePressure", [95500.0, 96210.0])
    ec.codes_set_array(h, "windDirection", [220, 250])
    ec.codes_set_array(h, "windSpeed", [3.6, 5.1])
    ec.codes_set(h, "pack", 1)
    with open(path, "wb") as f:
        ec.codes_write(h, f)
    ec.codes_release(h)


def ed4(h):
    ec.codes_set(h, "internationalDataSubCategory", 2)
    ec.codes_set(h, "masterTablesVersionNumber", 28)
    ec.codes_set(h, "typicalYear", 2024)
    ec.codes_set(h, "typicalSecond", 0)


def ed3(h):
    ec.codes_set(h, "dataSubCategory", 2)
    ec.codes_set(h, "masterTablesVersionNumber", 13)
    ec.codes_set(h, "typicalYearOfCentury", 24)


observation("BUFR4", os.path.join(out, "synop4.bufr"), ed4)
observation("BUFR3", os.path.join(out, "synop3.bufr"), ed3)


# ECMWF's local sample: section 2 holds the ECMWF RDB key; two subsets
# compressed.
observation("BUFR4_local", os.path.join(out, "synop4-local.bufr"), ed4)
