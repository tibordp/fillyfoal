"""Writes the external WKB fixtures with Shapely (GEOS's WKB writer):

    uv run --with shapely==2.1.2 python3 -I tests/data/wkb/make.py OUTDIR

- collection-z.wkb: an ISO WKB GeometryCollection Z (little-endian) of a
  point, a line string and a polygon with a hole.
- multipolygon-srid.ewkb: a big-endian PostGIS-style EWKB MultiPolygon
  carrying SRID 4326.
"""
import os
import sys

import shapely
from shapely import wkt


def main(out):
    coll = wkt.loads(
        "GEOMETRYCOLLECTION Z (POINT Z (14.5 46.05 295),"
        " LINESTRING Z (14 46 300, 14.2 46.1 310, 14.5 46.05 320),"
        " POLYGON Z ((0 0 1, 10 0 1, 10 10 1, 0 10 1, 0 0 1),"
        " (2 2 1, 4 2 1, 4 4 1, 2 2 1)))"
    )
    with open(os.path.join(out, "collection-z.wkb"), "wb") as f:
        f.write(shapely.to_wkb(coll, flavor="iso", output_dimension=3, byte_order=1))
    multi = shapely.set_srid(
        wkt.loads("MULTIPOLYGON (((0 0, 1 0, 1 1, 0 0)), ((5 5, 6 5, 6 6, 5 6, 5 5)))"),
        4326,
    )
    with open(os.path.join(out, "multipolygon-srid.ewkb"), "wb") as f:
        f.write(shapely.to_wkb(multi, flavor="extended", include_srid=True, byte_order=0))
    print("shapely", shapely.__version__, "GEOS", shapely.geos_version_string)


if __name__ == "__main__":
    main(sys.argv[1])
