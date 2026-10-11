#!/bin/sh
# Writes the external GeoPackage and MBTiles fixtures with GDAL (the
# ghcr.io/osgeo/gdal:alpine-small-latest image; needs Docker):
#
#   sh tests/data/gpkg/make.sh OUTDIR
#
# - geo.gpkg: ogr2ogr of a small GeoJSON (points, a line and a polygon with
#   attributes) into a GeoPackage with 1 KiB pages and no spatial index.
# - tiles.mbtiles: gdal_translate of a 256x256 RGB GeoTIFF (made with
#   gdal_create) into MBTiles (PNG tiles), plus overviews (gdaladdo).
set -eu
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm -v "$out:/out" -v "$here:/gen:ro" -w /tmp \
    ghcr.io/osgeo/gdal:alpine-small-latest sh /gen/inner.sh /out
