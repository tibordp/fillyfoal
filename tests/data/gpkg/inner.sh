#!/bin/sh
# Run inside the GDAL image by make.sh.
set -eu
out=$1
gdalinfo --version
cat > /tmp/geo.geojson <<'EOF'
{"type": "FeatureCollection", "features": [
 {"type": "Feature", "properties": {"name": "alpha", "rank": 1},
  "geometry": {"type": "Point", "coordinates": [14.5058, 46.0569]}},
 {"type": "Feature", "properties": {"name": "beta", "rank": 2},
  "geometry": {"type": "Point", "coordinates": [13.7300, 45.5481]}},
 {"type": "Feature", "properties": {"name": "path", "rank": 3},
  "geometry": {"type": "LineString", "coordinates": [[14.0, 46.0], [14.2, 46.1], [14.5, 46.05]]}},
 {"type": "Feature", "properties": {"name": "area", "rank": 4},
  "geometry": {"type": "Polygon", "coordinates": [[[14.0, 45.9], [14.3, 45.9], [14.3, 46.2], [14.0, 46.2], [14.0, 45.9]]]}}
]}
EOF
rm -f "$out/geo.gpkg" "$out/tiles.mbtiles"
OGR_SQLITE_PRAGMA="page_size=1024" ogr2ogr -f GPKG -lco SPATIAL_INDEX=NO -nln features \
    "$out/geo.gpkg" /tmp/geo.geojson
gdal_create -of GTiff -outsize 256 256 -bands 3 -ot Byte -burn 40 -burn 120 -burn 200 \
    -a_srs EPSG:3857 -a_ullr 1600000 5800000 1610000 5790000 /tmp/r.tif
gdal_translate -q -of MBTILES -co TILE_FORMAT=PNG -co NAME=fillyfoal /tmp/r.tif "$out/tiles.mbtiles"
