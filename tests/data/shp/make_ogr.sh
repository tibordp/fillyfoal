#!/bin/sh
# Shapefiles written by GDAL's ESRI Shapefile driver (ogr2ogr).
#
# Run in an empty directory outside the repository, e.g.:
#   mkdir -p /tmp/fixtures/science-shp && cd /tmp/fixtures/science-shp
#   docker run --rm -v "$PWD":/w -w /w ghcr.io/osgeo/gdal:alpine-small-latest \
#       sh /w/make_ogr.sh        (with this script copied there)
#
# Writes, from hand-written WKT:
# - polygonz.shp/.shx/.dbf: SHPT=POLYGONZ; a square with a hole and a
#   two-part multipolygon, Z on every vertex (GDAL writes no M block).
# - arcm.shp: SHPT=ARCM; a two-part line with M values, one record with
#   an unset M ("no data").
# - multipointz.shp: SHPT=MULTIPOINTZ; one record of three points.
# - point.shp: plain points and a null shape.
set -e

cat > polygonz.csv <<'EOF'
id,name,WKT
1,holed,"POLYGON Z ((0 0 1,10 0 2,10 10 3,0 10 4,0 0 1),(2 2 5,2 4 5,4 4 5,4 2 5,2 2 5))"
2,pair,"MULTIPOLYGON Z (((20 0 0,22 0 0,22 2 0,20 2 0,20 0 0)),((30 0 7,32 0 7,32 2 7,30 0 7)))"
EOF
cat > arcm.csv <<'EOF'
id,WKT
1,"MULTILINESTRING M ((0 0 0,1 1 1.5,2 0 3),(5 5 10,6 6 11))"
2,"LINESTRING (7 7,8 8)"
EOF
cat > multipointz.csv <<'EOF'
id,WKT
1,"MULTIPOINT Z (1 2 3,4 5 6,7 8 9)"
EOF
cat > point.csv <<'EOF'
id,WKT
1,"POINT (1.5 -2.25)"
2,
3,"POINT (100 200)"
EOF

ogr2ogr -oo KEEP_GEOM_COLUMNS=NO -f "ESRI Shapefile" -lco SHPT=POLYGONZ polygonz.shp polygonz.csv
ogr2ogr -oo KEEP_GEOM_COLUMNS=NO -f "ESRI Shapefile" -lco SHPT=ARCM arcm.shp arcm.csv
ogr2ogr -oo KEEP_GEOM_COLUMNS=NO -f "ESRI Shapefile" -lco SHPT=MULTIPOINTZ multipointz.shp multipointz.csv
ogr2ogr -oo KEEP_GEOM_COLUMNS=NO -f "ESRI Shapefile" -lco SHPT=POINT point.shp point.csv
for f in polygonz arcm multipointz point; do ogrinfo -al "$f.shp"; done > ogrinfo.txt
rm -f ./*.csv
