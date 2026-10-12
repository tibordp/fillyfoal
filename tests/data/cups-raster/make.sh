#!/bin/sh
# Writes the external CUPS/PWG raster and Apple URF fixtures with
# Ghostscript 10.00.0 (Debian bookworm's ghostscript package; needs Docker):
#
#   sh tests/data/cups-raster/make.sh OUTDIR
#
# The page is 1 x 0.75 inch with three coloured bars, rendered at 72 dpi.
# - cups-raster/gs-pwgraster.ras: `-sDEVICE=pwgraster` (PWG Raster, RaS2
#   sync word, PWG header fields, PackBits-style compressed rows)
# - cups-raster/gs-cups.ras: `-sDEVICE=cups` (CUPS raster, version 3
#   sync word RaS3, uncompressed rows)
# - urf/gs-urf.urf: `-sDEVICE=urf` (Apple raster, UNIRAST)
# IMAGE may name a prepared image that already has ghostscript.
set -eu
out=$(cd "$1" && pwd)
docker run --rm -v "$out:/out" "${IMAGE:-debian:bookworm-slim}" sh -c '
set -eu
if ! command -v gs >/dev/null; then
    apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends ghostscript >/dev/null 2>&1
fi
cd /tmp
cat > page.ps <<EOF
%!PS
<< /PageSize [72 54] >> setpagedevice
1 0 0 setrgbcolor 8 20 16 14 rectfill
0 0 1 setrgbcolor 28 20 16 14 rectfill
0 0.6 0 setrgbcolor 48 20 16 7 rectfill
showpage
EOF
g() { gs -q -dSAFER -dBATCH -dNOPAUSE -r72 "$@" page.ps; }
mkdir -p /out/cups-raster /out/urf
g -sDEVICE=pwgraster -sOutputFile=/out/cups-raster/gs-pwgraster.ras
g -sDEVICE=cups -sOutputFile=/out/cups-raster/gs-cups.ras
g -sDEVICE=urf -sOutputFile=/out/urf/gs-urf.urf
'
