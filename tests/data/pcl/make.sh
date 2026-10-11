#!/bin/sh
# Writes the Ghostscript printer-language fixtures into the directory given
# as $1 (default: the current one): bare PCL 5 colour (cdj550, starts with
# ESC*rbC and sends raster data plane by plane with ESC*b#V), PJL-wrapped
# PCL 5 colour (pjxl300) and PJL-wrapped PCL XL (pxlmono, pxlcolor).
# Run with Ghostscript 10.07.1; the outputs are reproducible byte for byte.
set -eu
out=${1:-.}
cd "$out"
cat > page.ps <<'EOF'
%!PS
<< /PageSize [144 144] >> setpagedevice
1 0 0 setrgbcolor 40 60 12 6 rectfill
0 0 1 setrgbcolor 52 60 12 6 rectfill
0 0.6 0 setrgbcolor 64 60 12 3 rectfill
showpage
EOF
gs() {
    command gs -q -dSAFER -dBATCH -dNOPAUSE -r75 "$@" page.ps
}
gs -sDEVICE=cdj550 -sOutputFile=gs-cdj550.pcl
gs -sDEVICE=pjxl300 -sOutputFile=gs-pjxl300.pcl
gs -sDEVICE=pxlmono -sOutputFile=gs-pxlmono.pxl
gs -sDEVICE=pxlcolor -sOutputFile=gs-pxlcolor.pxl
rm page.ps
