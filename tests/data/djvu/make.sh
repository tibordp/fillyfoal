#!/bin/sh
# Writes the external DjVu fixtures with DjVuLibre 3.5.28 (Debian bookworm's
# djvulibre-bin; needs Docker):
#
#   sh tests/data/djvu/make.sh OUTDIR
#
# Inputs are generated in the container: a 64x48 colour gradient (PPM, by
# a few lines of Python) and a 64x48 bitonal pattern (PBM).
# - djvu/c44.djvu: `c44 gradient.ppm` (single page, IW44 photo layer: BG44)
# - djvu/cjb2.djvu: `cjb2 pattern.pbm` (single page, JB2 mask: Sjbz)
# - djvu/djvm-bundled.djvu: `djvm -c` of the two pages (bundled multi-page
#   document, DIRM directory)
# IMAGE may name a prepared image that already has djvulibre-bin.
set -eu
out=$(cd "$1" && pwd)
docker run --rm -v "$out:/out" "${IMAGE:-debian:bookworm-slim}" sh -c '
set -eu
if ! command -v c44 >/dev/null; then
    apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends djvulibre-bin python3 >/dev/null 2>&1
fi
cd /tmp
python3 -I - <<EOF
w, h = 64, 48
with open("gradient.ppm", "wb") as f:
    f.write(b"P6 %d %d 255\n" % (w, h))
    f.write(bytes(v for y in range(h) for x in range(w) for v in (x * 4, y * 5, 128)))
with open("pattern.pbm", "wb") as f:
    f.write(b"P1\n%d %d\n" % (w, h))
    for y in range(h):
        f.write(" ".join("1" if (x // 8 + y // 8) % 2 else "0" for x in range(w)).encode() + b"\n")
EOF
mkdir -p /out/djvu
c44 gradient.ppm /out/djvu/c44.djvu
cjb2 pattern.pbm /out/djvu/cjb2.djvu
djvm -c /out/djvu/djvm-bundled.djvu /out/djvu/c44.djvu /out/djvu/cjb2.djvu
'
