#!/bin/sh
# Writes the JPEG XL fixtures in tests/fixtures/external/jxl with libjxl's
# cjxl 0.11.2 (and ImageMagick for the inputs, ExifTool for an Exif box),
# all from Debian trixie in Docker:
#
#   sh tests/data/jxl/make.sh <repo root>
#
# cjxl-alpha-lossless.jxl  bare codestream, lossless (not XYB), 8-bit RGB with
#                          an alpha extra channel
# cjxl-grey16.jxl          bare codestream, lossless greyscale from a 16-bit PNG
# cjxl-anim-jxlp.jxl       container, a three-frame animation from a GIF; cjxl
#                          splits the codestream over three jxlp boxes
# cjxl-jpeg-recon.jxl      container, a JPEG transcoded losslessly: jxlp, jbrd,
#                          a Brotli-compressed Exif box (brob) and the last jxlp
# cjxl-exif.jxl            container (--container=1) with an Exif box ExifTool
#                          appended
# cjxl-upsampling-nn.jxl   bare codestream of an already 2x-downsampled image
#                          with nearest-neighbour upsampling: custom 2x, 4x
#                          and 8x upsampling weights in CustomTransformData
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/image-jxl-make
rm -rf "$work"
mkdir -p "$work"
cat >"$work/run.sh" <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends libjxl-tools imagemagick \
    libimage-exiftool-perl >/dev/null
cd /w
magick -size 40x40 xc:none -fill 'rgba(0,128,255,0.5)' -draw 'circle 20,20 20,4' \
    -depth 8 -strip alpha.png
magick -size 16x16 gradient:white-black -depth 16 -colorspace Gray -strip grey16.png
magick -delay 10 -size 16x16 xc:red xc:green xc:blue -loop 0 anim.gif
magick -size 32x24 gradient:red-blue -depth 8 -strip rgb.png
magick rgb.png -quality 85 -strip rgb.jpg
exiftool -m -q -overwrite_original -Artist=fillyfoal -Copyright=fillyfoal rgb.jpg
cjxl -d 0 alpha.png cjxl-alpha-lossless.jxl --quiet
cjxl -d 0 grey16.png cjxl-grey16.jxl --quiet
cjxl -d 1 anim.gif cjxl-anim-jxlp.jxl --container=1 --quiet
cjxl rgb.jpg cjxl-jpeg-recon.jxl --lossless_jpeg=1 --quiet
cjxl -q 90 rgb.png cjxl-exif.jxl --container=1 --quiet
exiftool -m -q -overwrite_original -Artist=fillyfoal cjxl-exif.jxl
cjxl -d 1 rgb.png cjxl-upsampling-nn.jxl --resampling=2 --already_downsampled \
    --upsampling_mode=0 --quiet
EOF
docker run --rm -v "$work":/w debian:trixie-slim sh /w/run.sh
mkdir -p "$root/tests/fixtures/external/jxl"
for f in cjxl-alpha-lossless cjxl-grey16 cjxl-anim-jxlp cjxl-jpeg-recon cjxl-exif \
    cjxl-upsampling-nn; do
    cp "$work/$f.jxl" "$root/tests/fixtures/external/jxl/"
done
