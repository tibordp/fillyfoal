#!/bin/sh
# JPEG fixtures with metadata written by ExifTool, from Debian trixie in
# Docker (ExifTool 13.25, ImageMagick 7.1.1, libjpeg-turbo, Pillow 11.1):
#
#   sh tests/data/jpeg/exiftool_metadata.sh <repo root>
#
# external/jpeg/exiftool-metadata.jpg: a 32x24 ImageMagick JPEG to which
#   ExifTool adds IFD0/Exif/GPS tags, an IFD1 thumbnail (an 8x6 ImageMagick
#   JPEG), IPTC in a Photoshop APP13 block, XMP, and an ICC profile
#   (LittleCMS's built-in sRGB, written by Pillow's ImageCms; its creation
#   date set to 2026-01-01 by this script so the output is reproducible).
# synthetic/jpeg/exiftool-makernote-{canon,nikon,sony,panasonic}.jpg: the
#   same base image with a maker note ExifTool copies (and relocates) from
#   our synthetic tests/fixtures/synthetic/tiff/makernote-*.tif; the note's
#   contents are ours, so these are synthetic.
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/image-jpeg-exiftool
rm -rf "$work"
mkdir -p "$work"
for m in canon nikon sony panasonic; do
    cp "$root/tests/fixtures/synthetic/tiff/makernote-$m.tif" "$work/"
done
cat >"$work/run.sh" <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends imagemagick libimage-exiftool-perl \
    python3-pil >/dev/null
cd /w
magick -size 32x24 gradient:orange-navy -depth 8 -strip -quality 85 base.jpg
magick base.jpg -resize 8x6 -strip -quality 70 thumb.jpg
# LittleCMS stamps the profile with the current time: fix it to 2026-01-01.
python3 -I -c 'import struct; from PIL import ImageCms; b = bytearray(ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()); b[24:36] = struct.pack(">6H", 2026, 1, 1, 0, 0, 0); open("srgb.icc", "wb").write(b)'
cp base.jpg exiftool-metadata.jpg
exiftool -m -q -overwrite_original \
    -Make=fillyfoal -Model="Test Camera" -Software=ExifTool -Artist=fillyfoal \
    -DateTimeOriginal="2024:05:01 12:00:00" -ExposureTime=1/250 -FNumber=5.6 \
    -ISO=400 -FocalLength=50 -Orientation#=1 \
    -GPSLatitude=51.4779 -GPSLatitudeRef=N -GPSLongitude=0.0015 -GPSLongitudeRef=W \
    -GPSAltitude=80 -GPSAltitudeRef=0 \
    "-ThumbnailImage<=thumb.jpg" \
    -IPTC:ObjectName="Fixture" -IPTC:By-line=fillyfoal -IPTC:Keywords=one -IPTC:Keywords=two \
    -IPTC:City="Greenwich" -IPTC:CodedCharacterSet=UTF8 \
    -XMP-dc:Title="Fixture" -XMP-dc:Creator=fillyfoal -XMP-xmp:Rating=3 \
    "-ICC_Profile<=srgb.icc" \
    exiftool-metadata.jpg
for m in canon nikon sony panasonic; do
    cp base.jpg exiftool-makernote-$m.jpg
    exiftool -m -q -overwrite_original -TagsFromFile makernote-$m.tif \
        -Make -Model -MakerNotes exiftool-makernote-$m.jpg
done
EOF
docker run --rm -v "$work":/w debian:trixie-slim sh /w/run.sh
mkdir -p "$root/tests/fixtures/external/jpeg" "$root/tests/fixtures/synthetic/jpeg"
cp "$work/exiftool-metadata.jpg" "$root/tests/fixtures/external/jpeg/"
for m in canon nikon sony panasonic; do
    cp "$work/exiftool-makernote-$m.jpg" "$root/tests/fixtures/synthetic/jpeg/"
done
