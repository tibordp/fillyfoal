"""Writes a two-page BigTIFF with tifffile: a 32x32 RGB page in deflated
16x16 tiles carrying GeoTIFF tags (model pixel scale, tie point, a key
directory with SHORT, DOUBLE and ASCII parameters) and an ICC profile from
Pillow's LittleCMS, then an 8x8 uncompressed grayscale page in strips.

    uv run --with tifffile==2026.9.20 --with numpy==2.5.3 --with pillow==12.3.0 \
        python tests/data/tiff/geotiff_tifffile.py tests/fixtures/external/tiff/geotiff-bigtiff.tif
"""

import sys

import numpy
import tifffile
from PIL import ImageCms

icc = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
rgb = numpy.zeros((32, 32, 3), numpy.uint8)
rgb[:, :, 0] = numpy.arange(32, dtype=numpy.uint8)[None, :] * 8
rgb[:, :, 1] = numpy.arange(32, dtype=numpy.uint8)[:, None] * 8
gray = numpy.arange(64, dtype=numpy.uint8).reshape(8, 8)

citation = "WGS 84 / UTM zone 33N|"
keys = [
    1, 1, 1, 6,
    1024, 0, 1, 1,
    1025, 0, 1, 1,
    1026, 34737, len(citation), 0,
    2059, 34736, 1, 0,
    3072, 0, 1, 32633,
    3076, 0, 1, 9001,
]
geo = [
    (33550, "d", 3, (10.0, 10.0, 0.0), False),
    (33922, "d", 6, (0.0, 0.0, 0.0, 350000.0, 5000000.0, 0.0), False),
    (34735, "H", len(keys), keys, False),
    (34736, "d", 1, (298.257223563,), False),
    (34737, "s", 0, citation, False),
]
with tifffile.TiffWriter(sys.argv[1], bigtiff=True, byteorder="<") as tif:
    tif.write(
        rgb,
        photometric="rgb",
        tile=(16, 16),
        compression="zlib",
        iccprofile=icc,
        extratags=geo,
        metadata=None,
        software="fillyfoal fixture",
    )
    tif.write(gray, photometric="minisblack", rowsperstrip=4, metadata=None)
