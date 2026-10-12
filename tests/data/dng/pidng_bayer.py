"""Writes tests/fixtures/external/dng/pidng-bayer.dng with PiDNG: a 32x24
12-bit RGGB Bayer raw (a gradient made here) with colour matrices, as-shot
neutral, black/white levels and a neutral make/model.

    uv run --with pidng==4.0.9 --with numpy==2.5.4 python3 -I pidng_bayer.py OUT
"""

import sys

import numpy as np
from pidng.core import RAW2DNG, DNGTags, Tag
from pidng.defs import CalibrationIlluminant, CFAPattern, Orientation, PhotometricInterpretation, PreviewColorSpace

width, height, bpp = 32, 24, 12
y, x = np.mgrid[0:height, 0:width]
raw = ((x * 120 + y * 60) % 4096).astype(np.uint16)

ccm = [[1000, 1000], [0, 1000], [0, 1000],
       [0, 1000], [1000, 1000], [0, 1000],
       [0, 1000], [0, 1000], [1000, 1000]]
t = DNGTags()
t.set(Tag.ImageWidth, width)
t.set(Tag.ImageLength, height)
t.set(Tag.TileWidth, width)
t.set(Tag.TileLength, height)
t.set(Tag.Orientation, Orientation.Horizontal)
t.set(Tag.PhotometricInterpretation, PhotometricInterpretation.Color_Filter_Array)
t.set(Tag.SamplesPerPixel, 1)
t.set(Tag.BitsPerSample, bpp)
t.set(Tag.CFARepeatPatternDim, [2, 2])
t.set(Tag.CFAPattern, CFAPattern.RGGB)
t.set(Tag.BlackLevel, 64)
t.set(Tag.WhiteLevel, (1 << bpp) - 1)
t.set(Tag.ColorMatrix1, ccm)
t.set(Tag.CalibrationIlluminant1, CalibrationIlluminant.D65)
t.set(Tag.AsShotNeutral, [[1, 2], [1, 1], [1, 2]])
t.set(Tag.BaselineExposure, [[0, 100]])
t.set(Tag.Make, "fillyfoal")
t.set(Tag.Model, "Bayer Test")
t.set(Tag.PreviewColorSpace, PreviewColorSpace.sRGB)

out = sys.argv[1]
r = RAW2DNG()
r.options(t, path="", compress=False)
r.convert(raw, filename=out)
