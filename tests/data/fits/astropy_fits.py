"""Writes tests/fixtures/external/fits/astropy-tables.fits with astropy.

    uv run --with astropy==7.1.1 --with numpy==2.3.4 python tests/data/fits/astropy_fits.py tests/fixtures/external/fits/astropy-tables.fits

A primary HDU with a small unsigned 16-bit image (BZERO 32768) and string,
real and logical cards; a binary table with a variable-length array column
(so it has a heap); an ASCII table. The values are ours; the layout is
astropy's.
"""

import sys

import numpy as np
from astropy.io import fits

primary = fits.PrimaryHDU(np.arange(12, dtype=np.uint16).reshape(3, 4))
primary.header["OBJECT"] = ("M31", "target")
primary.header["OBSERVER"] = ("O'Brien", "a quote in a string")
primary.header["EXPTIME"] = (12.5, "seconds")
primary.header["CALIBRAT"] = (False, "a logical")
primary.header["HISTORY"] = "written by astropy for fillyfoal"

binary = fits.BinTableHDU.from_columns(
    [
        fits.Column(name="ID", format="J", array=np.array([1, 2, 3], dtype=np.int32)),
        fits.Column(
            name="FLUX", format="E", unit="Jy", array=np.array([0.5, 1.25, 2.0], dtype=np.float32)
        ),
        fits.Column(name="NAME", format="8A", array=np.array(["alpha", "beta", "gamma"])),
        fits.Column(
            name="SAMPLES",
            format="PI()",
            array=np.array(
                [np.array([1, 2], dtype=np.int16), np.array([3], dtype=np.int16), np.array([4, 5, 6], dtype=np.int16)],
                dtype=object,
            ),
        ),
    ],
    name="CATALOG",
)

ascii_table = fits.TableHDU.from_columns(
    [
        fits.Column(name="RA", format="F8.3", unit="deg", array=np.array([10.684, 83.822])),
        fits.Column(name="LABEL", format="A6", array=np.array(["M31", "M42"])),
    ],
    name="ASCII",
)

fits.HDUList([primary, binary, ascii_table]).writeto(sys.argv[1], overwrite=True)
