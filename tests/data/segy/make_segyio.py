"""SEG-Y files written by segyio, in both byte orders.

    uv run --with segyio==1.9.13 --with numpy==2.3.4 python tests/data/segy/make_segyio.py OUTDIR

Writes, in OUTDIR, four traces of ten IEEE float32 samples (format 5) at
1000 µs, inlines 1-2 x crosslines 10-11, with our own textual header (the
default one carries today's date):
- big.sgy: big endian (the standard byte order);
- little.sgy: the same with `spec.endian = "little"`.
Reproducible byte for byte.
"""

import sys

import numpy as np
import segyio

TEXT = {
    1: "FILLYFOAL TEST LINE",
    2: "WRITTEN BY SEGYIO, FOUR TRACES OF TEN IEEE FLOAT32 SAMPLES",
    40: "END TEXTUAL HEADER",
}


def make(path, endian):
    spec = segyio.spec()
    spec.ilines = [1, 2]
    spec.xlines = [10, 11]
    spec.samples = list(range(10))
    spec.format = 5
    spec.sorting = 2
    spec.endian = endian
    with segyio.create(path, spec) as f:
        f.text[0] = segyio.tools.create_text_header(TEXT)
        f.bin.update(hdt=1000, hns=10, format=5)
        tr = 0
        for il in spec.ilines:
            for xl in spec.xlines:
                f.header[tr] = {
                    segyio.su.iline: il,
                    segyio.su.xline: xl,
                    segyio.su.cdp: tr + 1,
                    segyio.su.tracf: tr + 1,
                    segyio.su.ns: 10,
                    segyio.su.dt: 1000,
                }
                f.trace[tr] = np.arange(10, dtype=np.float32) + tr * 0.5
                tr += 1


out = sys.argv[1]
make(f"{out}/big.sgy", "big")
make(f"{out}/little.sgy", "little")
