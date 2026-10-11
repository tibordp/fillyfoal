"""An unfinalized MDF 4 file: asammdf output, re-marked as unfinalized.

    uv run --with asammdf==8.6.10 --with numpy==2.3.4 python tests/data/mdf/make_unfinalized.py OUT.mf4

asammdf writes one channel group (a master time channel and a uint16
signal, five samples). The script then does what a logger that stopped
before finalizing leaves behind (ASAM MDF 4.1, 4.2: identification
block): file identifier "UnFinMF ", standard unfinalized flags 0x0005
(cycle counters of CG/CA blocks and the length of the last DT block need
updating) and custom flags 0x0001 at offsets 60 and 62. The blocks
themselves are left as asammdf wrote them, with the current time in the
header and file history blocks. A synthetic fixture: the re-marking is
ours.
"""

import struct
import sys

import numpy as np
from asammdf import MDF, Signal

out = sys.argv[1]
t = np.arange(5, dtype=np.float64) * 0.1
mdf = MDF(version="4.10")
mdf.append([Signal(np.arange(5, dtype=np.uint16) * 3, t, name="speed", unit="km/h")])
mdf.save(out, overwrite=True)

with open(out, "r+b") as f:
    data = bytearray(f.read())
    data[0:8] = b"UnFinMF "
    struct.pack_into("<HH", data, 60, 0x0005, 0x0001)
    f.seek(0)
    f.write(data)
