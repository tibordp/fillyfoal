"""Writes the SciPy MAT-file fixtures in tests/fixtures/external/mat/.

    cd /tmp/fixtures/mat && uv run --with scipy==1.16.2 --with numpy==2.3.3 python3 -I make_scipy.py

`savemat` puts the creation time in the 116-byte header text; it is
replaced by a fixed one afterwards (same length), so the output is
reproducible byte for byte.
"""

import re

import numpy as np
import scipy.io
from scipy.sparse import csc_matrix

FIXED = b"Created on: Thu Jan  1 00:00:00 2026"


def pin_header(path):
    data = bytearray(open(path, "rb").read())
    head = bytes(data[:116])
    new = re.sub(rb"Created on: [^\x00]*?(\d{4})", FIXED, head)
    assert len(new) <= 116
    data[:116] = new.ljust(116, b" ")
    open(path, "wb").write(bytes(data))


variables = {
    "x": np.arange(6, dtype=np.float64).reshape(2, 3),
    "u8": np.array([[7, 0, 8, 0, 0, 9]], dtype=np.uint8),
    "flag": np.array([[True, False, False, True]]),
    "greeting": "hello",
    "st": {"a": 1.5, "b": "hi"},
    "c": np.array([[np.float64(3.5), np.array([1, 0, 2], dtype=np.int16)]], dtype=object),
    "sp": csc_matrix(np.array([[0.0, 2.0, 0.0], [1.0, 0.0, 3.0]])),
}

# Every variable in its own miCOMPRESSED element, back to back: zlib
# streams are not padded to 8 bytes.
scipy.io.savemat("compressed.mat", variables, do_compression=True, oned_as="row")
pin_header("compressed.mat")

# The same, uncompressed: miMATRIX elements directly in the file.
scipy.io.savemat("plain.mat", variables, do_compression=False, oned_as="row")
pin_header("plain.mat")

for name in ("compressed.mat", "plain.mat"):
    back = scipy.io.loadmat(name)
    assert (back["u8"] == variables["u8"]).all()
    assert (back["flag"] == variables["flag"]).all()
    assert back["greeting"][0] == "hello"
