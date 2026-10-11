"""Writes the NumPy .npy fixtures in tests/fixtures/external/npy/ with
`numpy.save`.

    cd /tmp/fixtures/npy && uv run --with numpy==2.3.3 python3 -I make_numpy.py

The output is reproducible byte for byte.
"""

import numpy as np

# Little-endian float64, 2-D, C order.
np.save("f8-2d.npy", np.arange(12, dtype="<f8").reshape(3, 4) / 4)

# Fortran order, big-endian int32.
np.save("fortran.npy", np.asfortranarray(np.arange(6, dtype=">i4").reshape(2, 3)))

# Structured dtype: an int16, a float32 and a fixed-size byte string.
rec = np.array(
    [(1, 1.5, b"ab"), (2, -2.25, b"cde"), (3, 0.0, b"")],
    dtype=[("id", "<i2"), ("v", "<f4"), ("tag", "S3")],
)
np.save("structured.npy", rec)

# Fixed-width Unicode (UCS-4), shape (2,).
np.save("unicode.npy", np.array(["hello", "žaba"], dtype="<U5"))

# Object array: the data is a pickle stream.
np.save("object.npy", np.array([1, "two", None, [3.0]], dtype=object), allow_pickle=True)
