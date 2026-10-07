"""UBJSON fixtures, written by py-ubjson.

    uv run --with py-ubjson==0.16.1 python tests/data/ubjson/make.py

`sample.ubj` uses py-ubjson's defaults (end-marked containers);
`counted.ubj` the same object with `container_count=True` (`#` counts).
Both are one top-level object, the shape the probe recognises.
`array.ubj` (a top-level array, reachable only by extension) goes to
tests/data/ubjson/ for the "inspect as" test.
"""

import os
from decimal import Decimal

import ubjson

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures", "external", "ubjson"))

value = {
    "name": "fillyfoal",
    "letter": "x",
    "version": 3,
    "uint8": 200,
    "int8": -100,
    "int16": -30000,
    "int32": 2000000000,
    "int64": -(2**40),
    "pi": 3.141592653589793,
    "big": 2**70,
    "precise": Decimal("1234.56789012345678901234567890"),
    "enabled": True,
    "disabled": False,
    "nothing": None,
    "tags": ["a", "b", 3],
    "blob": b"\x00\x01\x02binary",
    "nested": {"deep": {"deeper": [True, False, None]}, "empty": {}},
    "unicode": "snow ☃",
    "squares": [i * i for i in range(12)],
}

os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "sample.ubj"), "wb") as f:
    f.write(ubjson.dumpb(value))
with open(os.path.join(OUT, "counted.ubj"), "wb") as f:
    f.write(ubjson.dumpb(value, container_count=True))
with open(os.path.join(HERE, "array.ubj"), "wb") as f:
    f.write(ubjson.dumpb([1, "two", {"three": 3.0}, b"\x04"], container_count=True))
