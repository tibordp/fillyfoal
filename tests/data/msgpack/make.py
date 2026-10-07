"""MessagePack fixtures, written by msgpack-python.

    uv run --with msgpack==1.1.2 python tests/data/msgpack/make.py

Writes `sample.msgpack` (one top-level map with string keys, the shape the
probe recognises) to tests/fixtures/external/msgpack/, and `stream.msgpack`
(a sequence of top-level values, reachable only by extension) to
tests/data/msgpack/ for the "inspect as" test.

`sample.msgpack` is a map16 header followed by keys and values each packed
by `msgpack.packb` (so that some values can use single-precision floats);
everything else is one `packb` call.
"""

import os
import struct

import msgpack

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

entries = [
    ("name", "fillyfoal", {}),
    ("version", 3, {}),
    ("negative", -5, {}),
    ("uint8", 200, {}),
    ("uint16", 60000, {}),
    ("uint32", 4000000000, {}),
    ("uint64", 2**64 - 1, {}),
    ("int8", -100, {}),
    ("int16", -30000, {}),
    ("int32", -2000000000, {}),
    ("int64", -(2**63), {}),
    ("float32", 1.5, {"use_single_float": True}),
    ("float64", 3.141592653589793, {}),
    ("nil", None, {}),
    ("flags", [True, False], {}),
    ("str8", "a string that is longer than thirty-one bytes", {}),
    ("str16", "snow ☃ " * 30, {}),
    ("bin8", b"\x00\x01\x02binary\xff", {}),
    ("nested", {"deep": {"deeper": [1, [2, 3], {}]}, "empty": []}, {}),
    ("squares", [i * i for i in range(20)], {}),
    ("array16", list(range(300)), {}),
    ("ext1", msgpack.ExtType(1, b"\x2a"), {}),
    ("ext2", msgpack.ExtType(2, b"\x01\x02"), {}),
    ("ext4", msgpack.ExtType(3, b"abcd"), {}),
    ("ext8", msgpack.ExtType(4, b"12345678"), {}),
    ("ext16", msgpack.ExtType(5, bytes(range(16))), {}),
    ("ext-other", msgpack.ExtType(100, b"hello extension"), {}),
    ("timestamp32", msgpack.Timestamp(1790000000, 0), {}),
    ("timestamp64", msgpack.Timestamp(1790000000, 123456789), {}),
    ("timestamp96", msgpack.Timestamp(-86400, 500), {}),
    ("int keys", {1: "one", -2: "minus two"}, {}),
]

out = bytearray(b"\xde" + struct.pack(">H", len(entries)))
for key, value, options in entries:
    out += msgpack.packb(key)
    out += msgpack.packb(value, **options)
with open(os.path.join(ROOT, "fixtures/external/msgpack/sample.msgpack"), "wb") as f:
    f.write(out)

stream = b"".join(
    msgpack.packb(v)
    for v in [
        [1, 2, 3],
        "second value",
        {"id": 7, "tags": ["a", "b"]},
        msgpack.Timestamp(0, 1),
        None,
    ]
)
with open(os.path.join(HERE, "stream.msgpack"), "wb") as f:
    f.write(stream)
