"""BSON fixtures, written by PyMongo's `bson` package.

    uv run --with pymongo==4.15.3 python tests/data/bson/make.py

`sample.bson` is one document covering the element types PyMongo can
write; `dump.bson` is a mongodump-style collection file: documents
concatenated with no framing.
"""

import datetime
import os
import uuid

import bson
from bson.binary import Binary, UuidRepresentation
from bson.code import Code
from bson.decimal128 import Decimal128
from bson.int64 import Int64
from bson.max_key import MaxKey
from bson.min_key import MinKey
from bson.objectid import ObjectId
from bson.regex import Regex
from bson.son import SON
from bson.timestamp import Timestamp

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures", "external", "bson"))

utc = datetime.timezone.utc
u = uuid.UUID("12345678-9abc-4def-8123-456789abcdef")

doc = SON(
    [
        ("_id", ObjectId("68e4f2a0" "1a2b3c4d5e" "000001")),
        ("name", "fillyfoal"),
        ("version", 3),
        ("big", Int64(-(2**40))),
        ("pi", 3.141592653589793),
        ("enabled", True),
        ("missing", None),
        ("created", datetime.datetime(2026, 10, 7, 12, 30, 15, 250000, tzinfo=utc)),
        ("ancient", datetime.datetime(1900, 1, 1, tzinfo=utc)),
        ("price", Decimal128("1234.5678")),
        ("tiny", Decimal128("-1.5E-30")),
        ("huge", Decimal128("9.999999999999999999999999999999999E+6144")),
        ("nan", Decimal128("NaN")),
        ("inf", Decimal128("-Infinity")),
        ("tags", ["a", "b", 3]),
        ("nested", SON([("deep", SON([("deeper", [True, False, None])])), ("empty", {})])),
        ("blob", Binary(b"\x00\x01\x02binary", 0)),
        ("uuid", Binary.from_uuid(u)),
        ("legacy uuid", Binary.from_uuid(u, UuidRepresentation.PYTHON_LEGACY)),
        ("md5", Binary(bytes.fromhex("d41d8cd98f00b204e9800998ecf8427e"), 5)),
        ("old binary", Binary(b"abc", 2)),
        ("user binary", Binary(b"custom", 0x80)),
        ("pattern", Regex(r"^fil+y\d*$", "im")),
        ("code", Code("function () { return 1; }")),
        ("scoped", Code("x + y", {"x": 1, "y": 2})),
        ("oplog", Timestamp(1790000000, 7)),
        ("min", MinKey()),
        ("max", MaxKey()),
        ("unicode", "snow ☃ and \U0001f600"),
    ]
)

os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "sample.bson"), "wb") as f:
    f.write(bson.encode(doc))

people = [
    SON([("_id", ObjectId("68e4f2a01a2b3c4d5e00000" + str(i))), ("name", n), ("age", a), ("tags", t)])
    for i, (n, a, t) in enumerate(
        [("Ada", 36, ["math"]), ("Grace", 85, ["cobol", "navy"]), ("Linus", 56, []), ("Margaret", 89, ["apollo"])]
    )
]
with open(os.path.join(OUT, "dump.bson"), "wb") as f:
    f.write(b"".join(bson.encode(p) for p in people))
