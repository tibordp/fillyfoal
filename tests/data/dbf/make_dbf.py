"""DBF tables written by the `dbf` package (Ethan Furman).

    uv run --with dbf==0.99.11 python tests/data/dbf/make_dbf.py OUTDIR

Writes, in OUTDIR:
- vfp.dbf: a Visual FoxPro table (version 0x30): character, numeric,
  float, logical, date, integer, double, currency and datetime fields, a
  263-byte database backlink after the field terminator, three records
  (the second deleted).
- db3.dbf: the same character/numeric/logical/date data as a dBase III
  table.
The writer stamps today's date into the header, so the files are
reproducible except for bytes 1-3.
"""

import datetime
import sys

import dbf

out = sys.argv[1]

vfp = dbf.Table(
    f"{out}/vfp.dbf",
    "name C(12); qty N(5,0); ratio F(8,3); ok L; day D; count I; "
    "weight B; price Y; stamp T",
    dbf_type="vfp",
    codepage="cp1252",
)
vfp.open(dbf.READ_WRITE)
vfp.append(
    (
        "alpha",
        42,
        1.5,
        True,
        datetime.date(2024, 2, 29),
        -7,
        3.25,
        12.5,
        datetime.datetime(2024, 2, 29, 13, 45, 30),
    )
)
vfp.append(
    (
        "beta",
        7,
        0.125,
        False,
        datetime.date(1999, 12, 31),
        100000,
        -0.5,
        1.0001,
        datetime.datetime(1999, 12, 31, 23, 59, 59),
    )
)
vfp.append(
    (
        "gamma",
        0,
        2.0,
        None,
        datetime.date(2000, 1, 1),
        0,
        0.0,
        0,
        datetime.datetime(2000, 1, 1, 0, 0, 0),
    )
)
dbf.delete(vfp[1])
vfp.close()

db3 = dbf.Table(
    f"{out}/db3.dbf",
    "name C(12); qty N(5,0); ok L; day D",
    dbf_type="db3",
    codepage="cp437",
)
db3.open(dbf.READ_WRITE)
db3.append(("alpha", 42, True, datetime.date(2024, 2, 29)))
db3.append(("beta", 7, False, datetime.date(1999, 12, 31)))
db3.close()
