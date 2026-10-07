"""Amazon Ion fixtures, written by ion-python (`amazon.ion`).

    uv run --with amazon.ion==0.13.0 python tests/data/ion/make.py

The same value stream is written as binary Ion (`ion/sample.10n`) and as
text Ion (`ion-text/sample.ion`). Symbols beyond the system table
(field names, symbol values, annotations) make ion-python emit a local
symbol table.
"""

import datetime
import os
from decimal import Decimal

from amazon.ion import simpleion
from amazon.ion.core import IonType, Timestamp, TimestampPrecision, OffsetTZInfo
from amazon.ion.simple_types import IonPyDict, IonPyInt, IonPyList, IonPyNull, IonPySymbol, IonPyText

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures", "external"))


def annotated(value, *annotations):
    value.ion_annotations = annotations
    return value


sexp = IonPyList.from_value(IonType.SEXP, [IonPySymbol.from_value(IonType.SYMBOL, "+"), 1, 2])

record = {
    "name": "fillyfoal",
    "version": 3,
    "negative": -500,
    "big": 2**80,
    "pi": 3.141592653589793,
    "price": Decimal("1234.5678"),
    "tiny": Decimal("-1.5e-30"),
    "zero point": Decimal("0.00"),
    "enabled": True,
    "nothing": None,
    "typed null": IonPyNull.from_value(IonType.INT, None),
    "kind": IonPySymbol.from_value(IonType.SYMBOL, "widget"),
    "tags": ["a", "b", 3],
    "expr": sexp,
    "blob": b"\x00\x01\x02binary",
    "clob": simpleion.IonPyBytes.from_value(IonType.CLOB, b"clob text"),
    "day": Timestamp(2026, 10, 7, precision=TimestampPrecision.DAY),
    "moment": Timestamp(
        2026, 10, 7, 12, 30, 15, 250000,
        tzinfo=OffsetTZInfo(datetime.timedelta(hours=2)), precision=TimestampPrecision.SECOND,
        fractional_precision=3,
    ),
    "nested": {"deep": {"deeper": [True, False]}, "empty": {}},
    "money": annotated(IonPyInt.from_value(IonType.INT, 42), "USD", "amount"),
}

values = [
    record,
    annotated(IonPyText.from_value(IonType.STRING, "second top-level value"), "note"),
    [1, 2.5, "three"],
]

with open(os.path.join(OUT, "ion", "sample.10n"), "wb") as f:
    f.write(simpleion.dumps(values, binary=True, sequence_as_stream=True))
with open(os.path.join(OUT, "ion-text", "sample.ion"), "w") as f:
    f.write(simpleion.dumps(values, binary=False, sequence_as_stream=True, indent="  "))
