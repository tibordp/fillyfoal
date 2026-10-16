"""Kafka message sets in the legacy formats (magic 0 and 1), written by
kafka-python's LegacyRecordBatchBuilder (the client's own encoder; Kafka 3.x
brokers no longer write these formats).

    uv run --with kafka-python==3.0.11 python -I tests/data/kafka-log/make_legacy.py /tmp/fixtures/kafka-log

Writes legacy.log: an uncompressed v0 message set (offsets 0-1), an
uncompressed v1 one with timestamps (offsets 2-3), and a gzip-compressed v1
wrapper message holding two inner messages (offsets 4-5), concatenated as
in a segment of a pre-0.11 broker.
"""

import os
import sys

from kafka.record.legacy_records import LegacyRecordBatchBuilder

GZIP = 1
TS = 1_700_000_000_000


def batch(magic, codec, records):
    b = LegacyRecordBatchBuilder(magic, codec, 1 << 20)
    for offset, ts, key, value in records:
        b.append(offset, ts if magic else None, key, value)
    return bytes(b.build())


out = sys.argv[1]
data = (
    batch(0, 0, [(0, None, b"k0", b"legacy v0 message"), (1, None, None, b"no key")])
    + batch(1, 0, [(2, TS, b"k2", b"legacy v1 message"), (3, TS + 5, None, None)])
    + batch(1, GZIP, [(4, TS + 10, b"k4", b"compressed inner one"),
                      (5, TS + 11, b"k5", b"compressed inner two")])
)
with open(os.path.join(out, "legacy.log"), "wb") as f:
    f.write(data)
