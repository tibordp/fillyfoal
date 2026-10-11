"""Writes the Avro object container fixtures in
tests/fixtures/external/avro/ with fastavro.

    cd /tmp/fixtures/avro && uv run --with fastavro==1.12.1 python3 -I make_fastavro.py

The sync marker is fixed (fastavro picks a random one by default), so
the output is reproducible byte for byte.
"""

import fastavro

schema = fastavro.parse_schema(
    {
        "type": "record",
        "name": "Event",
        "namespace": "org.example",
        "fields": [
            {"name": "id", "type": "long"},
            {"name": "kind", "type": {"type": "enum", "name": "Kind", "symbols": ["A", "B", "C"]}},
            {"name": "note", "type": ["null", "string"], "default": None},
            {"name": "value", "type": ["int", "double", "string"]},
            {"name": "attrs", "type": {"type": "map", "values": "string"}},
            {"name": "tags", "type": {"type": "array", "items": "string"}},
            {"name": "digest", "type": {"type": "fixed", "name": "Digest", "size": 4}},
        ],
    }
)


def records(n):
    for i in range(n):
        yield {
            "id": i * 1000 - 5,
            "kind": "ABC"[i % 3],
            "note": None if i % 2 else f"n{i}",
            "value": [i, i / 4, f"s{i}"][i % 3],
            "attrs": {"k": str(i), "z": "zz"} if i % 4 else {},
            "tags": [f"t{j}" for j in range(i % 3)],
            "digest": bytes([i, i + 1, i + 2, i + 3]),
        }


SYNC = bytes(range(16))

# Several blocks: a block is flushed every ~64 bytes of records.
for codec, name in (("null", "events.avro"), ("deflate", "events-deflate.avro")):
    with open(name, "wb") as out:
        fastavro.writer(
            out, schema, records(12), codec=codec, sync_interval=64, sync_marker=SYNC
        )
