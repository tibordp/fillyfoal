"""Writes tests/fixtures/external/mcap/{zstd,lz4}.mcap with the `mcap` Python
writer (one chunk per file, compressed with zstd or LZ4).

    uv run --with mcap==1.2.2 --with zstandard --with lz4 python3 -I make.py OUTDIR
"""

import json
import sys

from mcap.writer import CompressionType, Writer

out = sys.argv[1]
for name, comp in (("zstd", CompressionType.ZSTD), ("lz4", CompressionType.LZ4)):
    with open(f"{out}/{name}.mcap", "wb") as f:
        w = Writer(f, compression=comp, chunk_size=1 << 20)
        w.start(profile="", library="fillyfoal-fixture")
        schema = w.register_schema(
            name="Pose",
            encoding="jsonschema",
            data=json.dumps({"type": "object"}).encode(),
        )
        pose = w.register_channel(topic="/pose", message_encoding="json", schema_id=schema)
        log = w.register_channel(topic="/log", message_encoding="json", schema_id=schema)
        for i in range(6):
            t = 1_000_000_000 + i * 100_000_000
            w.add_message(
                channel_id=pose,
                log_time=t,
                publish_time=t,
                sequence=i,
                data=json.dumps({"x": i, "y": i * 2, "z": 0.5}).encode(),
            )
            if i % 2 == 0:
                w.add_message(
                    channel_id=log,
                    log_time=t,
                    publish_time=t,
                    sequence=i // 2,
                    data=json.dumps({"msg": f"step {i}"}).encode(),
                )
        w.finish()
