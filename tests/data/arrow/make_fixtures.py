"""Writes the Arrow IPC fixtures in tests/fixtures/external/arrow/ and
tests/fixtures/external/arrow-stream/ with pyarrow.

    cd /tmp/fixtures/arrow && uv run --with pyarrow==26.0.0 python3 -I make_fixtures.py

The output is reproducible byte for byte.
"""

import pyarrow as pa
import pyarrow.feather as feather
import pyarrow.ipc as ipc


def table():
    return pa.table(
        {
            "id": pa.array([1, 2, None, 4], pa.int32()),
            "name": pa.array(["alpha", "beta", "gamma", None]),
            "colour": pa.array(["red", "green", "red", "blue"]).dictionary_encode(),
            "score": pa.array([0.5, 1.5, 2.5, 3.5], pa.float64()),
            "tags": pa.array([["a"], [], ["b", "c"], None], pa.list_(pa.string())),
            "point": pa.array(
                [{"x": 1, "y": 2.0}, {"x": 3, "y": 4.0}, None, {"x": 5, "y": 6.0}],
                pa.struct([("x", pa.int16()), ("y", pa.float32())]),
            ),
            "flag": pa.array([True, False, None, True]),
            "when": pa.array([0, 86400, 172800, 259200], pa.timestamp("s", tz="UTC")),
        },
        metadata={"source": "fillyfoal"},
    )


t = table()
with ipc.new_file("plain.arrow", t.schema) as w:
    w.write_table(t, max_chunksize=2)
for codec in ["lz4", "zstd"]:
    opts = ipc.IpcWriteOptions(compression=codec)
    with ipc.new_file(f"{codec}.arrow", t.schema, options=opts) as w:
        w.write_table(t)
with ipc.new_stream("table.arrows", t.schema) as w:
    w.write_table(t, max_chunksize=2)
feather.write_feather(t, "table.feather", compression="uncompressed")
