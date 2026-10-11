"""Writes the Parquet fixtures in tests/fixtures/external/parquet/ with
pyarrow.

    cd /tmp/fixtures/parquet && uv run --with pyarrow==26.0.0 python3 -I make_fixtures.py

The output is reproducible byte for byte.
"""

import pyarrow as pa
import pyarrow.parquet as pq

t = pa.table(
    {
        "id": pa.array(range(20), pa.int64()),
        "city": pa.array(["Ljubljana", "Maribor", "Celje", "Koper"] * 5),
        "temp": pa.array([float(i) / 4 for i in range(20)], pa.float32()),
        "note": pa.array([None if i % 3 else f"n{i}" for i in range(20)]),
        "tags": pa.array([[i, i + 1] for i in range(20)], pa.list_(pa.int32())),
    }
)

# Dictionary and plain encodings, statistics, the page index, a bloom
# filter on "city", two row groups of data page v1.
pq.write_table(
    t,
    "indexed.parquet",
    row_group_size=10,
    use_dictionary=["city", "note"],
    compression="snappy",
    write_statistics=True,
    write_page_index=True,
    bloom_filter_options={"city": {"ndv": 4, "fpp": 0.05}},
)

# Data page v2, zstd, no dictionary, page CRCs.
pq.write_table(
    t,
    "v2.parquet",
    data_page_version="2.0",
    use_dictionary=False,
    compression="zstd",
    write_page_checksum=True,
)

# GZIP pages (each a complete RFC 1952 stream), one row group, no
# dictionary or statistics.
pq.write_table(
    t.select(["id", "city"]),
    "gzip.parquet",
    use_dictionary=False,
    compression="gzip",
    write_statistics=False,
)

# BYTE_STREAM_SPLIT for the numeric columns, uncompressed, no dictionary.
pq.write_table(
    t.select(["id", "temp"]),
    "byte-stream-split.parquet",
    use_dictionary=False,
    compression="none",
    use_byte_stream_split=["id", "temp"],
    write_statistics=False,
)

# DELTA_BINARY_PACKED, DELTA_BYTE_ARRAY and DELTA_LENGTH_BYTE_ARRAY
# columns (300 rows: several miniblocks), plus an INT96 timestamp column,
# uncompressed, no dictionary.
n = 300
d = pa.table(
    {
        "i": pa.array([i * 7 - 1000 for i in range(n)], pa.int64()),
        "s": pa.array([f"key{i // 3:04d}" for i in range(n)]),
        "l": pa.array([f"v{i}" for i in range(n)]),
        "ts": pa.array([1_700_000_000_000_000 + i for i in range(n)], pa.timestamp("us")),
    }
)
pq.write_table(
    d,
    "delta.parquet",
    use_dictionary=False,
    compression="none",
    column_encoding={
        "i": "DELTA_BINARY_PACKED",
        "s": "DELTA_BYTE_ARRAY",
        "l": "DELTA_LENGTH_BYTE_ARRAY",
    },
    use_deprecated_int96_timestamps=True,
    write_statistics=False,
)
