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
