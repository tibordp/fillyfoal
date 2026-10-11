"""Writes tests/fixtures/external/parquet/duckdb.parquet with DuckDB's own
Parquet writer (not parquet-cpp): one row group, a dictionary-encoded
string column, a nullable column, a list and a struct, Snappy.

    cd /tmp/fixtures/parquet && uv run --with duckdb==1.4.1 python3 -I make_duckdb.py
"""

import duckdb

con = duckdb.connect()
con.execute("SET threads = 1")
con.execute(
    """
    COPY (
        SELECT
            i::BIGINT AS id,
            ['Ljubljana', 'Maribor', 'Celje', 'Koper'][i % 4 + 1] AS city,
            CASE WHEN i % 3 = 0 THEN NULL ELSE i / 4 END AS q,
            [i, i + 1] AS tags,
            {'a': i, 'b': 'x' || i} AS rec
        FROM range(40) t(i)
    ) TO 'duckdb.parquet' (FORMAT parquet, COMPRESSION snappy)
    """
)
