"""Write the DuckDB fixtures in tests/fixtures/external/duckdb/ with the real
DuckDB library:

    uv run --with duckdb==1.5.6 python tests/data/duckdb/make_fixture.py OUTDIR
    gzip -9 -n OUTDIR/shop.duckdb OUTDIR/types.duckdb

`shop.duckdb`: the defaults (256 KiB blocks, storage compatible with
v0.10): two tables, a view and a sequence. `types.duckdb`: 16 KiB blocks
and the v1.5 storage format, with nested and user types, a macro, an index
and more constraint kinds. Both are checkpointed so the catalog and the row
groups are on disk (no WAL). The files are mostly zeros (whole blocks), so
they are stored gzip-compressed.
"""

import os
import sys

import duckdb

out = sys.argv[1]


def fresh(name):
    path = os.path.join(out, name)
    for p in (path, path + ".wal"):
        if os.path.exists(p):
            os.remove(p)
    return path


con = duckdb.connect(fresh("shop.duckdb"))
con.execute("CREATE SEQUENCE order_ids START 100")
con.execute(
    "CREATE TABLE customers (id INTEGER PRIMARY KEY, name VARCHAR, "
    "email VARCHAR, joined DATE)"
)
con.execute(
    "INSERT INTO customers VALUES (1, 'Ada', 'ada@example.org', '2024-01-02'), "
    "(2, 'Grace', 'grace@example.org', '2024-03-04'), (3, 'Linus', NULL, '2024-05-06')"
)
con.execute(
    "CREATE TABLE orders (id BIGINT DEFAULT nextval('order_ids'), customer INTEGER, "
    "amount DECIMAL(10,2), note TEXT, paid BOOLEAN)"
)
con.execute(
    "INSERT INTO orders (customer, amount, note, paid) VALUES "
    "(1, 12.50, 'first', true), (2, 99.99, NULL, false), (1, 3.10, 'small', true)"
)
con.execute("CREATE VIEW big_orders AS SELECT * FROM orders WHERE amount > 10")
con.execute("CHECKPOINT")
con.close()

con = duckdb.connect()
con.execute(
    f"ATTACH '{fresh('types.duckdb')}' AS db (BLOCK_SIZE 16384, STORAGE_VERSION 'v1.5.0')"
)
con.execute("USE db")
con.execute("CREATE SCHEMA lab")
con.execute("CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')")
con.execute(
    "CREATE TABLE lab.samples ("
    " id UBIGINT PRIMARY KEY,"
    " label VARCHAR NOT NULL DEFAULT 'unnamed' CHECK (length(label) < 40),"
    " feeling mood,"
    " ratio DOUBLE DEFAULT 0.5,"
    " big HUGEINT,"
    " tags VARCHAR[],"
    " point STRUCT(x FLOAT, y FLOAT),"
    " attrs MAP(VARCHAR, INTEGER),"
    " vec INTEGER[3],"
    " seen TIMESTAMP DEFAULT CAST('2024-01-01 00:00:00' AS TIMESTAMP),"
    " span INTERVAL,"
    " raw BLOB,"
    " uid UUID)"
)
con.execute(
    "INSERT INTO lab.samples VALUES "
    "(1, 'alpha', 'happy', 0.25, 170141183460469231731687303715884105727, ['a', 'b'], "
    " {'x': 1.5, 'y': -2}, MAP {'k': 1}, [1, 2, 3], '2024-02-03 04:05:06', INTERVAL 3 DAY, "
    " '\\xDE\\xAD'::BLOB, 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'), "
    "(2, 'beta', 'sad', NULL, -5, [], NULL, MAP {}, [4, 5, 6], NULL, NULL, NULL, NULL)"
)
con.execute(
    "CREATE TABLE lab.readings (sample UBIGINT REFERENCES lab.samples (id), "
    "taken TIMESTAMP, value REAL, UNIQUE (sample, taken))"
)
con.execute(
    "INSERT INTO lab.readings SELECT 1 + (i % 2), TIMESTAMP '2024-01-01' + "
    "to_minutes(i), i / 4 FROM range(300) t(i)"
)
con.execute("CREATE INDEX readings_value ON lab.readings (value)")
con.execute("CREATE MACRO lab.twice(x) AS x * 2")
con.execute("COMMENT ON TABLE lab.samples IS 'one row per sample'")
con.execute("CHECKPOINT db")
con.close()
