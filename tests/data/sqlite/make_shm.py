"""Writes the external sqlite-shm fixture: the WAL index of a database in
WAL mode, copied while connections are open (SQLite removes it when the
last one closes).

    python3 -I tests/data/sqlite/make_shm.py OUTDIR

Automatic checkpoints are off, so the log holds every frame; a partial
checkpoint backfills some of them, and a second connection holding a read
transaction leaves a read mark. The salts are random, so the output is not
byte-for-byte reproducible.
"""
import os
import shutil
import sqlite3
import sys
import tempfile


def main(out):
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "t.db")
        w = sqlite3.connect(db, isolation_level=None)
        w.execute("PRAGMA page_size=1024")
        w.execute("PRAGMA journal_mode=WAL")
        w.execute("PRAGMA wal_autocheckpoint=0")
        w.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
        def batch(i):
            w.execute("BEGIN")
            for j in range(20):
                w.execute("INSERT INTO notes(body) VALUES (?)", (f"note {i}-{j} " * 8,))
            w.execute("COMMIT")

        for i in range(3):
            batch(i)
        # A reader from here on keeps the checkpoint from passing its mark.
        r = sqlite3.connect(db, isolation_level=None)
        r.execute("BEGIN")
        r.execute("SELECT count(*) FROM notes").fetchone()
        for i in range(3, 6):
            batch(i)
        w.execute("PRAGMA wal_checkpoint(PASSIVE)")
        w.execute("INSERT INTO notes(body) VALUES ('after the checkpoint')")
        shutil.copyfile(db + "-shm", os.path.join(out, "t.db-shm"))
        r.execute("COMMIT")
        r.close()
        w.close()
    print("sqlite", sqlite3.sqlite_version)


if __name__ == "__main__":
    main(sys.argv[1])
