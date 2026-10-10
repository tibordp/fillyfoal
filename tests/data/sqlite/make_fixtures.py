"""Writes the SQLite fixtures in tests/fixtures/external/sqlite*/ with
Python's sqlite3 module (the SQLite library it links).

    uv run python3 -I tests/data/sqlite/make_fixtures.py /tmp/fixtures/sqlite-out

Run it in a neutral directory: nothing here records paths, but keep it out
of home directories anyway. The databases are reproducible byte for byte;
the WAL salts and the journal nonce are random, so those two files are not.
"""

import os
import shutil
import sqlite3
import sys

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)


def fresh(name):
    path = os.path.join(OUT, name)
    for suffix in ("", "-wal", "-shm", "-journal"):
        if os.path.exists(path + suffix):
            os.remove(path + suffix)
    return path


def text(n, word="lorem ipsum dolor sit amet "):
    return (word * (n // len(word) + 1))[:n]


def pattern(n):
    return bytes((i * 7 + 3) & 0xFF for i in range(n))


# --- A catalogue: tables, indexes (explicit and automatic), a view, a
# trigger, AUTOINCREMENT, WITHOUT ROWID, overflow, a freelist, ANALYZE.
path = fresh("catalog.sqlite")
db = sqlite3.connect(path, isolation_level=None)
db.executescript(
    """
    PRAGMA page_size = 512;
    PRAGMA auto_vacuum = NONE;
    CREATE TABLE authors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        born INTEGER,
        rating REAL,
        bio TEXT,
        photo BLOB
    );
    CREATE TABLE books (
        id INTEGER PRIMARY KEY,
        author INTEGER REFERENCES authors(id),
        title VARCHAR(80),
        year INT,
        price NUMERIC,
        isbn TEXT UNIQUE
    );
    CREATE INDEX books_by_year ON books(year DESC, title);
    CREATE TABLE tags (book INTEGER, tag TEXT, weight REAL, PRIMARY KEY (book, tag)) WITHOUT ROWID;
    CREATE TABLE settings (key TEXT PRIMARY KEY, value);
    CREATE VIEW recent AS SELECT title, year FROM books WHERE year > 2000;
    CREATE TRIGGER books_ai AFTER INSERT ON books
    BEGIN
        UPDATE authors SET rating = coalesce(rating, 0) + 0.5 WHERE id = NEW.author;
    END;
    """
)
db.execute("BEGIN")
for i, name in enumerate(["Ada", "Brook", "Cyra", "Dorian", "Ember"], 1):
    bio = text(1000) if i == 2 else f"Author {name}"
    photo = pattern(600) if i == 4 else None
    db.execute(
        "INSERT INTO authors (name, born, rating, bio, photo) VALUES (?, ?, ?, ?, ?)",
        (name, 1900 + i * 17, None, bio, photo),
    )
for i in range(1, 49):
    db.execute(
        "INSERT INTO books (author, title, year, price, isbn) VALUES (?, ?, ?, ?, ?)",
        (i % 5 + 1, f"Book number {i}", 1950 + (i * 37) % 70, i * 1.25 if i % 3 else i, f"978-{i:06d}"),
    )
for i in range(1, 37):
    db.execute("INSERT INTO tags VALUES (?, ?, ?)", (i, ["new", "old", "rare"][i % 3], i / 8))
for key, value in [
    ("int", 42),
    ("zero", 0),
    ("one", 1),
    ("negative", -129),
    ("big", 1 << 40),
    ("huge", -(1 << 62)),
    ("real", 2.5),
    ("tiny", 1e-300),
    ("text", "hello"),
    ("blob", b"\x00\x01\x02\xff"),
    ("null", None),
]:
    db.execute("INSERT INTO settings VALUES (?, ?)", (key, value))
db.execute("COMMIT")
db.execute("DELETE FROM books WHERE id BETWEEN 9 AND 40")
db.execute("ANALYZE")
db.close()

# --- UTF-16 little-endian text, with an index on it.
path = fresh("utf16.sqlite")
db = sqlite3.connect(path, isolation_level=None)
db.executescript(
    """
    PRAGMA page_size = 512;
    PRAGMA encoding = 'UTF-16le';
    CREATE TABLE words (id INTEGER PRIMARY KEY, word TEXT, lang TEXT);
    CREATE INDEX words_by_word ON words(word);
    """
)
for word, lang in [("Grüße", "de"), ("日本語", "ja"), ("naïve", "fr"), ("Ελληνικά", "el"), ("hello", "en")]:
    db.execute("INSERT INTO words (word, lang) VALUES (?, ?)", (word, lang))
db.close()

# --- Incremental vacuum: pointer-map pages, overflow chains, free pages.
path = fresh("incremental.sqlite")
db = sqlite3.connect(path, isolation_level=None)
db.executescript(
    """
    PRAGMA page_size = 512;
    PRAGMA auto_vacuum = INCREMENTAL;
    CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT, data BLOB);
    """
)
db.execute("BEGIN")
for i in range(1, 31):
    data = pattern(1200) if i % 10 == 0 else pattern(40)
    db.execute("INSERT INTO files (name, data) VALUES (?, ?)", (f"file{i}.bin", data))
db.execute("COMMIT")
db.execute("DELETE FROM files WHERE id IN (10, 11, 12, 13)")
db.close()

# --- WAL mode: a database written in rollback mode, switched to WAL, then
# changed in several transactions without checkpointing. A passive
# checkpoint in between restarts the log, so frames of the first generation
# remain after the new ones with old salts. The last transaction is left
# open after spilling pages, so the log ends in uncommitted frames.
path = fresh("wal.sqlite")
db = sqlite3.connect(path, isolation_level=None)
db.executescript(
    """
    PRAGMA page_size = 512;
    CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);
    """
)
for i in range(1, 9):
    db.execute("INSERT INTO notes (body) VALUES (?)", (f"note {i}",))
db.execute("PRAGMA journal_mode = WAL")
db.execute("PRAGMA wal_autocheckpoint = 0")
db.execute("BEGIN")
for i in range(9, 40):
    db.execute("INSERT INTO notes (body) VALUES (?)", (f"generation one, note {i}",))
db.execute("COMMIT")
db.execute("INSERT INTO notes (body) VALUES (?)", (text(700),))
db.execute("PRAGMA wal_checkpoint(PASSIVE)")
db.execute("UPDATE notes SET body = 'edited' WHERE id = 3")
db.execute("INSERT INTO notes (body) VALUES ('after restart')")
db.execute("PRAGMA cache_size = 1")
db.execute("BEGIN")
for i in range(0, 30):
    db.execute("INSERT INTO notes (body) VALUES (?)", (f"uncommitted {i} " + text(40),))
shutil.copyfile(path, os.path.join(OUT, "wal-copy.sqlite"))
shutil.copyfile(path + "-wal", os.path.join(OUT, "wal-copy.sqlite-wal"))
db.execute("ROLLBACK")
db.close()

# --- Rollback journal captured while a transaction is open. The cache is
# one page, so changes spill to the database early; each spill syncs the
# journal and starts a new journal segment.
path = fresh("journal.sqlite")
db = sqlite3.connect(path, isolation_level=None)
db.executescript(
    """
    PRAGMA page_size = 512;
    CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT, qty INTEGER);
    """
)
db.execute("BEGIN")
for i in range(1, 60):
    db.execute("INSERT INTO items (label, qty) VALUES (?, ?)", (f"item {i}", i * 3))
db.execute("COMMIT")
db.execute("PRAGMA cache_size = 1")
db.execute("BEGIN")
db.execute("UPDATE items SET qty = qty + 1 WHERE id % 7 = 0")
db.execute("DELETE FROM items WHERE id > 50")
shutil.copyfile(path + "-journal", os.path.join(OUT, "journal-copy.sqlite-journal"))
db.execute("ROLLBACK")
db.close()

print(sqlite3.sqlite_version)
