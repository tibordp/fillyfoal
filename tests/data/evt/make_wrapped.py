"""Writes `wrapped.evt`: a legacy Windows event log whose ring buffer has
wrapped. Six records were written into a 0x2c0-byte file; the first two
were overwritten, so the oldest (record 3) starts at StartOffset 0x160, and
record 5 is split across the end of the file inside its fixed header (the
rest continues right after the 0x30-byte header). Record 6 and the
end-of-file record follow it; the bytes between the end-of-file record and
StartOffset are what is left of record 2. Hand-built from the documented
ELF_LOGFILE_HEADER / EVENTLOGRECORD / ELF_EOF_RECORD layouts (synthetic).

Usage: python3 make_wrapped.py OUT_DIR
"""

import os
import struct
import sys

FILE_SIZE = 0x2C0
HEADER = 0x30
EOF_MAGIC = bytes.fromhex("11111111222222223333333344444444")


def record(number, event_id, kind, source, strings):
    computer = "FIXTURE-PC"
    names = (source + "\0" + computer + "\0").encode("utf-16-le")
    while (0x38 + len(names)) % 4:
        names += b"\0"
    body = b"".join(s.encode("utf-16-le") + b"\0\0" for s in strings)
    string_offset = 0x38 + len(names)
    total = string_offset + len(body)
    total += (-total) % 4
    length = total + 4
    t = 1_000_000_000 + number * 60
    fixed = struct.pack(
        "<I4sIIIIHHHHIIIIII",
        length,
        b"LfLe",
        number,
        t,
        t,
        event_id,
        kind,
        len(strings),
        0,
        0,
        0,
        string_offset,
        0,
        0,
        0,
        total,
    )
    rec = (fixed + names + body).ljust(total, b"\0") + struct.pack("<I", length)
    assert len(rec) == length
    return rec


def main():
    out = sys.argv[1]
    recs = [
        record(1, 6005, 4, "EventLog", []),
        record(2, 0xC0001B58, 1, "Service Control Manager", ["Fixture Service", "%%2", "Fixture extra 1"]),
        record(3, 7036, 4, "Service Control Manager", ["Print Spooler", "running"]),
        record(4, 1000, 2, "Fixture App", ["disk almost full"]),
        record(5, 7036, 4, "Service Control Manager", ["Print Spooler", "stopped"]),
        record(6, 6006, 4, "EventLog", []),
    ]
    ring = bytearray(FILE_SIZE)
    pos = HEADER
    starts = {}
    for i, rec in enumerate(recs):
        starts[i + 1] = pos
        for b in rec:
            ring[pos] = b
            pos += 1
            if pos == FILE_SIZE:
                pos = HEADER
    eof_at = pos
    oldest = 3
    start = starts[oldest]
    eof = struct.pack(
        "<I16sIIIII", 0x28, EOF_MAGIC, start, eof_at, 7, oldest, 0x28
    )
    for b in eof:
        ring[pos] = b
        pos = pos + 1 if pos + 1 < FILE_SIZE else HEADER
    assert starts[5] < FILE_SIZE <= starts[5] + 0x38, "record 5 must split in its header"
    assert eof_at < start and pos <= start, "the newest records must not reach record 3"
    ring[:HEADER] = struct.pack(
        "<I4sIIIIIIIIII",
        0x30,
        b"LfLe",
        1,
        1,
        start,
        eof_at,
        7,
        oldest,
        FILE_SIZE,
        2,  # ELF_LOGFILE_HEADER_WRAP
        0,
        0x30,
    )
    with open(os.path.join(out, "wrapped.evt"), "wb") as f:
        f.write(ring)


if __name__ == "__main__":
    main()
