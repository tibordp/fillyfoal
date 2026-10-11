"""Writes `sparse-head.$J.gz`: an NTFS change journal ($UsnJrnl:$J) as
icat or FTK export it, with the sparse (zeroed) head kept, so the records
only start at 0x1ff70 (past the 66 KiB a probe sees) and each record's USN is its offset in the stream.
Records do not span 4 KiB pages: the one that would is moved to the next
page and the gap is zeros. Hand-built from the documented USN_RECORD_V2 and
V3 layouts (synthetic). The fixture is stored gzipped (`gzip -n`
equivalent) only for size; the harness dissects the decompressed bytes.

Usage: python3 make_sparse_head.py OUT_DIR
"""

import gzip
import os
import struct
import sys

PAGE = 0x1000
BASE_TIME = 133_500_000_000_000_000  # FILETIME, 2024-01-17 21:20 UTC


def record_v2(usn, name, reason, n):
    name16 = name.encode("utf-16-le")
    length = (60 + len(name16) + 7) & ~7
    body = struct.pack(
        "<IHHQQQQIIIIHH",
        length,
        2,
        0,
        (1 << 48) | (0x40 + n),  # file reference: record, sequence 1
        (5 << 48) | 5,  # parent: the root directory
        usn,
        BASE_TIME + n * 10_000_000,
        reason,
        0,
        0,
        0x20,  # ARCHIVE
        len(name16),
        60,
    )
    return (body + name16).ljust(length, b"\0")


def record_v3(usn, name, reason, n):
    name16 = name.encode("utf-16-le")
    length = (76 + len(name16) + 7) & ~7
    body = struct.pack("<IHH", length, 3, 0)
    body += struct.pack("<QQ", 0x40 + n, 1) + struct.pack("<QQ", 5, 5)
    body += struct.pack(
        "<QQIIIIHH",
        usn,
        BASE_TIME + n * 10_000_000,
        reason,
        0,
        0,
        0x20,
        len(name16),
        76,
    )
    return (body + name16).ljust(length, b"\0")


def main():
    out = sys.argv[1]
    data = bytearray(0x1FF70)  # the sparse head
    entries = [
        (record_v2, "report.txt", 0x100),  # FILE_CREATE
        (record_v2, "report-final.txt", 0x2000),  # RENAME_NEW_NAME
        (record_v3, "report-final.txt", 0x8000_0002),  # DATA_EXTEND | CLOSE
        (record_v2, "report-final.txt", 0x8000_0200),  # FILE_DELETE | CLOSE
    ]
    for n, (make, name, reason) in enumerate(entries):
        rec = make(0, name, reason, n)
        if len(data) // PAGE != (len(data) + len(rec) - 1) // PAGE:
            data.extend(b"\0" * (PAGE - len(data) % PAGE))
        data.extend(make(len(data), name, reason, n))
    path = os.path.join(out, "sparse-head.$J.gz")
    with open(path, "wb") as f:
        f.write(gzip.compress(bytes(data), compresslevel=9, mtime=0))


if __name__ == "__main__":
    main()
