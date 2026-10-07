"""Writes the synthetic WiredTiger fixtures (no WiredTiger or MongoDB was
available to produce real ones):

    python3 tests/data/wiredtiger/make_fixtures.py OUTDIR

- `collection-0-1234.wt`: a MongoDB-style collection file (row store,
  packed record-id keys, BSON values): a leaf page, an overflow page, a
  Snappy-compressed leaf page, the internal root page and an extent list.
- `WiredTiger.wt`: the metadata file (URIs to configuration strings), with
  prefix-compressed keys and a checkpoint cookie.
- `WiredTiger.turtle`: the text file that bootstraps the metadata.

Layouts follow WiredTiger's block manager, page header and cell formats as
remembered (block_desc, WT_PAGE_HEADER + WT_BLOCK_HEADER, cell.h, intpack);
the same memory wrote the dissector, so these files lock behaviour in but
do not show conformance.
"""

import os
import struct
import sys

ALLOC = 4096


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def vuint(x):
    """WiredTiger packed unsigned integer."""
    if x <= 63:
        return bytes([0x80 | x])
    if x <= 63 + (1 << 13):
        x -= 64
        return bytes([0xC0 | (x >> 8), x & 0xFF])
    x -= 64 + (1 << 13)
    raw = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    return bytes([0xE0 | len(raw)]) + raw


def key_cell(key, prefix=None):
    if prefix is None:
        if len(key) <= 63:
            return bytes([(len(key) << 2) | 0x01]) + key
        return bytes([0x50]) + vuint(len(key) - 64) + key
    if len(key) <= 63:
        return bytes([(len(key) << 2) | 0x02, prefix]) + key
    return bytes([0x70, prefix]) + vuint(len(key) - 64) + key


def value_cell(value, tw=None):
    if tw is None and len(value) <= 63:
        return bytes([(len(value) << 2) | 0x03]) + value
    if tw is None:
        # Long values store their length minus 64 (short cells cover 0-63).
        return bytes([0x80]) + vuint(len(value) - 64) + value
    # A time window (second descriptor: start timestamp and transaction);
    # the length is then stored as is.
    start_ts, start_txn = tw
    return bytes([0x88, 0x08 | 0x20]) + vuint(start_ts) + vuint(start_txn) + vuint(len(value)) + value


def addr(offset, size, checksum):
    return vuint(offset // ALLOC - 1) + vuint(size // ALLOC) + vuint(checksum)


def addr_cell(kind, cookie):
    return bytes([kind]) + vuint(len(cookie)) + cookie


def page(ptype, entries, body, mem_size=None, flags=0, recno=0, write_gen=1, size=ALLOC):
    header = struct.pack(
        "<QQIIBBBB",
        recno,
        write_gen,
        mem_size if mem_size is not None else 40 + len(body),
        entries,
        ptype,
        flags,
        0,
        1,
    )
    block = bytearray(header + struct.pack("<IIB3x", size, 0, 0x01) + body)
    assert len(block) <= size
    block += bytes(size - len(block))
    struct.pack_into("<I", block, 32, crc32c(block))
    return bytes(block)


def desc():
    block = bytearray(ALLOC)
    struct.pack_into("<IHHII", block, 0, 120897, 1, 0, 0, 0)
    struct.pack_into("<I", block, 8, crc32c(block))
    return bytes(block)


def bson(doc):
    def elem(k, v):
        name = k.encode() + b"\0"
        if isinstance(v, bool):
            return b"\x08" + name + bytes([v])
        if isinstance(v, int):
            return b"\x10" + name + struct.pack("<i", v)
        if isinstance(v, float):
            return b"\x01" + name + struct.pack("<d", v)
        s = v.encode() + b"\0"
        return b"\x02" + name + struct.pack("<i", len(s)) + s

    body = b"".join(elem(k, v) for k, v in doc.items()) + b"\0"
    return struct.pack("<i", len(body) + 4) + body


def snappy_literal(data):
    """Snappy raw format, as one literal run (valid, if not small)."""
    out = bytearray()
    n = len(data)
    while True:
        out.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
        n >>= 7
        if not n:
            break
    n = len(data) - 1
    if n < 60:
        out.append(n << 2)
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "little")
        out.append((59 + len(raw)) << 2)
        out += raw
    return bytes(out) + data


def collection():
    docs = [
        {"_id": 1, "name": "Ada", "born": 1815},
        {"_id": 2, "name": "Grace", "born": 1906, "navy": True},
        {"_id": 3, "name": "Linus", "bio": "x" * 1500},
        {"_id": 4, "name": "Ken", "score": 9.5},
        {"_id": 5, "name": "Dennis"},
    ]
    # Overflow page holding document 3 (at 8192).
    big = bson(docs[2])
    ovfl = page(5, len(big), big, mem_size=40 + len(big))
    ovfl_ck = struct.unpack_from("<I", ovfl, 32)[0]
    # Leaf at 4096: records 1-3, the third value on the overflow page.
    cells = bytearray()
    cells += key_cell(vuint(1)) + value_cell(bson(docs[0]), tw=(100, 7))
    cells += key_cell(vuint(2)) + value_cell(bson(docs[1]))
    cells += key_cell(vuint(3)) + addr_cell(0xA0, addr(8192, ALLOC, ovfl_ck))
    leaf1 = page(7, 6, bytes(cells))
    # Compressed leaf at 12288: records 4 and 5; the first 64 bytes of the
    # page stay uncompressed (24 bytes of cells after the 40-byte header).
    cells = key_cell(vuint(4)) + value_cell(bson(docs[3])) + key_cell(vuint(5)) + value_cell(bson(docs[4]))
    skip = cells[:24]
    rest = cells[24:]
    compressed = snappy_literal(rest)
    body = skip + struct.pack("<Q", len(compressed)) + compressed
    leaf2 = page(7, 4, body, mem_size=40 + len(cells), flags=0x01)
    # Internal root at 16384.
    c1 = struct.unpack_from("<I", leaf1, 32)[0]
    c2 = struct.unpack_from("<I", leaf2, 32)[0]
    cells = key_cell(vuint(1)) + addr_cell(0x20, addr(4096, ALLOC, c1))
    cells += key_cell(vuint(4)) + addr_cell(0x20, addr(12288, ALLOC, c2))
    root = page(6, 4, bytes(cells))
    # Extent list at 20480 (the checkpoint's allocated blocks).
    ext = vuint(71002) + vuint(0)
    for off in (4096, 8192, 12288, 16384):
        ext += vuint(off) + vuint(ALLOC)
    ext += vuint(0) + vuint(0)
    extl = page(1, 0, ext)
    return desc() + leaf1 + ovfl + leaf2 + root + extl


META = [
    (
        "colgroup:collection-0-1234",
        "app_metadata=,assert=(commit_timestamp=none,read_timestamp=none),collator=,"
        "columns=,source=\"file:collection-0-1234.wt\",type=file,verbose=[]",
    ),
    (
        "file:collection-0-1234.wt",
        "access_pattern_hint=none,allocation_size=4KB,app_metadata=(formatVersion=1),"
        "block_allocation=best,block_compressor=snappy,checksum=on,"
        "key_format=q,value_format=u,leaf_page_max=32KB,"
        "checkpoint=(WiredTigerCheckpoint.3=(addr=\"01e4c08084e4c08084\",order=3,"
        "time=1700000000,size=24576,newest_txn=12,write_gen=7)),"
        "checkpoint_lsn=(1,24320),id=7,version=(major=1,minor=1)",
    ),
    (
        "file:sizeStorer.wt",
        "allocation_size=4KB,block_compressor=snappy,key_format=u,value_format=u,id=3",
    ),
    ("system:checkpoint", "checkpoint_timestamp=\"0\""),
    (
        "table:collection-0-1234",
        "app_metadata=(formatVersion=1),colgroups=,collator=,columns=,"
        "key_format=q,value_format=u",
    ),
]


def metadata():
    cells = bytearray()
    prev = b""
    for k, v in META:
        key = k.encode() + b"\0"
        p = 0
        while p < min(len(prev), len(key), 255) and prev[p] == key[p]:
            p += 1
        cells += key_cell(key[p:], prefix=p if p else None)
        cells += value_cell(v.encode() + b"\0")
        prev = key
    leaf = page(7, 2 * len(META), bytes(cells))
    return desc() + leaf


TURTLE = (
    "WiredTiger version string\n"
    "WiredTiger 11.2.0: (December  1, 2023)\n"
    "WiredTiger version\n"
    "major=11,minor=2,patch=0\n"
    "file:WiredTiger.wt\n"
    "access_pattern_hint=none,allocation_size=4KB,app_metadata=,block_allocation=best,"
    "block_compressor=,checksum=uncompressed,id=0,key_format=S,value_format=S,"
    "checkpoint=(WiredTigerCheckpoint.5=(addr=\"018081e4b3a2c1d0\",order=5,time=1700000001,"
    "size=8192,newest_txn=12,write_gen=9)),checkpoint_backup_info=,"
    "checkpoint_lsn=(1,24448),version=(major=1,minor=1)\n"
)

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "collection-0-1234.wt"), "wb") as f:
    f.write(collection())
with open(os.path.join(out, "WiredTiger.wt"), "wb") as f:
    f.write(metadata())
with open(os.path.join(out, "WiredTiger.turtle"), "w") as f:
    f.write(TURTLE)
