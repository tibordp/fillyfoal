# Writes the synthetic bbolt fixture from the on-disk layout of
# go.etcd.io/bbolt (page.go, meta.go, freelist.go, bucket.go): no Go writer
# was available offline, so this assembles the pages itself.
#
#   python3 tests/data/bbolt/make.py tests/fixtures/synthetic/bbolt/etcd.db
#
# Layout (4 KiB pages):
#   0, 1  meta pages (txid 5 and 6; page 1 is the active one)
#   2     freelist (page 7 is free)
#   3     root bucket leaf: buckets "blobs", "key", "meta" (inline)
#   4     branch page of bucket "key" -> pages 5, 6
#   5, 6  leaf pages of "key": etcd-style revision keys -> mvccpb.KeyValue
#   7     free page
#   8, 9  leaf page of "blobs" with one overflow page: a PNG and the
#         nested inline bucket "thumbs"
import random
import struct
import sys
import zlib

PAGE = 4096
BRANCH, LEAF, META, FREELIST = 0x01, 0x02, 0x04, 0x10
BUCKET_LEAF = 0x01
MAGIC, VERSION = 0xED0CDAED, 2


def header(pgid, flags, count, overflow=0):
    return struct.pack("<QHHI", pgid, flags, count, overflow)


def leaf(pgid, items, overflow=0):
    """items: (flags, key, value); returns the page bytes (unpadded)."""
    elems = b""
    data = b""
    base = 16 + 16 * len(items)
    for i, (flags, k, v) in enumerate(items):
        elem_at = 16 + 16 * i
        pos = base + len(data) - elem_at
        elems += struct.pack("<IIII", flags, pos, len(k), len(v))
        data += k + v
    return header(pgid, LEAF, len(items), overflow) + elems + data


def branch(pgid, items):
    """items: (key, child pgid)."""
    elems = b""
    data = b""
    base = 16 + 16 * len(items)
    for i, (k, child) in enumerate(items):
        elem_at = 16 + 16 * i
        pos = base + len(data) - elem_at
        elems += struct.pack("<IIQ", pos, len(k), child)
        data += k
    return header(pgid, BRANCH, len(items)) + elems + data


def fnv64a(b):
    h = 0xCBF29CE484222325
    for c in b:
        h ^= c
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def meta(pgid, txid, root, freelist, high):
    body = struct.pack("<IIIIQQQQQ", MAGIC, VERSION, PAGE, 0, root, 0, freelist, high, txid)
    return header(pgid, META, 0) + body + struct.pack("<Q", fnv64a(body))


def bucket(root, seq, inline=b""):
    return struct.pack("<QQ", root, seq) + inline


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def field_bytes(no, b):
    return varint(no << 3 | 2) + varint(len(b)) + b


def field_int(no, n):
    return varint(no << 3) + varint(n)


def keyvalue(key, create, mod, version, value):
    """mvccpb.KeyValue: key=1, create_revision=2, mod_revision=3,
    version=4, value=5."""
    return (field_bytes(1, key) + field_int(2, create) + field_int(3, mod)
            + field_int(4, version) + field_bytes(5, value))


def revision(main, sub):
    return struct.pack(">Q", main) + b"_" + struct.pack(">Q", sub)


def png(w, h, seed):
    rnd = random.Random(seed)
    raw = b"".join(b"\0" + bytes(rnd.randrange(256) for _ in range(w * 3)) for _ in range(h))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


revs = []
for i in range(12):
    key = b"/registry/configmaps/default/cm-%02d" % (i // 2)
    revs.append((revision(i + 2, 0),
                 keyvalue(key, (i // 2) * 2 + 2, i + 2, i % 2 + 1, b"data-%d" % i)))
# A deletion: the tombstone key carries a trailing "t" and the value only
# names the key.
revs.append((revision(14, 0) + b"t", field_bytes(1, b"/registry/configmaps/default/cm-05")))

thumbs = leaf(0, [(0, b"a.txt", b"inline value a"), (0, b"b.txt", b"inline value b")])
pages = {
    0: meta(0, 5, 3, 2, 10),
    1: meta(1, 6, 3, 2, 10),
    2: header(2, FREELIST, 1) + struct.pack("<Q", 7),
    3: leaf(3, [
        (BUCKET_LEAF, b"blobs", bucket(8, 0)),
        (BUCKET_LEAF, b"key", bucket(4, 0)),
        (BUCKET_LEAF, b"meta", bucket(0, 0, leaf(0, [
            (0, b"consistent_index", struct.pack(">Q", 13)),
            (0, b"term", struct.pack(">Q", 2)),
        ]))),
    ]),
    4: branch(4, [(revs[0][0], 5), (revs[6][0], 6)]),
    5: leaf(5, [(0, k, v) for k, v in revs[:6]]),
    6: leaf(6, [(0, k, v) for k, v in revs[6:]]),
    7: b"",
    8: leaf(8, [
        (0, b"image.png", png(40, 40, 2)),
        (BUCKET_LEAF, b"thumbs", bucket(0, 7, thumbs)),
    ], overflow=1),
}

out = bytearray()
for no in range(10):
    if no == 9:
        continue
    body = pages[no]
    span = 2 * PAGE if no == 8 else PAGE
    assert len(body) <= span, (no, len(body))
    out += body + bytes(span - len(body))
open(sys.argv[1], "wb").write(out)
