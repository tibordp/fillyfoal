"""Writes tests/fixtures/synthetic/pxar/entry-v1.pxar: a pxar archive of the
first format version (before Proxmox Backup 1.0), whose ENTRY items
(`ENTRY_V1`) hold the modification time as one 64-bit nanosecond count.
No current tool writes this version, so it is made by hand from the pxar
crate's `format/mod.rs` (`Stat_V1`): a root directory with one file,
`hello.txt`, and the goodbye table that ends the directory.

    python3 tests/data/pxar/make-v1.py
"""
import os
import struct

ENTRY_V1 = 0x11da850a1c1cceff
FILENAME = 0x16701121063917b3
PAYLOAD = 0x28147a1b0b7c1a25
GOODBYE = 0x2fec4fa642d5731d
GOODBYE_TAIL = 0xef5eed5b753e1555
HASH_KEY = (0x83ac3f1cfbb450db, 0xaa4f1b6879369fbd)
M = (1 << 64) - 1


def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M


def siphash24(k0, k1, data):
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573

    def rnd():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & M; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32)
        v2 = (v2 + v3) & M; v3 = rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & M; v3 = rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & M; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32)

    n = len(data)
    end = n - n % 8
    for i in range(0, end, 8):
        m = struct.unpack('<Q', data[i:i + 8])[0]
        v3 ^= m
        rnd(); rnd()
        v0 ^= m
    last = (n & 0xff) << 56
    for i, b in enumerate(data[end:]):
        last |= b << (8 * i)
    v3 ^= last
    rnd(); rnd()
    v0 ^= last
    v2 ^= 0xff
    for _ in range(4):
        rnd()
    return v0 ^ v1 ^ v2 ^ v3


def item(kind, content):
    return struct.pack('<QQ', kind, 16 + len(content)) + content


def stat_v1(mode, mtime_ns):
    return item(ENTRY_V1, struct.pack('<QQIIQ', mode, 0, 0, 0, mtime_ns))


# 2026-01-02 03:04:05.5 UTC
MTIME = 1767323045 * 10**9 + 500_000_000
out = bytearray(stat_v1(0o040755, MTIME))
name = b'hello.txt'
file_start = len(out)
out += item(FILENAME, name + b'\0')
out += stat_v1(0o100644, MTIME)
out += item(PAYLOAD, b'Hello from fillyfoal.\n')
file_len = len(out) - file_start
gb_start = len(out)
gb_len = 16 + 24 * 2
out += struct.pack('<QQ', GOODBYE, gb_len)
out += struct.pack('<QQQ', siphash24(*HASH_KEY, name), gb_start - file_start, file_len)
out += struct.pack('<QQQ', GOODBYE_TAIL, gb_start, gb_len)

here = os.path.dirname(os.path.abspath(__file__))
dest = os.path.join(here, '..', '..', 'fixtures', 'synthetic', 'pxar', 'entry-v1.pxar')
os.makedirs(os.path.dirname(dest), exist_ok=True)
with open(dest, 'wb') as f:
    f.write(out)
