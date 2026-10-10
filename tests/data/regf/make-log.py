"""Writes tests/fixtures/synthetic/regf/small.LOG1: a new-format registry
transaction log (file type 6) for small.hive, by hand from the format
description: a 512-byte base block, then one HvLE log entry holding the
hive's first bin as its dirty page. The Marvin32 hashes are left zero (we
do not check them).

    python3 tests/data/regf/make-log.py tests/fixtures/synthetic/regf/small.hive OUT
"""
import struct
import sys

hive = open(sys.argv[1], 'rb').read()
base = bytearray(hive[:512])
struct.pack_into('<II', base, 4, 8, 7)        # sequence numbers: one write pending
struct.pack_into('<I', base, 0x1c, 6)         # file type: transaction log (new format)
x = 0
for (v,) in struct.iter_unpack('<I', bytes(base[:508])):
    x ^= v
struct.pack_into('<I', base, 508, {0: 1, 0xffffffff: 0xfffffffe}.get(x, x))

page = hive[0x1000:0x2000]
refs = struct.pack('<II', 0, len(page))       # offset in the hive bins, size
size = 40 + len(refs) + len(page)
size = (size + 511) // 512 * 512
entry = bytearray(size)
struct.pack_into('<4sIIIII', entry, 0, b'HvLE', size, 0, 7, 0x1000, 1)
entry[40:40 + len(refs)] = refs
entry[48:48 + len(page)] = page

open(sys.argv[2], 'wb').write(bytes(base) + bytes(entry))
