"""Cuts a systemd journal after its last object and sets the header's
arena_size to match, so journalctl still reads and verifies it.

journald grows files in 8 MiB steps (fallocate); everything after the
tail object is zeros. Usage: python3 -I trim.py IN OUT
"""
import struct
import sys

src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, 'rb').read())
assert d[:8] == b'LPKSHHRH'
header_size = struct.unpack_from('<Q', d, 88)[0]
tail = struct.unpack_from('<Q', d, 136)[0]
tail_size = struct.unpack_from('<Q', d, tail + 8)[0]
end = (tail + tail_size + 7) // 8 * 8
assert not any(d[end:]), 'non-zero bytes after the tail object'
d = d[:end]
struct.pack_into('<Q', d, 96, end - header_size)
open(dst, 'wb').write(d)
