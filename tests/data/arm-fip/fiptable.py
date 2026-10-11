"""Prints the FIP ToC UUID table for platform.rs: reads a FIP's ToC (UUIDs
in byte order) and names each entry from `fiptool info` output, matched by
offset. Usage: python3 -I fiptable.py ALL.fip ALL-info.txt (see fip.sh)."""
import re
import struct
import sys

fip, info = sys.argv[1], sys.argv[2]
names = {}
for line in open(info):
    m = re.match(r'(.*): offset=0x([0-9A-F]+), size', line)
    if m:
        names[int(m.group(2), 16)] = m.group(1)
d = open(fip, 'rb').read()
pos = 16
while pos + 40 <= len(d):
    uuid = d[pos:pos + 16]
    off, size, _ = struct.unpack_from('<QQQ', d, pos + 16)
    pos += 40
    if uuid == bytes(16):
        print('terminator offset', hex(off), 'size', size)
        break
    h = uuid.hex()
    u = f'{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}'
    print(f'    ("{u}", "{names.get(off, "?")}"),')
