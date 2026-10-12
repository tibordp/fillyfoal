"""Zeroes the vDSO in a little-endian ELF64 core dump (make-core.sh).

The kernel dumps its vDSO image with every process; that is the running
kernel's code, not ours to redistribute, so the PT_LOAD segment holding it
(the one whose data is an ELF image naming linux-vdso.so.1) is overwritten
with zeros. Everything else is left as the kernel wrote it.

    python3 scrub_core.py CORE
"""

import struct
import sys

path = sys.argv[1]
data = bytearray(open(path, "rb").read())
assert data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1, "ELF64 LE expected"
phoff, = struct.unpack_from("<Q", data, 0x20)
phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
scrubbed = 0
for i in range(phnum):
    at = phoff + i * phentsize
    p_type, _flags, p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from("<IIQQQQ", data, at)
    segment = data[p_offset:p_offset + p_filesz]
    if p_type == 1 and segment[:4] == b"\x7fELF" and b"linux-vdso.so.1" in segment:
        data[p_offset:p_offset + p_filesz] = bytes(p_filesz)
        scrubbed += 1
assert scrubbed == 1, f"expected one vDSO segment, found {scrubbed}"
open(path, "wb").write(data)
print(f"zeroed the vDSO segment of {path}")
