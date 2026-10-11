"""Removes what an alias file says about the machine that wrote it, in
place and without changing its structure:

- every volume UUID string becomes 00000000-0000-4000-8000-00000000000N;
- in the table of contents for the volume holding the mount point (id
  0xf000, the boot volume), the volume size (key 0x2012) becomes 0 and the
  volume creation date (key 0x2013) becomes 0.0 (2001-01-01).

Usage: python3 scrub_alias.py FILE
"""

import re
import struct
import sys

UUID = re.compile(rb"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")


def main():
    path = sys.argv[1]
    data = bytearray(open(path, "rb").read())
    assert data[:16] == b"book\0\0\0\0mark\0\0\0\0"
    base = struct.unpack_from("<I", data, 0x14)[0]
    n = 0

    def uuid(_):
        nonlocal n
        n += 1
        return b"00000000-0000-4000-8000-%012d" % n

    data[:] = UUID.sub(uuid, bytes(data))
    toc = struct.unpack_from("<I", data, base)[0]
    seen = 0
    while toc and seen < 64:
        seen += 1
        _, magic, ident, nxt, count = struct.unpack_from("<IIIII", data, base + toc)
        assert magic == 0xFFFFFFFE
        if ident == 0xF000:
            for i in range(count):
                key, off, _ = struct.unpack_from("<III", data, base + toc + 20 + 12 * i)
                length, kind = struct.unpack_from("<II", data, base + off)
                body = base + off + 8
                if key == 0x2012 and kind == 0x0304 and length == 8:
                    struct.pack_into("<q", data, body, 0)
                elif key == 0x2013 and kind == 0x0400 and length == 8:
                    struct.pack_into(">d", data, body, 0.0)
        toc = nxt if nxt != toc else 0
    open(path, "wb").write(data)


if __name__ == "__main__":
    main()
