"""Writes the payload files, and copies a file's resource out of a WIM.

  python3 wim-resource.py payload DIR
      writes DIR/xpress.txt (text, then a block of seeded pseudo-random
      bytes that XPRESS cannot shrink, stored as is) and DIR/lzx.txt.
  python3 wim-resource.py extract WIM SIZE OUT
      copies the compressed resource whose uncompressed size is SIZE (the
      chunk table and the chunks) from WIM to OUT.

WIM layout (wimlib's wim.h / resource.h): the header's lookup table
resource header is at 0x30 (7-byte size, flags byte, 8-byte offset, 8-byte
original size); lookup table entries are 50 bytes: a 24-byte resource
header, part number (2), reference count (4), SHA-1 (20).
"""

import random
import struct
import sys


def reshdr(b, at):
    size = int.from_bytes(b[at : at + 7], "little")
    flags = b[at + 7]
    offset, original = struct.unpack_from("<QQ", b, at + 8)
    return size, flags, offset, original


def payload(d):
    lines = "".join(f"WOF test line {i:05d}: the quick brown fox\n" for i in range(300))
    lines = lines.encode()[:12288]
    # The fourth 4 KiB chunk.
    noise = random.Random(1).randbytes(4096)
    with open(f"{d}/xpress.txt", "wb") as f:
        f.write(lines + noise + lines[:5000])
    # Two 32 KiB chunks and a bit, in few lines (not starting with "LZX",
    # the Amiga LZX archive signature, and without commas or colons, or it
    # is CSV or YAML).
    text = "".join(f"line {i:02d} " + "LZX-compressed text " * 50 + "\n" for i in range(70))
    with open(f"{d}/lzx.txt", "wb") as f:
        f.write(text.encode())


def extract(wim, size, out):
    b = open(wim, "rb").read()
    tsize, _, toff, _ = reshdr(b, 0x30)
    table = b[toff : toff + tsize]
    for at in range(0, len(table) - 49, 50):
        csize, flags, off, original = reshdr(table, at)
        if original == size and flags & 0x04:
            open(out, "wb").write(b[off : off + csize])
            return
    sys.exit(f"no compressed resource of {size} bytes in {wim}")


if sys.argv[1] == "payload":
    payload(sys.argv[2])
else:
    extract(sys.argv[2], int(sys.argv[3]), sys.argv[4])
