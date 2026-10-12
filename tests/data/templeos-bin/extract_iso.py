"""Extracts the templeos-bin and templeos-kernel fixtures from the TempleOS
V5.03 distribution ISO.

    python3 tests/data/templeos-bin/extract_iso.py TempleOS.ISO OUT_DIR
    TOSZ OUT_DIR/Compiler.BIN.Z OUT_DIR/Compiler.BIN

The ISO wraps a RedSea file system whose directory entries (64 bytes:
U16 attr, 38-byte name, I64 first block, I64 size, CDate) give absolute
512-byte block numbers; the root directory is at the block the RedSea boot
sector at 0xB000 names. `0000Boot/0000Kernel.BIN.C` is stored contiguous
and uncompressed and is written as is; `Compiler/Compiler.BIN.Z` is
TempleOS-compressed and is expanded with Terry Davis's own `TOSZ`
(`Linux/TOSZ.CPP` in the TempleOS sources, built with the host `c++`).
"""

import os
import struct
import sys

RS_ATTR_DIR = 0x10
WANTED = {"/0000Boot/0000Kernel.BIN.C", "/Compiler/Compiler.BIN.Z"}


def main():
    iso, out = sys.argv[1], sys.argv[2]
    with open(iso, "rb") as f:
        disk = f.read()
    root = struct.unpack_from("<q", disk, 0xB000 + 0x18)[0]
    seen = set()
    stack = [(root, "")]
    while stack:
        block, path = stack.pop()
        if block in seen:
            continue
        seen.add(block)
        at = block * 512
        while True:
            attr = struct.unpack_from("<H", disk, at)[0]
            name = disk[at + 2 : at + 40].split(b"\0")[0].decode("latin-1")
            if not name:
                break
            first, size = struct.unpack_from("<qq", disk, at + 40)
            at += 64
            if name in (".", ".."):
                continue
            full = f"{path}/{name}"
            if attr & RS_ATTR_DIR:
                stack.append((first, full))
            elif full in WANTED:
                data = disk[first * 512 : first * 512 + size]
                with open(os.path.join(out, name), "wb") as f:
                    f.write(data)


if __name__ == "__main__":
    main()
