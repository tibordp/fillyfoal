"""Hand-built TempleOS binary modules (CBinFile) for the templeos-bin tests.

    python3 tests/data/templeos-bin/make_crafted.py OUT_DIR

Layout as `Cmp` (Compiler/CMain.HC) writes it and `Load` (Kernel/KLoad.HC)
reads it: a 32-byte header (EB 1E jump, module_align_bits, reserved,
'TOSB', org, patch_table_offset, file_size), the image, then the patch
table: entries of type byte, U32 value, NUL-terminated name, and for
IET_ABS_ADDR / *_HEAP a heap size and `value` U32 offsets; IET_END, 16
zero bytes, padded to 16.

- `crafted.BIN`: one entry of every kind the real compiler and kernel do
  not contain (heap globals, immediate exports, import runs of several
  widths, an unnamed first import, an unknown entry type), so their paths
  are covered.
- `not-kernel.BIN`: a module whose image starts with a 16-bit near jump and
  a NOP like the kernel's CKernel, but jumping past the image; it must stay
  a plain module, not `templeos-kernel`.

Synthetic: written by this script.
"""

import os
import struct
import sys

IET_REL_I0, IET_IMM_U8, IET_REL_I16, IET_REL_I32, IET_IMM_U32, IET_REL_I64 = 2, 5, 6, 8, 9, 10
IET_REL32_EXPORT, IET_IMM32_EXPORT = 16, 17
IET_ABS_ADDR, IET_ZEROED_CODE_HEAP, IET_DATA_HEAP, IET_MAIN = 20, 22, 23, 25


def entry(kind, value, name=b"", extra=b""):
    return struct.pack("<BI", kind, value) + name + b"\0" + extra


def offsets(*v):
    return struct.pack(f"<{len(v)}I", *v)


def module(image, table, align_bits=0, org=0x7FFF_FFFF_FFFF_FFFF):
    table = table + b"\0" + bytes(16)
    size = (32 + len(image) + len(table) + 15) & -16
    header = struct.pack(
        "<HBB4sqqq", 0x1EEB, align_bits, 0, b"TOSB", org, 32 + len(image), size
    )
    out = header + image + table
    return out + bytes(size - len(out))


def crafted():
    # main: PUSH RBP; MOV RBP,RSP; CALL rel32 (import); LEAVE; RET; then data.
    image = bytes.fromhex("55488bece800000000c9c3") + bytes(21)
    table = b"".join(
        [
            entry(IET_ABS_ADDR, 2, b"", offsets(0x10, 0x14)),
            entry(IET_DATA_HEAP, 2, b"counter", struct.pack("<q", 8) + offsets(0x18, 0x1C)),
            entry(IET_DATA_HEAP, 1, b"", struct.pack("<q", 64) + offsets(0x18)),
            entry(IET_ZEROED_CODE_HEAP, 1, b"stub", struct.pack("<i", 16) + offsets(0x10)),
            entry(IET_REL32_EXPORT, 0, b"Main"),
            entry(IET_IMM32_EXPORT, 0x1234, b"ANSWER"),
            entry(IET_REL_I32, 5, b"Print"),
            entry(IET_IMM_U8, 0x0B),
            entry(IET_REL_I16, 0x0C),
            entry(IET_REL_I64, 0x10),
            entry(IET_REL_I0, 0x00),
            entry(IET_IMM_U32, 0x14, b"sys_var"),
            entry(IET_REL_I32, 0x18),
            entry(12, 0x99, b"future"),
            entry(IET_REL_I32, 0x1C),
            entry(IET_MAIN, 0),
        ]
    )
    return module(image, table, align_bits=4)


def not_kernel():
    # JMP I16 far past the image, NOP, RET.
    image = bytes.fromhex("e9f0ff90c3") + bytes(11)
    table = entry(IET_REL32_EXPORT, 4, b"Start") + entry(IET_MAIN, 4)
    return module(image, table)


def main():
    out = sys.argv[1]
    for name, data in (("crafted.BIN", crafted()), ("not-kernel.BIN", not_kernel())):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main()
