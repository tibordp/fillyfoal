"""Writes the synthetic COFF objects in tests/fixtures/synthetic/coff:

- `nreloc-ovfl.obj`: an x64 object whose `.data` section has
  IMAGE_SCN_LNK_NRELOC_OVFL set and NumberOfRelocations 0xffff, so the first
  relocation's VirtualAddress holds the real count (4: itself and three
  ADDR64 relocations). Real objects only do this past 65,535 relocations
  (clang writes it for `--target=x86_64-pc-windows-msvc` objects with
  70,000 relocations), which is too large for a fixture; the layout is the
  one clang/LLVM `WinCOFFObjectWriter` writes and lld-link reads.
- `ltcg.obj`: the anonymous object header (ANON_OBJECT_HEADER, Version 1)
  of an object compiled with MSVC's `/GL`, with the ClassID that lld-link 19
  rejects as "not a native COFF file. Recompile without /GL", followed by
  48 bytes standing in for the compiler's (undocumented) IL.

    python3 tests/data/coff/make_synthetic.py [output directory]
"""

import struct
import sys
from pathlib import Path

out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "fixtures/synthetic/coff"

# nreloc-ovfl.obj
data = bytes(range(16))
relocs = struct.pack("<IIH", 4, 0, 0)  # the count record, itself included
for va in (0, 8, 4):
    relocs += struct.pack("<IIH", va, 0, 1)  # IMAGE_REL_AMD64_ADDR64 -> symbol 0
raw_at = 20 + 40
reloc_at = raw_at + len(data)
sym_at = reloc_at + len(relocs)
header = struct.pack("<HHIIIHH", 0x8664, 1, 0, sym_at, 1, 0, 0)
section = struct.pack(
    "<8sIIIIIIHHI",
    b".data",
    0,
    0,
    len(data),
    raw_at,
    reloc_at,
    0,
    0xFFFF,
    0,
    0x01000000 | 0xC0000040 | 0x00500000,  # NRELOC_OVFL, data, r/w, align 16
)
symbol = struct.pack("<8sIhHBB", b"filly", 0, 1, 0, 2, 0)
strings = struct.pack("<I", 4)
(out / "nreloc-ovfl.obj").write_bytes(header + section + data + relocs + symbol + strings)

# ltcg.obj
CLASS_ID = bytes.fromhex("38feb30ca5d9ab4dac9bd6b6222653c2")
il = bytes((i * 7) & 0xFF for i in range(48))
anon = struct.pack("<HHHHI", 0, 0xFFFF, 1, 0x8664, 0x5F000000) + CLASS_ID + struct.pack("<I", len(il))
(out / "ltcg.obj").write_bytes(anon + il)
