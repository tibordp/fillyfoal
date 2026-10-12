"""Synthetic pre-027 VDEX files: tests/fixtures/synthetic/vdex/v006.vdex
(Android 8), v019.vdex (Android 9) and v021.vdex (Android 10/11), each
holding tests/fixtures/synthetic/dex/classes.dex.

    python3 tests/data/vdex/legacy.py

Header layouts from ART's vdex_file.h of each release: 006 has one header
(magic, version, number_of_dex_files, dex_size, verifier_deps_size,
quickening_info_size) followed by the DEX checksums and the DEX files; 019
has a verifier-deps header (magic, version, dex section version "002",
number_of_dex_files, verifier_deps_size), the checksums, then a DEX section
header (dex_size, dex_shared_data_size, quickening_info_size); 021 adds
bootclasspath_checksums_size and class_loader_context_size to the first
header. The verifier dependencies are placeholder bytes.
"""

import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "..", "fixtures", "synthetic")


def main():
    dex = open(os.path.join(FIX, "dex", "classes.dex"), "rb").read()
    checksum = struct.unpack_from("<I", dex, 8)[0]
    deps = b"\0" * 8
    out = os.path.join(FIX, "vdex")
    os.makedirs(out, exist_ok=True)

    v006 = b"vdex006\0" + struct.pack("<IIII", 1, len(dex), len(deps), 0)
    v006 += struct.pack("<I", checksum) + dex + deps

    v019 = b"vdex019\x00002\x00" + struct.pack("<II", 1, len(deps))
    v019 += struct.pack("<I", checksum)
    v019 += struct.pack("<III", len(dex), 0, 0) + dex + deps

    v021 = b"vdex021\x00002\x00" + struct.pack("<IIII", 1, len(deps), 0, 0)
    v021 += struct.pack("<I", checksum)
    v021 += struct.pack("<III", len(dex), 0, 0) + dex + deps

    for name, data in (("v006.vdex", v006), ("v019.vdex", v019), ("v021.vdex", v021)):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
    assert zlib.adler32(dex[12:]) == struct.unpack_from("<I", dex, 8)[0]


if __name__ == "__main__":
    main()
