"""Writes classic.act: a Photoshop colour table in the original 768-byte
form (256 RGB triples, no count or transparent index), from the layout in
Adobe's Photoshop File Formats Specification. A 768-byte file has nothing
to check, so it is identified only by its `.act` name (second-phase probe).

Usage: python3 make.py OUT_DIR
"""

import sys
from pathlib import Path

out = Path(sys.argv[1])
# A ramp from black to white, with a red, green and blue entry first.
table = bytearray()
for i in range(256):
    table += bytes((i, i, i))
table[0:9] = bytes((0xFF, 0, 0, 0, 0xFF, 0, 0, 0, 0xFF))
assert len(table) == 768
(out / "classic.act").write_bytes(bytes(table))
