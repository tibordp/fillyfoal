"""Exits 0 if the newest record in an XFS image's internal log is split
over the log's end (its header in the last blocks, its data continuing at
the log's start), printing it; 1 otherwise. See make-xfs-split.sh.

    python3 xfs-split-check.py IMAGE
"""
import struct
import sys

BB = 512
MAGIC = 0xFEEDBABE

with open(sys.argv[1], "rb") as f:
    sb = f.read(512)
    blocksize = struct.unpack(">I", sb[4:8])[0]
    logstart = struct.unpack(">Q", sb[48:56])[0]
    logblocks = struct.unpack(">I", sb[96:100])[0]
    f.seek(logstart * blocksize)
    log = f.read(logblocks * blocksize)

total = len(log) // BB
best = None  # (cycle, block, header)
for blk in range(total):
    h = log[blk * BB:(blk + 1) * BB]
    if struct.unpack(">I", h[:4])[0] != MAGIC:
        continue
    cycle, version, length = struct.unpack(">III", h[4:16])
    lsn_cycle, lsn_blk = struct.unpack(">II", h[16:24])
    if lsn_blk != blk or lsn_cycle != cycle:
        continue
    if best is None or (cycle, blk) > best[:2]:
        best = (cycle, blk, length, version)
if best is None:
    sys.exit(1)
cycle, blk, length, version = best
size = struct.unpack(">I", log[blk * BB + 320:blk * BB + 324])[0] if version == 2 else 0
headers = max(1, -(-size // 32768))
end = blk + headers + -(-length // BB)
if end > total:
    print(f"record at block {blk} of {total}, cycle {cycle}, {length} bytes: "
          f"ends at block {end - total} after wrapping")
    sys.exit(0)
sys.exit(1)
