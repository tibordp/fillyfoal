"""Write a tiny seed Impulse Tracker module (seed.it) that is then opened in OpenMPT
and re-saved by OpenMPT itself (all shipped files are written by OpenMPT).

Contents: title "fillyfoal test", sample mode, 2 mono synthetic samples
(8-bit sine, 16-bit square, both looped), 1 pattern of 32 rows, 2 channels.
Usage: python -I make_seed_it.py <out.it>
"""
import math
import struct
import sys

out = sys.argv[1]

N = 256
sine8 = bytes((int(round(100 * math.sin(2 * math.pi * i / 64))) & 0xFF) for i in range(N))
square16 = b"".join(struct.pack("<h", 12000 if (i // 32) % 2 == 0 else -12000) for i in range(N))
samples = [("fillyfoal sine", sine8, False), ("fillyfoal square", square16, True)]

# Pattern (packed IT format)
rows = 32
events = {0: [(0, 60, 1)], 8: [(1, 64, 2)], 16: [(0, 67, 1)], 24: [(0, 255, 0), (1, 255, 0)]}
pat = bytearray()
for r in range(rows):
    for ch, note, ins in events.get(r, []):
        if ins:
            pat += bytes([0x80 | (ch + 1), 0x03, note, ins])
        else:
            pat += bytes([0x80 | (ch + 1), 0x01, note])
    pat += b"\x00"
pattern = struct.pack("<HHI", len(pat), rows, 0) + bytes(pat)

orders = bytes([0, 255])
ordnum, insnum, smpnum, patnum = len(orders), 0, len(samples), 1

hdr = bytearray()
hdr += b"IMPM" + b"fillyfoal test".ljust(26, b"\0")
hdr += struct.pack("<H", 0x1004)  # pattern row highlight 4/16
hdr += struct.pack("<HHHHHHHH", ordnum, insnum, smpnum, patnum, 0x0214, 0x0214, 0x0009, 0x0000)
hdr += bytes([128, 48, 6, 125, 128, 0])
hdr += struct.pack("<HII", 0, 0, 0)
hdr += bytes([32, 32] + [32 | 0x80] * 62)  # channel pan (2 enabled)
hdr += bytes([64] * 64)
assert len(hdr) == 192

table_len = ordnum + 4 * (insnum + smpnum + patnum)
smp_hdr_off = 192 + table_len
pat_off = smp_hdr_off + 80 * smpnum
data_off = pat_off + len(pattern)

smp_hdrs = bytearray()
data = bytearray()
for name, pcm, is16 in samples:
    length = len(pcm) // (2 if is16 else 1)
    flg = 0x01 | (0x02 if is16 else 0) | 0x10
    h = b"IMPS" + b"".ljust(12, b"\0") + b"\0" + bytes([64, flg, 64])
    h += name.encode().ljust(26, b"\0") + bytes([0x01, 32])
    h += struct.pack("<IIIIIII", length, 0, length, 8363 * 4 if not is16 else 8363 * 2, 0, 0,
                     data_off + len(data))
    h += bytes([0, 0, 0, 0])
    assert len(h) == 80
    smp_hdrs += h
    data += pcm

f = bytearray(hdr) + orders
f += b"".join(struct.pack("<I", smp_hdr_off + 80 * i) for i in range(smpnum))
f += struct.pack("<I", pat_off)
f += smp_hdrs + pattern + data
open(out, "wb").write(f)
print(out, len(f))
