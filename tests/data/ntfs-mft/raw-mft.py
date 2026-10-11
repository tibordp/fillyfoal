"""Copies the $MFT of an NTFS volume out byte for byte, as stored on disk.

ntfscat returns the records with the update sequence fixups applied, so the
copy would not be what forensic tools export (icat, FTK, MFTECmd input). This
follows record 0's unnamed $DATA runlist and concatenates the raw clusters,
cut to the stream's data size.

    python3 raw-mft.py VOLUME OUT
"""

import struct
import sys


def runs(data):
    at, lcn = 0, 0
    while at < len(data) and data[at]:
        head = data[at]
        nlen, noff = head & 0xF, head >> 4
        count = int.from_bytes(data[at + 1 : at + 1 + nlen], "little")
        off = data[at + 1 + nlen : at + 1 + nlen + noff]
        at += 1 + nlen + noff
        if noff:
            lcn += int.from_bytes(off, "little", signed=True)
            yield count, lcn
        else:
            yield count, None


def main(volume, out):
    with open(volume, "rb") as f:
        vol = f.read()
    sector = struct.unpack_from("<H", vol, 11)[0]
    cluster = sector * vol[13]
    mft_lcn = struct.unpack_from("<Q", vol, 0x30)[0]
    rec = bytearray(vol[mft_lcn * cluster : mft_lcn * cluster + 1024])
    usa, count = struct.unpack_from("<HH", rec, 4)
    for i in range(1, count):
        rec[i * 512 - 2 : i * 512] = rec[usa + 2 * i : usa + 2 * i + 2]
    at = struct.unpack_from("<H", rec, 20)[0]
    while True:
        kind, length = struct.unpack_from("<II", rec, at)
        if kind == 0xFFFFFFFF:
            sys.exit("record 0 has no $DATA")
        if kind == 0x80 and rec[at + 8] and rec[at + 9] == 0:
            break
        at += length
    attr = rec[at : at + length]
    size = struct.unpack_from("<Q", attr, 48)[0]
    runlist = attr[struct.unpack_from("<H", attr, 32)[0] :]
    data = bytearray()
    for n, lcn in runs(runlist):
        if lcn is None:
            data += bytes(n * cluster)
        else:
            data += vol[lcn * cluster : (lcn + n) * cluster]
    with open(out, "wb") as f:
        f.write(data[:size])


main(sys.argv[1], sys.argv[2])
