"""Writes the external torrent fixtures with libtorrent:

    uv run --with libtorrent==2.1.1 python3 -I tests/data/torrent/make.py OUTDIR

Builds a small directory `payload` (two files, ~71 KB) in OUTDIR and writes
`v1.torrent` (v1 only), `v2.torrent` (v2 only, BEP 52) and `hybrid.torrent`
(v1 + v2, with BEP 47 padding files) with 16 KiB pieces. The creation date is
fixed and the creator set to "fillyfoal" so the files are reproducible.
"""

import os
import shutil
import sys

import libtorrent as lt

out = os.path.abspath(sys.argv[1])
os.chdir(out)
shutil.rmtree("payload", ignore_errors=True)
os.makedirs("payload/sub")
with open("payload/readme.txt", "wb") as f:
    f.write(b"fillyfoal torrent fixture\n" * 1000)
with open("payload/sub/data.bin", "wb") as f:
    f.write(bytes(i * 7 % 251 for i in range(45000)))

for name, flags in [
    ("v1.torrent", lt.create_torrent.v1_only),
    ("v2.torrent", lt.create_torrent.v2_only),
    ("hybrid.torrent", 0),
]:
    fs = lt.file_storage()
    lt.add_files(fs, "payload")
    ct = lt.create_torrent(fs, 16384, flags=flags)
    ct.set_creator("fillyfoal")
    lt.set_piece_hashes(ct, ".")
    entry = ct.generate()
    entry[b"creation date"] = 1700000000
    with open(name, "wb") as f:
        f.write(lt.bencode(entry))

shutil.rmtree("payload")
