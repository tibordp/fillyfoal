#!/bin/sh
# Writes tests/fixtures/external/chd/chdman-{hd,cd}.chd with chdman (amd64) from
# Debian bookworm's mame-tools (0.251), in Docker:
#   sh tests/data/chd/make-chdman.sh
# Outputs land in /tmp/fixtures/games-retro-chd/out.
#
# hd: a 64 KiB raw disk of 4 KiB hunks: distinct text hunks, a repeated
#     hunk (a self reference) and zero hunks, compressed with chdman's
#     default hard-disk codecs (lzma, zlib, huff, flac).
# cd: a cue sheet over a small xorriso ISO (Mode 1/2048), with chdman's
#     default CD codecs (cdlz, cdzl, cdfl).
set -e
out=/tmp/fixtures/games-retro-chd
mkdir -p "$out"
docker run --rm --platform linux/amd64 -v "$out:/w" debian:bookworm-slim sh -c '
  set -e
  apt-get update -qq >/dev/null
  apt-get install -y -qq mame-tools xorriso python3 >/dev/null
  cd /w && rm -rf in out && mkdir -p in/iso out
  python3 - <<"PY"
hunk = 4096
parts = []
for i in range(16):
    if i in (5, 9):
        parts.append(parts[2])           # repeats hunk 2
    elif i >= 12:
        parts.append(bytes(hunk))        # zeros
    else:
        text = "".join("hunk %02d line %03d of the fillyfoal CHD test\n" % (i, n) for n in range(200))
        parts.append(text.encode()[:hunk].ljust(hunk, b"."))
open("in/disk.img", "wb").write(b"".join(parts))
PY
  printf "first read file\n" > in/iso/README.TXT
  xorriso -as mkisofs -quiet -V FILLYFOAL -o in/cd.iso in/iso
  printf "FILE \"cd.iso\" BINARY\n  TRACK 01 MODE1/2048\n    INDEX 01 00:00:00\n" > in/cd.cue
  chdman createhd -i in/disk.img -o out/chdman-hd.chd -hs 4096 -f
  chdman createcd -i in/cd.cue -o out/chdman-cd.chd -f
  chdman info -i out/chdman-hd.chd
  chdman info -i out/chdman-cd.chd
  ls -l out'
