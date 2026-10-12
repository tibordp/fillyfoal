#!/bin/sh
# Writes the external KF8, LRF and eReader fixtures with calibre 6.13
# (debian:bookworm-slim, `apt-get install --no-install-recommends calibre`;
# needs Docker):
#
#   sh tests/data/mobi/calibre-kf8.sh OUTDIR
#
# book.txt is ~3 KB of generated sentences.
# - mobi/calibre-kf8.azw3: `ebook-convert book.txt x.azw3` (KF8 only: MOBI
#   header version 8, FDST, skeleton/fragment INDX records)
# - mobi/calibre-both.mobi: `ebook-convert book.txt x.mobi
#   --mobi-file-type both` (MOBI 6 followed by a BOUNDARY record and the KF8
#   half; EXTH 121 points at the KF8 record 0)
# - lrf/calibre.lrf: `ebook-convert book.txt x.lrf` (Sony BBeB)
# - palm-pdb/calibre-ereader.pdb: `ebook-convert book.txt x.pdb --format ereader`
# calibre records the conversion time and a random UUID, so a re-run
# differs in those bytes. IMAGE may name a prepared image with calibre.
set -eu
out=$(cd "$1" && pwd)
docker run --rm -v "$out:/out" "${IMAGE:-debian:bookworm-slim}" sh -c '
set -eu
if ! command -v ebook-convert >/dev/null; then
    apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends calibre >/dev/null 2>&1
fi
cd /tmp
python3 -I - <<EOF
words = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima".split()
lines = []
for i in range(48):
    w = [words[(i * 7 + k * 3) % len(words)] for k in range(6 + i % 5)]
    lines.append("Sentence %d tells of %s." % (i, " ".join(w)))
open("/tmp/book.txt", "w").write("\n\n".join(lines) + "\n")
EOF
m="--title Fillyfoal-Sample --authors fillyfoal"
ebook-convert book.txt kf8.azw3 $m >/dev/null
ebook-convert book.txt both.mobi --mobi-file-type both $m >/dev/null
ebook-convert book.txt book.lrf $m >/dev/null
ebook-convert book.txt ereader.pdb --format ereader $m >/dev/null
mkdir -p /out/mobi /out/lrf /out/palm-pdb
cp kf8.azw3 /out/mobi/calibre-kf8.azw3
cp both.mobi /out/mobi/calibre-both.mobi
cp book.lrf /out/lrf/calibre.lrf
cp ereader.pdb /out/palm-pdb/calibre-ereader.pdb
'
