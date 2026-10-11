#!/bin/sh
# Writes the external MOBI and PalmDOC fixtures with calibre 6.13
# (debian:bookworm-slim, `apt-get install --no-install-recommends calibre`;
# needs Docker):
#
#   sh tests/data/mobi/calibre.sh OUTDIR
#
# book.txt is ~14 KB of generated sentences (several 4 KiB text records).
# - mobi/calibre.mobi: `ebook-convert book.txt calibre.mobi
#   --mobi-file-type old` (MOBI 6, PalmDOC LZ77, trailing entries)
# - palmdoc/calibre.pdb: `ebook-convert book.txt calibre.pdb --format doc`
#   (PalmDOC, LZ77)
# calibre records the conversion time and a random UUID, so a re-run
# differs in those bytes.
set -eu
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm -v "$out:/out" -v "$here:/gen:ro" debian:bookworm-slim sh /gen/calibre-inner.sh
