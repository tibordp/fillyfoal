#!/bin/sh
# Builds the LZMS WIM test files with wimlib-imagex (Debian bookworm's
# wimtools, wimlib 1.13.x) in Docker. Usage: make.sh OUTDIR
#
# lzms.wim, solid.esd and solid-lzx.wim are the fixtures in
# tests/fixtures/external/wim/; zeros.esd (16 MiB of zeros in one solid
# LZMS chunk) is test data here, for the codec's step-bound test.
#
# The input tree comes from make_tree.py; it is copied inside the container
# so no host metadata (owners, extended attributes) reaches the image.
set -e
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d /tmp/wimtree.XXXXXX)
python3 -I "$here/make_tree.py" "$work/tree"
docker run --rm -v "$work:/in:ro" -v "$out:/out" debian:bookworm-slim sh -c '
  set -e
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends wimtools >/dev/null
  cp -a /in/tree /tmp/tree
  cd /tmp
  # Non-solid LZMS, 32 KiB chunks so the larger files take several.
  wimcapture tree /out/lzms.wim fillyfoal --compress=LZMS --chunk-size=32768
  # Solid LZMS (an ESD-style WIM, version 3584), 32 KiB solid chunks.
  wimcapture tree /out/solid.esd fillyfoal --solid --solid-chunk-size=32768
  # A solid resource with LZX chunks, of the text file only.
  mkdir text && cp -a tree/notes.txt text/
  wimcapture text /out/solid-lzx.wim fillyfoal --solid --solid-compress=LZX --solid-chunk-size=32768
  mkdir zeros && head -c 16777216 /dev/zero > zeros/zero.bin
  touch -d @1600000000 zeros/zero.bin zeros
  wimcapture zeros /out/zeros.esd fillyfoal --solid --solid-chunk-size=16777216
  wimlib-imagex --version | head -n 1
'
rm -rf "$work"
