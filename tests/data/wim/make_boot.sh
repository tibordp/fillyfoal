#!/bin/sh
# Builds tests/fixtures/external/wim/boot.wim with wimlib-imagex (Debian
# bookworm's wimtools, wimlib 1.13.x) in Docker: one XPRESS image of a
# two-file tree, marked bootable (--boot), so the header's boot metadata
# resource points at the image's metadata resource. Usage: make_boot.sh OUTDIR
set -e
out=$(cd "$1" && pwd)
docker run --rm -v "$out:/out" debian:bookworm-slim sh -c '
  set -e
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends wimtools >/dev/null
  mkdir -p /tmp/tree/sub
  printf "hello from the boot image\n" > /tmp/tree/hello.txt
  printf "fillyfoal\n" > /tmp/tree/sub/name.txt
  touch -d @1704164645 /tmp/tree/hello.txt /tmp/tree/sub/name.txt /tmp/tree/sub /tmp/tree
  cd /tmp
  wimcapture tree /out/boot.wim fillyfoal --boot --compress=XPRESS
  wimlib-imagex --version | head -n 1
'
