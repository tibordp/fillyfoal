#!/bin/sh
# Builds the NSIS fixtures in tests/fixtures/external/nsis/ with makensis
# (NSIS 3.08, Debian bookworm's `nsis` package) in Docker:
#
#     sh tests/data/nsis/make.sh <repo>
#
# Each installer is compiled from installer.nsi with a different
# compressor; the fixture is the installer data makensis appends to its
# Windows stub (from the first header, found at a 512-byte boundary, to the
# end), cut out by cut.py so the stub's 40-odd KiB of x86 code stay out of
# the repository. Built in /tmp/fixtures/archive-nsis with fixed file times.
set -eu
repo=$(cd "${1:?usage: make.sh <repo>}" && pwd)
work=/tmp/fixtures/archive-nsis
rm -rf "$work"
mkdir -p "$work"
cp "$repo/tests/data/nsis/installer.nsi" "$work/"
docker run --rm -v "$work:/w" -w /w debian:bookworm-slim sh -c '
  set -e
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends nsis >/dev/null
  mkdir -p payload/docs
  i=0
  while [ $i -lt 60 ]; do
    echo "Line $i of the readme installed by a real NSIS installer." >> payload/readme.txt
    i=$((i + 1))
  done
  printf "[settings]\nname=fillyfoal\n" > payload/docs/config.ini
  touch -d "2024-01-02 03:04:05" payload/readme.txt payload/docs/config.ini
  makensis -VERSION
  makensis -V2 -DCOMPRESSOR="/SOLID lzma" -DUNICODE=true -DOUT=lzma-solid-unicode.exe installer.nsi
  makensis -V2 -DCOMPRESSOR=zlib -DUNICODE=false -DOUT=zlib-ansi.exe installer.nsi
  makensis -V2 -DCOMPRESSOR=bzip2 -DUNICODE=true -DOUT=bzip2-unicode.exe installer.nsi
'
mkdir -p "$repo/tests/fixtures/external/nsis"
for exe in lzma-solid-unicode zlib-ansi bzip2-unicode; do
  python3 -I "$repo/tests/data/nsis/cut.py" "$work/$exe.exe" "$repo/tests/fixtures/external/nsis/$exe.bin"
done
