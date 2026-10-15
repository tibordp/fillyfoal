#!/bin/sh
# Real-tool fixtures for 7-Zip's AES-256 coder (7zAES), password `fillyfoal`.
# Runs 7-Zip in Docker (Debian trixie's `7zip` package) and writes into a
# neutral scratch directory; copy the results to tests/fixtures/external/7z/
# by hand. Not byte-for-byte reproducible: 7-Zip draws a random IV for every
# encrypted folder.
#
#   7-Zip 25.01 (Debian 25.01+dfsg-1~deb13u2, arm64), in debian:trixie
#
# Usage: sh tests/data/7z/make_aes.sh [outdir]   (default /tmp/fixtures/7z-aes)
set -eu
if [ "${1:-}" = "--inside" ]; then
  # In the container: /out holds code.bin; everything else is made here.
  apt-get update -qq > /dev/null
  apt-get install -y -qq 7zip > /dev/null 2>&1
  dpkg-query -W 7zip
  cd /out
  rm -rf src ./*.7z
  mkdir -p src/notes
  printf 'The quick brown fox jumps over the lazy dog.\n' > src/fox.txt
  i=0
  while [ $i -lt 40 ]; do
    printf 'Line %d: lorem ipsum dolor sit amet, consectetur adipiscing elit.\n' $i
    i=$((i + 1))
  done > src/notes/lorem.txt
  printf 'one\ntwo\nthree\n' > src/notes/list.txt
  cp code.bin src/code.bin
  find src -exec touch -d '2024-01-02 03:04:00 UTC' {} +
  cd src
  # Header encryption: the encoded header is AES + LZMA2, so is the data.
  7z a -t7z -pfillyfoal -mhe=on -m0=LZMA2 ../aes-header-lzma2.7z fox.txt notes > /dev/null
  # Data encryption only, LZMA, one solid folder; the header is LZMA (plain).
  7z a -t7z -pfillyfoal -mhe=off -m0=LZMA -ms=on ../aes-data-lzma-solid.7z fox.txt notes > /dev/null
  # A filter chain: BCJ (x86) + LZMA2 + AES, with a plain header (which
  # tests patch).
  7z a -t7z -pfillyfoal -mhe=off -mhc=off -mf=BCJ -m0=LZMA2 ../aes-bcj-lzma2.7z code.bin > /dev/null
  # The empty password (7-Zip reads it from the terminal prompt).
  printf '\n' | 7z a -t7z -p -mhe=on -m0=LZMA2 ../aes-empty-password.7z fox.txt > /dev/null
  cd ..
  rm -rf src
  ls -l ./*.7z
  exit 0
fi
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/tmp/fixtures/7z-aes}
mkdir -p "$out"
python3 -I "$here/../xz/bcjdata.py" "$out/code.bin"
docker run --rm --name fillyfoal-7zaes -v "$out:/out" -v "$here:/scripts:ro" \
  debian:trixie sh /scripts/make_aes.sh --inside
rm -f "$out/code.bin"
