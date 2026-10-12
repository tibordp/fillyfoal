#!/bin/sh
# Makes the ISO 9660 image under tests/data/saturn/raw.py's fixture with
# xorriso (Debian bookworm), in Docker:
#   sh tests/data/saturn/make-raw.sh
set -e
out=/tmp/fixtures/games-retro-saturn
mkdir -p "$out"
docker run --rm -v "$out:/w" debian:bookworm-slim sh -c '
  set -e
  apt-get update -qq >/dev/null && apt-get install -y -qq xorriso >/dev/null
  rm -rf /w/root && mkdir -p /w/root
  printf "first read file\n" > /w/root/0.BIN
  xorriso -as mkisofs -quiet -no-pad -V FILLYFOAL -o /w/base.iso /w/root
  ls -l /w/base.iso'
