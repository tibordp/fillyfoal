#!/bin/sh
# Builds git-pack/signed.pack with git in a Debian trixie container
# (inside.sh): SSH-signed commits and tag (multi-line gpgsig headers),
# ofs-deltas. The signing key is generated per run, so signatures and
# hence object IDs differ between runs.
#
#   sh tests/data/git-pack/signed.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/system-git
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -w /work debian:trixie sh /scripts/inside.sh
mkdir -p "$FIX/git-pack"
cp "$B/out/signed.pack" "$FIX/git-pack/signed.pack"
cat "$B/out/version.txt"
