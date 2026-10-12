#!/bin/sh
# Builds the SHA-256 git fixtures with git in a Debian trixie container
# (inside-sha256.sh): a `git init --object-format=sha256` repository of
# three commits, repacked so the edited file becomes ofs-deltas, giving
# git-pack/sha256.pack, its index git-pack-index/sha256.idx and the
# staging-area index git-index/sha256.index. Dates, author and content are
# fixed, so the pack and its index are the same on every run; the
# staging-area index holds the files' stat data (times, device, inode),
# which is not.
#
#   sh tests/data/git-pack/sha256.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/system-git256
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -w /work debian:trixie sh /scripts/inside-sha256.sh
mkdir -p "$FIX/git-pack" "$FIX/git-pack-index" "$FIX/git-index"
cp "$B/out/sha256.pack" "$FIX/git-pack/sha256.pack"
cp "$B/out/sha256.idx" "$FIX/git-pack-index/sha256.idx"
cp "$B/out/sha256.index" "$FIX/git-index/sha256.index"
cat "$B/out/version.txt"
