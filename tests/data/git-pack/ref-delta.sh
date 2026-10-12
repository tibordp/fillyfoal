#!/bin/sh
# Builds git-pack/ref-delta.pack and git-pack/thin.pack with git in a
# Debian trixie container (inside-ref-delta.sh). `git pack-objects`
# without `--delta-base-offset` names every delta base by object ID
# (ref-deltas), as the old wire protocol does; ref-delta.pack holds the
# whole history (bases in the pack, deltas on deltas), thin.pack only the
# last commit's objects with `--thin`, so its delta's base is outside the
# pack. Dates, author and content are fixed, so both packs are the same on
# every run.
#
#   sh tests/data/git-pack/ref-delta.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/system-git-ref
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -w /work debian:trixie sh /scripts/inside-ref-delta.sh
mkdir -p "$FIX/git-pack"
cp "$B/out/ref-delta.pack" "$FIX/git-pack/ref-delta.pack"
cp "$B/out/thin.pack" "$FIX/git-pack/thin.pack"
cat "$B/out/version.txt"
