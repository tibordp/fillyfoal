#!/bin/sh
# Builds the git-commit-graph fixtures with git in a Debian trixie
# container (inside.sh): a small history with fixed authors, dates and
# content, so every run gives the same files.
#
#   commit-graph       `git commit-graph write --reachable --changed-paths`:
#                      OIDF, OIDL, CDAT, GDA2, GDO2 (a commit dated in 2100
#                      followed by one dated 1970), EDGE (an octopus merge),
#                      BIDX/BDAT (changed-path Bloom filters);
#   split-base.graph,  a two-layer chain (`--split=no-merge` twice); the top
#   split-top.graph    layer has a BASE chunk naming the base layer;
#   sha256.graph       the same history in a SHA-256 repository.
#
#   sh tests/data/git-commit-graph/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/commit-graph
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm --hostname fillyfoal -v "$B:/work" -v "$SRC:/scripts:ro" -w /work \
  debian:trixie sh /scripts/inside.sh
mkdir -p "$FIX/git-commit-graph"
for f in commit-graph split-base.graph split-top.graph sha256.graph; do
  cp "$B/out/$f" "$FIX/git-commit-graph/$f"
  chmod 644 "$FIX/git-commit-graph/$f"
done
cat "$B/out/version.txt"
