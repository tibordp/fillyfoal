#!/bin/sh
# Writes the external OSTree and flatpak fixtures with libostree 2025.2
# and flatpak 1.16.1 from Alpine 3.22 (needs Docker):
#
#   sh tests/data/ostree/make.sh OUTDIR
#
# ostree.sh: objects of an archive-mode repository holding two commits of
# a small tree (ostree-commit, ostree-commitmeta, ostree-dirtree,
# ostree-dirmeta, ostree-filez), its summary (ostree-summary), a
# self-contained static delta with its part inline and a delta between
# the commits whose part is a file of its own (ostree-delta,
# ostree-delta-part).
# flatpak.sh: a bundle (flatpak build-bundle) of a hand-made app.
#
# Commit times are fixed; summaries, delta superblocks and bundles record
# the time they were written, so reruns differ in those bytes (and in the
# checksums of the parts that hold them).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$1" && pwd)
docker run --rm -v "$here:/scripts:ro" -v "$out:/out" alpine:3.22 sh -c '
set -eu
apk add --no-cache ostree flatpak >/dev/null
sh /scripts/ostree.sh /out
sh /scripts/flatpak.sh /out
'
