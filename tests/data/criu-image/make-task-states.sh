#!/bin/sh
# Rebuilds the task-state fixtures of tests/fixtures/external/criu-image/
# (stopped-core-*.img, zombie-core-*.img, zombie-pstree.img): `criu dump`
# (CRIU 4.1.1, Debian 13, privileged Docker container, host name
# "fillyfoal") of a stopped `sleep` and of a `sleep` with a zombie child.
# The PIDs in the names depend on the run (7 and 20 when committed); the
# zombie's core image is the small one.
#
#   sh tests/data/criu-image/make-task-states.sh [scratch dir]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/criu-image-states}
rm -rf "$work/out"
mkdir -p "$work/out"
docker build -q -t fillyfoal-vmstate-tools "$repo/tests/data/qemu-vmstate"
docker run --rm --privileged --hostname fillyfoal -v "$work/out:/out" -v "$here:/scripts:ro" \
  fillyfoal-vmstate-tools sh /scripts/inner-task-states.sh
dst="$repo/tests/fixtures/external/criu-image"
for f in "$work"/out/stopped/core-*.img; do cp "$f" "$dst/stopped-$(basename "$f")"; done
for f in "$work"/out/zombie/core-*.img; do
  # The zombie's core holds only the task core (a few dozen bytes).
  if [ "$(wc -c <"$f")" -lt 256 ]; then cp "$f" "$dst/zombie-$(basename "$f")"; fi
done
cp "$work/out/zombie/pstree.img" "$dst/zombie-pstree.img"
