#!/bin/sh
# Rebuilds tests/fixtures/external/fsarchiver/specials.fsa (inner-specials.sh
# says what it holds): a privileged Debian container, host name
# "fillyfoal", in a scratch directory outside the home directory:
#
#   sh tests/data/fsarchiver/make-specials.sh [scratch dir]
#
# Not byte-for-byte reproducible: the archive id, some access times and the
# mount point fsarchiver makes come from the real clock.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/disk-backup-fsarchiver}
mkdir -p "$work"
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner-specials.sh
cp "$work/out/specials.fsa" "$repo/tests/fixtures/external/fsarchiver/"
