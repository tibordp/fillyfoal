#!/bin/sh
# Rebuilds tests/fixtures/external/xfsdump/specials.xfsdump.raw.zst and
# subtree.xfsdump.raw.zst (inner-specials.sh says what they hold), stored
# with `zstd -19`: a privileged Debian container (a loop device and a
# mount in the Docker VM's kernel), host name "fillyfoal", in a scratch
# directory outside the home directory:
#
#   sh tests/data/xfsdump/make-specials.sh [scratch dir]
#
# Not reproducible byte for byte: the dump session and media ids are
# random, and the inode generation numbers come from the kernel.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/disk-backup-xfsdump}
mkdir -p "$work"
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner-specials.sh
for f in specials subtree; do
  zstd -19 -q -f "$work/out/$f.xfsdump" -o "$repo/tests/fixtures/external/xfsdump/$f.xfsdump.raw.zst"
  chmod 644 "$repo/tests/fixtures/external/xfsdump/$f.xfsdump.raw.zst"
done
