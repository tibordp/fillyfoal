#!/bin/sh
# Rebuilds the Proxmox file archive fixtures with `pxar create` from
# proxmox-backup-client 3.4.9 (Proxmox's bookworm repository):
#
#   tests/fixtures/external/pxar/archive.pxar         a plain archive
#   tests/fixtures/external/pxar-meta/split.mpxar     the same tree split:
#   tests/fixtures/external/pxar-payload/split.ppxar  metadata and payloads
#
# of a small tree with a subdirectory, a symlink, a hard link, a FIFO, a
# character device, an empty file, an xattr, an access ACL and a default
# ACL, every mtime fixed, owned by root. Build the image first (see
# tests/data/proxmox/Dockerfile), then:
#
#   sh tests/data/pxar/make-external.sh [scratch dir]
#
# The output is reproducible for the same client version.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/pxar}
mkdir -p "$work"
docker run --rm --platform linux/amd64 --hostname fillyfoal -v "$work:/out" -v "$here:/data:ro" \
  fillyfoal-proxmox:bookworm bash /data/inner.sh
for d in pxar pxar-meta pxar-payload; do mkdir -p "$repo/tests/fixtures/external/$d"; done
cp "$work/archive.pxar" "$repo/tests/fixtures/external/pxar/archive.pxar"
cp "$work/split.mpxar" "$repo/tests/fixtures/external/pxar-meta/split.mpxar"
cp "$work/split.ppxar" "$repo/tests/fixtures/external/pxar-payload/split.ppxar"
