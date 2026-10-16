#!/bin/sh
# Rebuilds tests/fixtures/external/pbs-didx/, pbs-fidx/ and pbs-catalog/
# with Proxmox Backup Server and client 3.4.9 (Proxmox's bookworm
# repository): inner.sh starts a throwaway server in the container, backs
# up a small directory tree holding every entry kind (as a pxar archive)
# and a sparse 9 MiB image, and copies out the snapshot's dynamic index,
# fixed index and catalog. Build the image first (see
# tests/data/proxmox/Dockerfile), then:
#
#   sh tests/data/pbs-index/make-external.sh [scratch dir]
#
# Not reproducible byte for byte (UUIDs, chunk digests of the random data
# and the catalog's chunking vary).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/pbs-index}
mkdir -p "$work"
docker run --rm --platform linux/amd64 --tmpfs /run --hostname fillyfoal -v "$work:/out" -v "$here:/data:ro" \
  fillyfoal-proxmox:bookworm bash /data/inner.sh
ext="$repo/tests/fixtures/external"
mkdir -p "$ext/pbs-didx" "$ext/pbs-fidx" "$ext/pbs-catalog"
cp "$work/files.pxar.didx" "$ext/pbs-didx/files.pxar.didx"
cp "$work/disk.img.fidx" "$ext/pbs-fidx/disk.img.fidx"
cp "$work/catalog.pcat1" "$ext/pbs-catalog/catalog.pcat1"
