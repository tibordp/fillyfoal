#!/bin/sh
# Rebuilds tests/fixtures/external/pbs-blob/ with Proxmox Backup Server and
# client 3.4.9 (Proxmox's bookworm repository): inner.sh starts a throwaway
# server in the container, backs up a two-file directory (as a pxar
# archive) and a 4 KiB random image, once plain and once encrypted with a
# fresh key file, and copies out the snapshot's index.json.blob and one
# chunk of each blob kind. Build the image first (see
# tests/data/proxmox/Dockerfile), then:
#
#   sh tests/data/pbs-blob/make-external.sh [scratch dir]
#
# Not reproducible byte for byte (keys, IVs and the random image vary).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/pbs-blob}
mkdir -p "$work"
docker run --rm --platform linux/amd64 --tmpfs /run --hostname fillyfoal -v "$work:/out" -v "$here:/data:ro" \
  fillyfoal-proxmox:bookworm bash /data/inner.sh
mkdir -p "$repo/tests/fixtures/external/pbs-blob"
for f in index.json uncompressed-chunk compressed-chunk encrypted-chunk encrypted-compressed-chunk pxar-chunk; do
  cp "$work/$f.blob" "$repo/tests/fixtures/external/pbs-blob/$f.blob"
done
