#!/bin/sh
# Rebuilds the split-archive fixtures that Proxmox Backup Server's client
# 3.4.9 writes with --change-detection-mode=metadata (Proxmox's bookworm
# repository):
#
#   tests/fixtures/external/pxar-meta/backup-1.mpxar             first run
#   tests/fixtures/external/pxar-meta/backup-2.mpxar             second run
#   tests/fixtures/external/pxar-payload/backup-2.ppxar.raw.zst  its payloads
#
# split-inner.sh starts a throwaway server in the container, backs up a
# directory of 100 files of 100 KB, a text file in a subdirectory and a file
# with a capability (cap_net_raw+ep), changes one file and adds one, backs
# it up again, and concatenates the decoded chunks of each snapshot's
# .mpxar.didx and .ppxar.didx. The second payload stream reuses chunks of
# the first, so it holds the first run's start and tail markers. Build the
# image first (see tests/data/proxmox/Dockerfile), then:
#
#   sh tests/data/pxar/make-split.sh [scratch dir]
#
# Not reproducible byte for byte: which chunks the second run reuses, and
# so the payload offsets, can vary.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/pxar-split}
mkdir -p "$work"
docker run --rm --platform linux/amd64 --tmpfs /run --hostname fillyfoal -v "$work:/out" -v "$here:/data:ro" \
  fillyfoal-proxmox:bookworm bash /data/split-inner.sh
cp "$work/snap1/x.mpxar" "$repo/tests/fixtures/external/pxar-meta/backup-1.mpxar"
cp "$work/snap2/x.mpxar" "$repo/tests/fixtures/external/pxar-meta/backup-2.mpxar"
zstd -19 --long=27 -q -f "$work/snap2/x.ppxar" -o "$repo/tests/fixtures/external/pxar-payload/backup-2.ppxar.raw.zst"
