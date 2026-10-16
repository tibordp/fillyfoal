#!/bin/sh
# Rebuilds tests/fixtures/external/criu-image/: the images `criu dump`
# (CRIU 4.1.1 from Debian 13, aarch64, in a privileged Docker container,
# host name "fillyfoal") writes for `sleep 1000` started with an empty
# environment (HOME=/, PATH=/bin:/usr/bin) in its own session. Everything
# but pages-1.img (raw page data with no magic, which is not this format)
# is copied; the PID-numbered names depend on the run.
#
#   sh tests/data/criu-image/make-external.sh [scratch dir]
#
# Uses the image built from tests/data/qemu-vmstate/Dockerfile. Check what
# the images hold before committing (`crit show`): paths are the
# container's, the time namespace offsets are the Docker VM's uptime.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/criu-image}
rm -rf "$work/out"
mkdir -p "$work/out"
docker build -q -t fillyfoal-vmstate-tools "$repo/tests/data/qemu-vmstate"
docker run --rm --privileged --hostname fillyfoal -v "$work/out:/out" -v "$here:/scripts:ro" \
  fillyfoal-vmstate-tools sh /scripts/inner.sh
dst="$repo/tests/fixtures/external/criu-image"
mkdir -p "$dst"
for f in "$work"/out/*; do
  case "$(basename "$f")" in
    pages-*.img) ;;
    *) cp "$f" "$dst/" ;;
  esac
done
