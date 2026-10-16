#!/bin/bash
# An atop raw log written by `atop -w` (Debian trixie atop 2.11.1) in a
# container, host name fillyfoal: two samples a second apart. The process
# list is the container's own: this script's shell, a `sleep` and atop.
# Output lands in $OUT (default /tmp/fixtures/atop-raw).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/atop-raw}
mkdir -p "$OUT"
docker run --rm --hostname fillyfoal -e TZ=UTC -v "$HERE:/work:ro" -v "$OUT:/out" \
    debian:trixie bash /work/inside.sh
