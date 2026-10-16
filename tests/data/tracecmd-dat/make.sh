#!/bin/bash
# Records the trace-cmd fixtures (tests/fixtures/external/tracecmd-dat) in a
# privileged Debian trixie container on the Docker VM's kernel; see inside.sh
# for what is recorded and what is replaced for privacy.
# Output lands in $OUT (default /tmp/fixtures/tracecmd-dat).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/tracecmd-dat}
mkdir -p "$OUT"
docker run --rm --privileged --hostname fillyfoal \
    -v "$HERE:/work:ro" -v "$OUT:/out" debian:trixie bash /work/inside.sh
