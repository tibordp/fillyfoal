#!/bin/bash
# More CTF data streams (tests/fixtures/external/ctf-packet): an LTTng-UST
# trace from a 32-bit tracer (Debian trixie for linux/arm/v7, run under
# emulation), and babeltrace2's sink.ctf.fs conversion of that trace, which
# keeps its clock (timestamps in the packet context) and its cpu_id; see
# inside-32bit.sh. Output lands in $OUT/ctf-packet (default /tmp/fixtures/ctf).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/ctf}
mkdir -p "$OUT"
docker run --rm --platform linux/arm/v7 --hostname fillyfoal -e TZ=UTC \
    -v "$HERE:/work:ro" -v "$OUT:/out" debian:trixie bash /work/inside-32bit.sh
