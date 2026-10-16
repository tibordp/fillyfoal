#!/bin/bash
# CTF fixtures (tests/fixtures/external/ctf-packet and ctf-metadata), written
# by LTTng-UST 2.13 and babeltrace2 2.1 in Debian trixie; see inside.sh.
# Output lands in $OUT/ctf-packet and $OUT/ctf-metadata (default /tmp/fixtures/ctf).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/ctf}
mkdir -p "$OUT"
docker run --rm --hostname fillyfoal -e TZ=UTC -v "$HERE:/work:ro" -v "$OUT:/out" \
    debian:trixie bash /work/inside.sh
