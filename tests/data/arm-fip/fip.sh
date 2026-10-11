#!/bin/sh
# Builds the Arm FIP fixture with TF-A's fiptool (Debian trixie
# `arm-trusted-firmware-tools`) and prints the ToC UUID table used by
# platform.rs (read back from a FIP holding every image type, see
# fiptable.py).
#
#   sh tests/data/arm-fip/fip.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/system-fip
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -w /work debian:trixie sh /scripts/inside.sh
python3 -I "$SRC/fiptable.py" "$B/out/all.fip" "$B/out/all-info.txt"
mkdir -p "$FIX/arm-fip"
cp "$B/out/fip.bin" "$FIX/arm-fip/fip.bin"
cat "$B/out/version.txt" "$B/out/fip-info.txt"
