#!/bin/sh
# Rebuilds the zlib fixtures made by real encoders,
# tests/fixtures/external/zlib/: Python's zlib.compress at levels 1, 9 and
# 0 (stored blocks), and pigz -z -11, of the same 2.4 KB of neutral text.
#
# Runs a plain Debian container, host name "fillyfoal", in a scratch
# directory outside the home directory:
#
#   sh tests/data/zlib/make-external.sh [scratch dir]
#
# The output is reproducible for the same package versions (inner.sh
# prints them).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/zlib}
mkdir -p "$work"
docker run --rm --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner.sh
mkdir -p "$repo/tests/fixtures/external/zlib"
cp "$work"/out/* "$repo/tests/fixtures/external/zlib/"
