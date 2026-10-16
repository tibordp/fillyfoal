#!/bin/sh
# Rebuilds tests/fixtures/external/borg-segment/names and
# tests/fixtures/external/borg-index/ with Debian bookworm's borgbackup
# (1.2.4), in a plain Debian container with host name "fillyfoal":
#
#   sh tests/data/borg-segment/make-more.sh [scratch dir]
#
# more-inner.sh backs up a file whose name is not UTF-8, one dated 1965
# (Borg stores times before 1970 as 0) with a binary extended attribute,
# into an unencrypted repository, and copies the data segment, the
# repository index (`index.5`) and the client's chunks cache. The two hash
# indexes are mostly empty buckets; they are stored gzipped (`gzip -9 -n`)
# and the test harness decompresses them. Not reproducible byte for byte
# (times in the metadata, and so the object IDs of the metadata, vary).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/borg-more}
mkdir -p "$work/out"
docker run --rm --hostname fillyfoal -v "$work/out:/work" -v "$here:/data:ro" \
  debian:bookworm-slim bash /data/more-inner.sh
ext="$repo/tests/fixtures/external"
mkdir -p "$ext/borg-index"
cp "$work/out/names" "$ext/borg-segment/names"
gzip -9 -n -c "$work/out/index.5" > "$ext/borg-index/index.5.gz"
gzip -9 -n -c "$work/out/chunks" > "$ext/borg-index/chunks.gz"
