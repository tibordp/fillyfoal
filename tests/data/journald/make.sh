#!/bin/sh
# Builds the journald fixtures: a compact (systemd 252+ default) and a
# regular journal written by systemd-journal-remote in a Debian trixie
# container from a fixed export-format stream, trimmed after the last
# object (trim.py), checked with `journalctl --header --verify` and
# stored gzip'd (`gzip -9 -n`).
#
#   sh tests/data/journald/make.sh [fixtures directory]
#
# File ID and sequence number ID are random per run, and the keyed hashes
# (KEYED_HASH: SipHash keyed by the file ID) and hash-table slots follow
# them, so reruns differ in those bytes.
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/system-journald
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -w /work debian:trixie sh /scripts/inside.sh
for k in compact regular; do
    python3 -I "$SRC/trim.py" "$B/out/$k.journal" "$B/out/$k-trim.journal"
done
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -w /work debian:trixie sh -c \
    'apt-get update -qq >/dev/null && apt-get install -y -qq systemd >/dev/null 2>&1; sh /scripts/verify.sh'
mkdir -p "$FIX/journald"
for k in compact regular; do
    gzip -9 -n -c "$B/out/$k-trim.journal" > "$FIX/journald/$k.journal.gz"
done
cat "$B/out/version.txt"
ls -l "$B/out" "$FIX/journald"
