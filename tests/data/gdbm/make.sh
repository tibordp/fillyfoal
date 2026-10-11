#!/bin/sh
# Writes the external GDBM fixtures with real GNU dbm (needs Docker):
#
#   sh tests/data/gdbm/make.sh OUTDIR
#
# - dbm-gnu.gdbm: Python's dbm.gnu (python:3.12-slim, Debian libgdbm 1.23,
#   64-bit, magic 0x13579acf), 5 keys.
# - numsync.gdbm: gdbmtool 1.23 (debian:bookworm-slim) with --numsync, the
#   extended header (magic 0x13579ad1), 512-byte blocks, 3 keys.
set -eu
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm -v "$out:/out" -v "$here:/gen:ro" -w /out python:3.12-slim \
    python3 -I /gen/dbm_gnu.py /out/dbm-gnu.gdbm
docker run --rm -v "$out:/out" -v "$here:/gen:ro" -w /out debian:bookworm-slim \
    sh /gen/numsync.sh /out/numsync.gdbm
