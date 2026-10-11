#!/bin/sh
# Writes the external RocksDB table fixtures with rocksdict 0.3.29 (RocksDB
# 9.x) in python:3.12-slim (needs Docker). The container's host name is set
# to "fillyfoal", which RocksDB records as rocksdb.creating.host.identity.
#
#   sh tests/data/rocksdb-sst/make.sh OUTDIR
set -eu
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm --hostname fillyfoal -v "$out:/out" -v "$here:/gen:ro" -w /out \
    python:3.12-slim sh -c \
    'pip install -q --disable-pip-version-check rocksdict==0.3.29 && python3 -I /gen/make.py /out'
