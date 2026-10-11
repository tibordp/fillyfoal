#!/bin/sh
# Writes the external WiredTiger fixtures with MongoDB 7 (WiredTiger 11.2,
# snappy block compression) in the official mongo:7 image (needs Docker):
#
#   sh tests/data/wiredtiger/mongod.sh OUTDIR
#
# The container's host name is "fillyfoal". mongod starts on an empty
# dbpath, inserts 300 documents into fillyfoal.items (every 50th with a
# 6000-byte string), creates an index on `n`, and shuts down cleanly. Kept:
# WiredTiger, WiredTiger.turtle and WiredTiger.wt (the metadata), prefixed
# `mongod7-`, and the items collection and its two index files (renamed
# from their random idents, listed in idents.txt). diagnostic.data, the
# journal, the catalog and the other tables are not kept.
set -eu
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm --hostname fillyfoal -v "$out:/out" -v "$here:/gen:ro" mongo:7 \
    bash /gen/mongod-inner.sh /out
