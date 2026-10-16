#!/bin/sh
# Builds the mongo-archive fixtures with mongodump from the official
# mongo:7 image (inside.sh): a throwaway mongod in a new container (host
# name "fillyfoal"), two databases with neutral documents covering most
# BSON types, an index and a view, then
#
#   mongo-archive/dump.archive   mongodump --archive
#   gzip/dump.archive.gz         mongodump --archive --gzip (the whole
#                                archive is one gzip stream)
#
# Collection UUIDs are random, so the files differ between runs in those
# bytes (the documents, and the CRCs over them, stay the same).
#
#   sh tests/data/mongo-archive/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/mongo-archive
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm --hostname fillyfoal -v "$B/out:/out" -v "$SRC:/scripts:ro" \
  mongo:7 sh /scripts/inside.sh
mkdir -p "$FIX/mongo-archive" "$FIX/gzip"
cp "$B/out/dump.archive" "$FIX/mongo-archive/dump.archive"
cp "$B/out/dump.archive.gz" "$FIX/gzip/dump.archive.gz"
cat "$B/out/version.txt"
