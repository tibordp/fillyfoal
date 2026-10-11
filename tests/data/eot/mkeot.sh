#!/bin/sh
# Builds tests/fixtures/external/eot/freeserif-subset.eot with the W3C's
# mkeot (Debian bookworm eot-utils 1.1-1+b1) from the TrueType FreeFont
# subset made by tests/data/sfnt/freefont_subsets.py, with one root string.
# Usage: mkeot.sh DIR   (DIR holds sfnt/freeserif-subset.ttf; writes DIR/freeserif-subset.eot)
set -e
docker run --rm -v "$1":/w debian:bookworm-slim sh -c '
apt-get update -qq >/dev/null
apt-get install -y -qq eot-utils >/dev/null
mkeot /w/sfnt/freeserif-subset.ttf https://example.org/ > /w/freeserif-subset.eot
'
