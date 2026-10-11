#!/bin/sh
# Writes the multi-member and padded gzip fixtures in a neutral directory.
#
#   external/gzip/two-members.gz  gzip -n -c of two files: one member each
#   synthetic/gzip/zero-padded.gz a one-member gzip -n file with 1000 zero
#                                 bytes appended (as dd or a tape block
#                                 leaves them); the padding is ours
#
#   sh tests/data/gzip/make-members.sh [fixtures directory]
set -eu
FIX=$(cd "${1:-$(dirname "$0")/../../fixtures}" && pwd)
B=/tmp/fixtures/archive-gzip
rm -rf "$B"
mkdir -p "$B"
cd "$B"
printf 'first member\n' > a.txt
printf 'second member, a bit longer\n' > b.txt
gzip -9 -n -c a.txt b.txt > two-members.gz
gzip -9 -n -c b.txt > zero-padded.gz
head -c 1000 /dev/zero >> zero-padded.gz
mkdir -p "$FIX/external/gzip" "$FIX/synthetic/gzip"
cp two-members.gz "$FIX/external/gzip/"
cp zero-padded.gz "$FIX/synthetic/gzip/"
