#!/bin/sh
# Builds the erlang-etf fixtures with term_to_binary/2 in the official
# erlang:27-alpine image (make.escript), host name "fillyfoal":
#
#   terms.etf        a map holding every kind of term the runtime writes
#                    outside distribution: small/integer/big integers,
#                    new floats, UTF-8 atoms, nil, strings, lists (and an
#                    improper one), small and large tuples, maps,
#                    binaries, a bit binary, a pid, a port, a reference,
#                    an export fun and a local fun
#   latin1.etf       {minor_version, 1}: Latin-1 atoms
#   old-float.etf    {minor_version, 0}: floats as text
#   compressed.etf   [compressed]: the term zlib-compressed
#
# The pid, port, reference and local fun differ between runs (creation
# numbers, the fun's environment); the rest is fixed.
#
#   sh tests/data/erlang-etf/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/erlang-etf
rm -rf "$B"
mkdir -p "$B"
docker run --rm --hostname fillyfoal -v "$B:/out" -v "$SRC:/scripts:ro" \
  erlang:27-alpine escript /scripts/make.escript /out
mkdir -p "$FIX/erlang-etf"
for f in terms.etf latin1.etf old-float.etf compressed.etf; do
  cp "$B/$f" "$FIX/erlang-etf/$f"
done
