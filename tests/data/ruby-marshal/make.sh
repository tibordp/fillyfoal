#!/bin/sh
# Builds the ruby-marshal fixtures with Marshal.dump in the official
# ruby:3.4-alpine image (make.rb), host name "fillyfoal":
#
#   objects.marshal  a hash of nil/true/false, fixnums of every width,
#                    bignums, floats (NaN, infinity), symbols and symbol
#                    links, strings with encodings (instance variables E
#                    and encoding), a binary string, arrays, an object
#                    link, hashes (one with a default), a struct, an
#                    object with instance variables, _dump ('u') and
#                    marshal_dump ('U') objects, a regexp, a class, a
#                    module, a range and an extended String subclass
#   array.marshal    600 two-element arrays (paging)
#   regexps.marshal  regexps with a fixed encoding, /n and /imx
#
# All are the same on every run.
#
#   sh tests/data/ruby-marshal/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/ruby-marshal
rm -rf "$B"
mkdir -p "$B"
docker run --rm --hostname fillyfoal -v "$B:/out" -v "$SRC:/scripts:ro" \
  ruby:3.4-alpine ruby /scripts/make.rb /out
mkdir -p "$FIX/ruby-marshal"
for f in objects.marshal array.marshal regexps.marshal; do
  cp "$B/$f" "$FIX/ruby-marshal/$f"
done
