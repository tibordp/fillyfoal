#!/bin/sh
# Writes the external APE, Musepack and Speex fixtures (see inside.sh)
# into OUTDIR:
#   mac-normal.ape, mac-extra-high.ape -> tests/fixtures/external/ape/
#   mpcenc.mpc                         -> tests/fixtures/external/musepack/
#   speexenc.spx                       -> tests/fixtures/external/speex/
set -eu
out=$(cd "${1:?usage: make.sh OUTDIR}" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm -v "$here:/data:ro" -v "$out:/out" fedora:42 bash /data/inside.sh
