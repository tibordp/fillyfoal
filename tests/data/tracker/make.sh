#!/bin/sh
# Writes the external tracker fixtures (see inside.sh) into OUTDIR:
#   schism.it, schism.s3m, schism.mod  -> tests/fixtures/external/{it,s3m,mod}/
#   milkytracker.xm                    -> tests/fixtures/external/xm/
# Schism Tracker stamps its build date and an edit-history entry with the
# save time into the IT file, so reruns differ in those bytes.
set -eu
out=$(cd "${1:?usage: make.sh OUTDIR}" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm -v "$here:/data:ro" -v "$out:/out" debian:trixie-slim bash /data/inside.sh
