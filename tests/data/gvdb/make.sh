#!/bin/sh
# Writes the external GVDB fixtures with GLib 2.84.4 and dconf 0.40 from
# Alpine 3.22 (needs Docker):
#
#   sh tests/data/gvdb/make.sh OUTDIR
#
# - gresource/demo.gresource: glib-compile-resources, three files under
#   /org/example/demo (one aliased into ui/, one zlib-compressed)
# - dconf/local: dconf compile of a keyfile with keys of many types and a
#   lock (the nested .locks table)
# - gvdb/gschemas.compiled: glib-compile-schemas of one schema with an
#   enum, a range and a summary
#
# The files hold no times; reruns give the same bytes.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$1" && pwd)
docker run --rm -v "$here:/scripts:ro" -v "$out:/out" alpine:3.22 sh -c '
set -eu
apk add --no-cache glib-dev dconf >/dev/null
sh /scripts/gresource.sh /out
sh /scripts/dconf.sh /out
sh /scripts/gschemas.sh /out
'
