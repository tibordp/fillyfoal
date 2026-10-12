#!/bin/sh
# Builds tests/fixtures/external/pyc/tables.cpython-{38,310,313}.pyc from
# tables.py with CPython 3.8, 3.10 and 3.13 (Docker python:X.Y-slim), in a
# neutral directory, for the line tables (3.8: co_lnotab; 3.10: the
# co_linetable of (offset, line) deltas; 3.13: the location table) and the
# 3.11+ exception table. The source mtime is pinned, so a rerun gives the
# same bytes. `dis` and `co_lines`/`co_positions` in each image show what
# the snapshots should list.
#
#   sh tests/data/pyc/make-tables.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/bytecode-pyc-tables
mkdir -p "$B"
cp "$SRC/tables.py" "$B/tables.py"
TZ=UTC touch -t 202601010000 "$B/tables.py"
mkdir -p "$FIX/pyc"
for v in 3.8 3.10 3.13; do
    tag=$(echo "$v" | tr -d .)
    docker run --rm -v "$B:/w" -w /w "python:$v-slim" python -c "
import py_compile
py_compile.compile('tables.py', 'tables.cpython-$tag.pyc', 'tables.py', True)"
    cp "$B/tables.cpython-$tag.pyc" "$FIX/pyc/tables.cpython-$tag.pyc"
done
