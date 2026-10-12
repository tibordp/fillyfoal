#!/bin/sh
# Builds tests/fixtures/external/pyc/interned.python27.pyc with CPython 2.7
# (Docker python:2.7-slim) in a neutral directory: a module whose names
# repeat, so marshal writes interned strings ('t') and back-references to
# them ('R', TYPE_STRINGREF). The source mtime is pinned, so a rerun gives
# the same bytes.
#
#   sh tests/data/pyc/make-py2.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/bytecode-pyc2
rm -rf "$B"
mkdir -p "$B"
cat > "$B/interned.py" <<'EOF'
def total(values):
    count = 0
    for value in values:
        count = count + value
    return count

def scaled(values, factor):
    return [value * factor for value in values]

result = total(scaled([1, 2, 3], 2))
EOF
TZ=UTC touch -t 202601010000 "$B/interned.py"
docker run --rm -v "$B:/w" -w /w python:2.7-slim python -c '
import py_compile
py_compile.compile("interned.py", "interned.pyc", "interned.py", True)'
mkdir -p "$FIX/pyc"
cp "$B/interned.pyc" "$FIX/pyc/interned.python27.pyc"
