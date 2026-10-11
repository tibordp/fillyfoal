#!/bin/sh
# Runs in a debian:trixie container (see make.sh): prints the header of and
# verifies each trimmed journal, then its entries.
set -eu
for f in /work/out/*-trim.journal; do
    echo "== $f"
    journalctl --file "$f" --header
    journalctl --file "$f" --verify
    journalctl --file "$f" -o export
done
