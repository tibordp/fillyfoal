#!/bin/sh
# Builds tests/fixtures/external/wasm/component.wasm from component.wat with
# wasm-tools 1.240.0 (Bytecode Alliance), built from crates.io inside the
# rust:1-slim-bookworm Docker image (`cargo install wasm-tools --locked
# --version 1.240.0`), in a neutral directory. `wasm-tools validate` checks
# it and `wasm-tools print` shows the structure the snapshot should match.
# Deterministic: rerunning gives the same bytes.
#
#   sh tests/data/wasm/make-component.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/bytecode-wasm-component
mkdir -p "$B/cargo" "$B/out"
cp "$SRC/component.wat" "$B/out/component.wat"
docker run --rm -v "$B/cargo:/opt/wt" -v "$B/out:/w" -w /w rust:1-slim-bookworm sh -c '
    set -e
    [ -x /opt/wt/bin/wasm-tools ] ||
        cargo install wasm-tools --locked --version 1.240.0 --root /opt/wt
    /opt/wt/bin/wasm-tools --version
    /opt/wt/bin/wasm-tools parse component.wat -o component.wasm
    /opt/wt/bin/wasm-tools validate --features all component.wasm
    /opt/wt/bin/wasm-tools print component.wasm'
mkdir -p "$FIX/wasm"
cp "$B/out/component.wasm" "$FIX/wasm/component.wasm"
