#!/bin/sh
# Builds tests/fixtures/external/spirv/shader.spv from shader.frag with
# glslang (Docker alpine:edge package `glslang`), in a neutral directory;
# `spirv-dis` (package `spirv-tools`) lists what the snapshot should show.
# No timestamps: a rerun gives the same bytes.
#
#   sh tests/data/spirv/make-shader.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/bytecode-spirv
rm -rf "$B"
mkdir -p "$B"
cp "$SRC/shader.frag" "$B/shader.frag"
docker run --rm -v "$B:/w" -w /w alpine:edge sh -c '
    set -e
    apk add --no-cache -q glslang spirv-tools
    apk list --installed glslang spirv-tools
    glslangValidator -V -o shader.spv shader.frag
    spirv-dis shader.spv > shader.spvasm'
mkdir -p "$FIX/spirv"
cp "$B/shader.spv" "$FIX/spirv/shader.spv"
