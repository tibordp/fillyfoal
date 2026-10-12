#!/bin/sh
# Build the EDK2 BaseTools C tools needed for the UEFI fixtures (in Docker).
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq build-essential uuid-dev python3 git >/dev/null
cd /work
[ -d edk2 ] || git clone -q --depth 1 --branch edk2-stable202405 https://github.com/tianocore/edk2.git
cd edk2
# BrotliCompress builds google/brotli from its submodule.
git submodule update -q --init --depth 1 BaseTools/Source/C/BrotliCompress/brotli
cd BaseTools/Source/C
make -s -C Common
for t in GenSec GenFfs GenFv LzmaCompress TianoCompress BrotliCompress; do make -s -C $t; done
ls bin
