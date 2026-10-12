#!/bin/sh
# Build the EDK2 BaseTools C tools needed for the UEFI fixture (in Docker).
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq build-essential uuid-dev python3 git >/dev/null
cd /work
[ -d edk2 ] || git clone -q --depth 1 --branch edk2-stable202405 https://github.com/tianocore/edk2.git
cd edk2/BaseTools/Source/C
make -s -C Common
for t in GenSec GenFfs GenFv LzmaCompress; do make -s -C $t; done
ls bin
