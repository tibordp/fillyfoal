#!/bin/sh
# Writes tests/fixtures/external/rar/ with RAR 6.23 (RARLAB, Debian
# bullseye non-free package 2:6.23-1~deb11u1, amd64), the last version that
# still writes RAR 4.x archives (-ma4):
#
#     sh tests/data/rar/make_external.sh <repo>
#
# Built in /tmp/fixtures/archive-rar with fixed modification times; RAR
# records no user or host names. Reruns reproduce every archive byte for
# byte except v5-encrypted.rar (random salt and IV).
set -eu
repo=$(cd "${1:?usage: make_external.sh <repo>}" && pwd)
work=/tmp/fixtures/archive-rar
rm -rf "$work"
mkdir -p "$work"
cp "$repo/tests/data/rar/make_external_inner.sh" "$work/inner.sh"
docker run --rm --platform linux/amd64 -v "$work:/w" -w /w debian:bullseye-slim sh /w/inner.sh
mkdir -p "$repo/tests/fixtures/external/rar"
cp "$work"/out/*.rar "$repo/tests/fixtures/external/rar/"
