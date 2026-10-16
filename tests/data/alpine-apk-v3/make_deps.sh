#!/bin/sh
# An APK v3 package whose dependencies carry versions and match operators,
# for tests/fixtures/external/alpine-apk-v3/deps.apk.
# Run (writes /tmp/fixtures/alpine-apk-v3/out/deps.apk and its `apk adbdump`):
#   mkdir -p /tmp/fixtures/alpine-apk-v3
#   cp tests/data/alpine-apk-v3/make_deps.sh /tmp/fixtures/alpine-apk-v3/deps.sh
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/alpine-apk-v3:/work -w /work \
#     alpine:latest sh /work/deps.sh   (Alpine 3.23.4, apk-tools 3.0.6, x86_64)
set -e
apk --version
mkdir -p /work/out /tmp/d/root/usr/share/fillyfoal && cd /tmp/d
printf 'deps\n' > root/usr/share/fillyfoal/deps.txt
touch -h -d '2024-01-01 00:00:00' root/usr/share/fillyfoal/deps.txt root/usr/share/fillyfoal root/usr/share root/usr root
apk mkpkg -I name:fillyfoal-deps -I version:1.0-r0 -I arch:noarch -I license:MIT \
  -I build-time:1704067200 \
  -I 'depends:busybox>=1.36 musl=1.2.5-r0 zlib<2 fillyfoal~1.0 !fillyfoal-old so:libc.musl-x86_64.so.1' \
  -F root --compression none -o /work/out/deps.apk
apk adbdump --allow-untrusted --format yaml /work/out/deps.apk > /work/out/deps.apk.yaml
ls -la /work/out/deps.apk
