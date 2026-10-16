#!/bin/sh
# Alpine APK v3 packages and an index for tests/fixtures/external/alpine-apk-v3/.
# Run (writes /tmp/fixtures/alpine-apk-v3/out/, with `apk adbdump` YAML next to each file):
#   mkdir -p /tmp/fixtures/alpine-apk-v3
#   cp tests/data/alpine-apk-v3/make.sh /tmp/fixtures/alpine-apk-v3/run.sh
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/alpine-apk-v3:/work -w /work \
#     alpine:edge sh /work/run.sh
# The package tree is built inside the container (a bind-mounted tree from macOS carries
# `com.apple.provenance` extended attributes, which apk records).
set -e
cd /work
apk --version
apk add -q openssl >/dev/null 2>&1 || true
rm -rf out && mkdir -p out /tmp/b/root/usr/share/fillyfoal /tmp/b/root/usr/bin && cd /tmp/b
printf 'hello from fillyfoal\n' > root/usr/share/fillyfoal/hello.txt
printf '#!/bin/sh\necho hello\n' > root/usr/bin/fillyfoal-hello
chmod 755 root/usr/bin/fillyfoal-hello
ln -s fillyfoal-hello root/usr/bin/ff-hello
printf '#!/bin/sh\nexit 0\n' > post-install.sh
touch -h -d '2024-01-01 00:00:00' root/usr/share/fillyfoal/hello.txt root/usr/bin/fillyfoal-hello root/usr/bin/ff-hello root/usr/share/fillyfoal root/usr/bin root/usr root
INFO="-I name:fillyfoal-hello -I version:1.0-r0 -I description:demo -I arch:noarch -I license:MIT -I origin:fillyfoal-hello -I maintainer:fillyfoal -I url:https://example.org/ -I build-time:1704067200 -I depends:busybox"
# uncompressed, unsigned
apk mkpkg $INFO -F root -s post-install:post-install.sh --compression none -o /work/out/hello-plain.apk
# default compression (deflate), unsigned
apk mkpkg $INFO -F root -s post-install:post-install.sh -o /work/out/hello.apk
# explicit compression level: written as "ADBc" with an algorithm/level header
apk mkpkg $INFO -F root --compression deflate:9 -o /work/out/hello-deflate9.apk
# signed (RSA key made here, thrown away)
openssl genrsa -out /tmp/fillyfoal.rsa 2048 2>/dev/null
openssl rsa -in /tmp/fillyfoal.rsa -pubout -out /tmp/fillyfoal.rsa.pub 2>/dev/null
apk mkpkg $INFO -F root --compression none --sign-key /tmp/fillyfoal.rsa -o /work/out/hello-signed.apk
# repository index over the package
apk mkndx --allow-untrusted -d "fillyfoal demo" -o /work/out/index.adb /work/out/hello.apk
for f in /work/out/*.apk /work/out/index.adb; do echo "== $f"; apk adbdump --allow-untrusted --format yaml "$f" > "$f.yaml" 2>&1 || true; done
ls -la /work/out
