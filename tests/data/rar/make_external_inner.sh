#!/bin/sh
# Runs inside debian:bullseye-slim (amd64); see make_external.sh.
set -eu
echo "deb http://deb.debian.org/debian bullseye main non-free" > /etc/apt/sources.list
apt-get update -qq >/dev/null
apt-get install -y -qq rar=2:6.23-1~deb11u1 >/dev/null
export LC_ALL=C.UTF-8 TZ=UTC
rm -rf src out
mkdir -p src/docs out
cd src
i=0
while [ $i -lt 40 ]; do
  echo "Line $i: the quick brown fox jumps over the lazy dog." >> docs/readme.txt
  i=$((i + 1))
done
printf 'Grüße aus Zürich\n' > 'docs/Grüße.txt'
printf 'こんにちは\n' > '日本語.txt'
printf 'plain ascii\n' > ascii.txt
find . -exec touch -h -d '2024-01-02 03:04:05' {} +
# RAR 4.x: names with non-ASCII characters get the 0x200 flag, an OEM part
# and the compressed Unicode part after a NUL.
rar a -ma4 -m3 -r -idq ../out/v4-unicode.rar ascii.txt docs '日本語.txt'
# RAR 4.x, solid.
rar a -ma4 -m5 -s -r -idq ../out/v4-solid-real.rar docs ascii.txt
# RAR 5.
rar a -ma5 -m3 -r -idq ../out/v5-unicode.rar ascii.txt docs '日本語.txt'
# RAR 5 with the archive password "fillyfoal" (data only).
rar a -ma5 -m3 -pfillyfoal -idq ../out/v5-encrypted.rar ascii.txt
# The same, solid: one dictionary across files encrypted one by one.
rar a -ma5 -m3 -s -r -pfillyfoal -idq ../out/v5-encrypted-solid.rar docs ascii.txt
# Headers encrypted too (-hp): everything after the encryption header.
rar a -ma5 -m3 -hpfillyfoal -idq ../out/v5-encrypted-headers.rar ascii.txt docs/readme.txt
