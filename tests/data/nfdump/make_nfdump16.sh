#!/bin/sh
# nfdump flow files in the old layout 1, written by nfdump 1.6.22 (Debian
# bullseye, now on archive.debian.org): nfcapd receiving the NetFlow v5
# packet netflow_v5.py sends over the loopback, with every extension (-T all).
#
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/nfdump:/out \
#     -v "$PWD/tests/data/nfdump":/gen:ro debian:bullseye-slim sh /gen/make_nfdump16.sh
#
# Writes v1.nfcapd (as nfcapd wrote it, uncompressed), v1-lzo.nfcapd,
# v1-bz2.nfcapd and v1-lz4.nfcapd (rewritten by nfdump -z, -j, -y).
# *.txt are reference listings (not committed).
set -e
echo "deb http://archive.debian.org/debian bullseye main" > /etc/apt/sources.list
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq nfdump python3-minimal procps >/dev/null 2>&1
nfdump -V
mkdir -p /tmp/cap
nfcapd -l /tmp/cap -p 9995 -b 127.0.0.1 -I fillyfoal -T all -D -P /tmp/nfcapd.pid
sleep 1
python3 -I /gen/netflow_v5.py 9995
sleep 1
kill -TERM "$(cat /tmp/nfcapd.pid)"
while pgrep -x nfcapd >/dev/null; do sleep 1; done
cp /tmp/cap/nfcapd.2* /out/v1.nfcapd
nfdump -r /out/v1.nfcapd -z -w /out/v1-lzo.nfcapd
nfdump -r /out/v1.nfcapd -j -w /out/v1-bz2.nfcapd
nfdump -r /out/v1.nfcapd -y -w /out/v1-lz4.nfcapd
for f in v1 v1-lzo v1-bz2 v1-lz4; do
  nfdump -r /out/$f.nfcapd -o raw > /out/$f.txt
  nfdump -r /out/$f.nfcapd -I >> /out/$f.txt
done
