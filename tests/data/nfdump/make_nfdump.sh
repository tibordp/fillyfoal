#!/bin/sh
# nfdump flow files (layout 2) written by Debian trixie's nfdump 1.7.5,
# from the neutral capture flows_pcap.py writes.
#
#   python3 -I tests/data/nfdump/flows_pcap.py /tmp/fixtures/nfdump/flows.pcap
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/nfdump:/out \
#     -v "$PWD/tests/data/nfdump":/gen:ro debian:trixie sh /gen/make_nfdump.sh
#
# Writes plain.nfcapd (nfpcapd), fat.nfcapd (nfpcapd -o fat: more
# extensions), lzo/bz2/lz4/zstd.nfcapd (the plain flows rewritten by
# nfdump -z=<codec>) and nfcapd.nfcapd: nfcapd receiving the plain flows
# as NetFlow v9 from nfreplay over the loopback (exporter, sampler and
# exporter statistics records). *.txt are reference listings (not
# committed).
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq nfdump procps >/dev/null 2>&1
nfdump -V
cd /tmp
for opt in plain fat; do
  mkdir -p $opt
  if [ $opt = fat ]; then o="-o fat"; else o=""; fi
  nfpcapd -r /out/flows.pcap -w /tmp/$opt -I fillyfoal $o
  cp /tmp/$opt/nfcapd.* /out/$opt.nfcapd
done
for z in lzo bz2 lz4 zstd; do
  nfdump -r /out/plain.nfcapd -z=$z -w /out/$z.nfcapd
done
mkdir -p /tmp/cap
nfcapd -w /tmp/cap -p 9995 -b 127.0.0.1 -I fillyfoal -D -P /tmp/nfcapd.pid
sleep 1
nfreplay -r /out/plain.nfcapd -H 127.0.0.1 -p 9995 -v 9
sleep 1
kill -TERM "$(cat /tmp/nfcapd.pid)"
while pgrep -x nfcapd >/dev/null; do sleep 1; done
cp /tmp/cap/nfcapd.2* /out/nfcapd.nfcapd
for f in plain fat lzo bz2 lz4 zstd nfcapd; do
  nfdump -r /out/$f.nfcapd -o raw > /out/$f.txt
  nfdump -E /out/$f.nfcapd >> /out/$f.txt
  nfdump -r /out/$f.nfcapd -I >> /out/$f.txt
done
