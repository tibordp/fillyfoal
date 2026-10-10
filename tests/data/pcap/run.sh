#!/bin/bash
# Host-side orchestration for the packet-capture fixtures: an --internal
# Docker network (no route out), a server and a client container (see
# server.sh and client.sh); then convert.sh writes the other capture formats.
# Build the image first: docker build -t fillyfoal-pcap-tools tests/data/pcap
# Captures land in $OUT (default /tmp/fixtures/pcap).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/pcap}
IMG=fillyfoal-pcap-tools
NET=fillyfoal-capnet
docker rm -f ff-server ff-client >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
docker network create --internal --ipv6 --subnet 10.99.0.0/24 --subnet fd99::/64 $NET >/dev/null
rm -rf "$OUT"; mkdir -p "$OUT"
docker run -d --name ff-server --hostname server --network $NET --ip 10.99.0.2 --ip6 fd99::2 \
    --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    -v "$HERE:/work:ro" $IMG bash /work/server.sh >/dev/null
sleep 4
docker run --rm --name ff-client --hostname client --network $NET --ip 10.99.0.3 --ip6 fd99::3 \
    --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    -v "$HERE:/work:ro" -v "$OUT:/out" $IMG bash /work/client.sh
docker rm -f ff-server >/dev/null
docker network rm $NET >/dev/null
docker run --rm --network none -v "$HERE:/work:ro" -v "$OUT:/out" $IMG bash /work/convert.sh
