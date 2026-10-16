#!/bin/bash
# sysstat activity files written by sadc (Debian trixie sysstat 12.7.5) in a
# container, host name fillyfoal, TZ=UTC (sar files keep interface names and
# counters, mount points and device numbers, no addresses):
#  - sa-all.sa: every activity (-S ALL), two samples a second apart, a
#    comment record, a restart mark (sadc with no interval), then one more
#    sample;
#  - sa-default.sa: sadc's default activities, three samples.
# Output lands in $OUT (default /tmp/fixtures/sysstat-sa).
set -eu
OUT=${OUT:-/tmp/fixtures/sysstat-sa}
mkdir -p "$OUT"
docker run --rm --hostname fillyfoal -e TZ=UTC -v "$OUT:/out" debian:trixie bash -euc '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sysstat > /dev/null
    dpkg-query -W sysstat
    cd /out
    rm -f sa-all.sa sa-default.sa
    sadc=/usr/libexec/sysstat/sadc
    $sadc -S ALL 1 2 sa-all.sa
    $sadc -C "fillyfoal test comment" sa-all.sa
    $sadc -S ALL sa-all.sa
    $sadc -S ALL 1 1 sa-all.sa
    $sadc 1 3 sa-default.sa
'
