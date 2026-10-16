#!/bin/bash
# Runs in the container (see make.sh).
set -eu
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq atop > /dev/null
dpkg-query -W atop
rm -f /out/atop.raw
sleep 30 &
atop -w /out/atop.raw 1 2 > /dev/null
kill %1
