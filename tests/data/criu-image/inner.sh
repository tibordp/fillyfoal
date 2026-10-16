#!/bin/sh
# Runs inside the fillyfoal-vmstate-tools container (privileged, see
# make-external.sh): checkpoints a trivial process with `criu dump`.
set -eu
mkdir -p /tmp/dump
cd /
# A tiny process with a neutral, minimal environment.
env -i HOME=/ PATH=/bin:/usr/bin setsid sh -c 'exec sleep 1000' </dev/null >/dev/null 2>&1 &
pid=$!
sleep 1
criu dump -t "$pid" -D /tmp/dump --shell-job -v1 || { cat /tmp/dump/*.log 2>/dev/null; exit 1; }
cp /tmp/dump/* /out/
ls -l /out
