#!/bin/bash
# Runs in the container (see make.sh): an LTTng user-space trace of
# hello.c (150 lttng_ust_tracef messages, filling several packets;
# contexts vpid and procname), and
# babeltrace2's conversion of dmesg.txt to CTF 1.8 and CTF 2.
set -euo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    lttng-tools liblttng-ust-dev clang babeltrace2 > /dev/null
dpkg-query -W lttng-tools liblttng-ust-dev babeltrace2
cd /tmp
clang -O1 -o /tmp/hello /work/hello.c -llttng-ust -ldl
export HOME=/tmp/lthome
mkdir -p "$HOME"
lttng-sessiond --daemonize
lttng create fillyfoal --output=/tmp/lt > /dev/null
lttng enable-channel -u --subbuf-size=4096 --num-subbuf=2 ch > /dev/null
lttng enable-event -u -c ch 'lttng_ust_tracef:*' > /dev/null
lttng add-context -u -c ch -t vpid -t procname > /dev/null
lttng start > /dev/null
/tmp/hello
lttng stop > /dev/null
lttng destroy > /dev/null
dir=/tmp/lt/ust/uid/0/64-bit
mkdir -p /out/ctf-packet /out/ctf-metadata
cp "$dir/metadata" /out/ctf-metadata/lttng-ust-metadata
# The one per-CPU stream file holding the events.
for f in "$dir"/ch_*; do
    if grep -q "fillyfoal message" "$f"; then
        cp "$f" /out/ctf-packet/lttng-ust-stream
    fi
done
babeltrace2 /tmp/lt | tail -2

rm -rf /tmp/bt1 /tmp/bt2
babeltrace2 --component=src.text.dmesg --params='path="/work/dmesg.txt"' \
    --component=sink.ctf.fs --params='path="/tmp/bt1",ctf-version="1"' > /dev/null
babeltrace2 --component=src.text.dmesg --params='path="/work/dmesg.txt"' \
    --component=sink.ctf.fs --params='path="/tmp/bt2",ctf-version="2"' > /dev/null
cp /tmp/bt1/dmesg.txt/metadata /out/ctf-metadata/babeltrace-ctf18-metadata
cp /tmp/bt1/dmesg.txt/stream /out/ctf-packet/babeltrace-ctf18-stream
cp /tmp/bt2/dmesg.txt/metadata /out/ctf-metadata/babeltrace-ctf2-metadata
chmod 644 /out/ctf-packet/* /out/ctf-metadata/*
