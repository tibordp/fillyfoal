#!/bin/bash
# Runs in the 32-bit container (see make-32bit.sh): the same LTTng user-space
# trace of hello.c as inside.sh, without extra contexts, then babeltrace2's
# conversion of it to CTF with sink.ctf.fs. Only the stream files holding
# the events are kept (the metadata records the kernel release).
set -euo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    lttng-tools liblttng-ust-dev gcc babeltrace2 > /dev/null
dpkg-query -W lttng-tools liblttng-ust-dev babeltrace2
cd /tmp
gcc -O1 -o /tmp/hello /work/hello.c -llttng-ust -ldl
export HOME=/tmp/lthome
mkdir -p "$HOME"
lttng-sessiond --daemonize
lttng create fillyfoal --output=/tmp/lt > /dev/null
lttng enable-channel -u --subbuf-size=4096 --num-subbuf=2 ch > /dev/null
lttng enable-event -u -c ch 'lttng_ust_tracef:*' > /dev/null
lttng start > /dev/null
/tmp/hello
lttng stop > /dev/null
lttng destroy > /dev/null
dir=/tmp/lt/ust/uid/0/32-bit
mkdir -p /out/ctf-packet
# The one per-CPU stream file holding the events.
for f in "$dir"/ch_*; do
    if grep -q "fillyfoal message" "$f"; then
        cp "$f" /out/ctf-packet/lttng-ust-32bit-stream
        echo "events in $(basename "$f")"
    fi
done
babeltrace2 /tmp/lt | tail -2

rm -rf /tmp/bt
babeltrace2 /tmp/lt --component=sink.ctf.fs --params='path="/tmp/bt"' > /dev/null
for f in $(find /tmp/bt -type f -name 'ch_*'); do
    if grep -q "fillyfoal message" "$f"; then
        cp "$f" /out/ctf-packet/babeltrace-clocked-stream
    fi
done
babeltrace2 /tmp/bt | tail -2
chmod 644 /out/ctf-packet/*
