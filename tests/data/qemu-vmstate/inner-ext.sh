#!/bin/sh
# Runs inside the fillyfoal-vmstate-tools container (see make-external.sh):
# boots a diskless VM under TCG with the arguments given, stops it, and
# saves its state with a QMP `migrate` to a file.
#   $1: QEMU binary   $2: output name   $3...: machine and device arguments
set -eu
qemu=$1 out=$2
shift 2
cd /tmp
rm -f /tmp/qmp.sock
"$qemu" -nodefaults -accel tcg -display none -serial none -monitor none \
    -qmp unix:/tmp/qmp.sock,server=on,wait=off -daemonize -pidfile /tmp/qemu.pid "$@"
sleep 3
qmp() {
    printf '{"execute":"qmp_capabilities"}\n%s\n' "$1" | socat - UNIX-CONNECT:/tmp/qmp.sock
}
qmp '{"execute":"stop"}'
qmp "{\"execute\":\"migrate\",\"arguments\":{\"uri\":\"exec:cat > /out/$out\"}}"
sleep 3
qmp '{"execute":"query-migrate"}'
qmp '{"execute":"quit"}' || true
sleep 1
ls -l "/out/$out"
