#!/bin/sh
# Runs inside the fillyfoal-vmstate-tools container (see make-external.sh):
# boots a diskless VM under TCG, stops it once the firmware has given up,
# and saves its state with a QMP `migrate` to a file.
#   $1: machine type (pc, q35, microvm)   $2: RAM size   $3: output name
set -eu
machine=$1 mem=$2 out=$3
cd /tmp
qemu-system-x86_64 -nodefaults -machine "$machine" -accel tcg -m "$mem" \
    -display none -serial none -monitor none \
    -qmp unix:/tmp/qmp.sock,server=on,wait=off -daemonize -pidfile /tmp/qemu.pid
sleep 3
qmp() {
    printf '{"execute":"qmp_capabilities"}\n%s\n' "$1" | socat - UNIX-CONNECT:/tmp/qmp.sock
}
qmp '{"execute":"stop"}'
qmp "{\"execute\":\"migrate\",\"arguments\":{\"uri\":\"exec:cat > /out/$out\"}}"
sleep 3
qmp '{"execute":"query-migrate"}'
qmp '{"execute":"quit"}' || true
ls -l /out
