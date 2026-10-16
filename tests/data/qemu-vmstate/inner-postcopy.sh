#!/bin/sh
# Runs inside the fillyfoal-vmstate-tools container (see make-external.sh):
# boots a diskless microvm under TCG and migrates it with postcopy to a
# socket whose other end (socat) writes the stream to a file, so the device
# state is sent as a MIG_CMD_PACKAGED blob. Nothing answers on the return
# path, so QEMU is killed once the stream has been written.
#   $1: output name
set -eu
out=$1
cd /tmp
rm -f /tmp/qmp.sock
socat -u TCP-LISTEN:4444,reuseaddr "OPEN:/out/$out,creat,trunc" &
sleep 1
qemu-system-x86_64 -nodefaults -machine microvm -accel tcg -m 2 -display none -serial none \
    -monitor none -qmp unix:/tmp/qmp.sock,server=on,wait=off -daemonize -pidfile /tmp/qemu.pid
sleep 3
qmp() {
    printf '{"execute":"qmp_capabilities"}\n%s\n' "$1" | socat - UNIX-CONNECT:/tmp/qmp.sock
}
qmp '{"execute":"migrate-set-capabilities","arguments":{"capabilities":[{"capability":"postcopy-ram","state":true}]}}'
qmp '{"execute":"migrate-set-parameters","arguments":{"max-bandwidth":8192,"downtime-limit":1}}'
qmp '{"execute":"migrate","arguments":{"uri":"tcp:127.0.0.1:4444"}}'
sleep 1
qmp '{"execute":"migrate-start-postcopy"}'
sleep 5
qmp '{"execute":"query-migrate"}'
kill "$(cat /tmp/qemu.pid)" || true
sleep 1
ls -l "/out/$out"
