#!/bin/sh
# Rebuilds the raw-* fixtures of tests/fixtures/external/criu-image/: the
# images `criu dump --tcp-established` (CRIU 4.2.1, Debian sid, aarch64,
# privileged Docker container, host name "fillyfoal") writes for a Python
# process holding a pipe with unread data, a Unix datagram socket pair with
# queued messages, a loopback TCP connection with unread data both ways, a
# System V message queue and semaphore set in its own IPC namespace, and a
# deleted open file (see inner-raw.sh). Only the images with raw data after
# their entries, and files.img for the objects they belong to, are kept; the
# names of the TCP stream images (socket inode numbers) and of the IPC
# namespace images (namespace IDs) depend on the run, so they are renamed.
#
#   sh tests/data/criu-image/make-raw.sh [scratch dir]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/criu-image-raw}
rm -rf "$work/out"
mkdir -p "$work/out"
docker build -q -t fillyfoal-criu-sid "$here"
docker run --rm --privileged --hostname fillyfoal -e TCP=1 -v "$work/out:/out" \
  -v "$here:/scripts:ro" fillyfoal-criu-sid sh /scripts/inner-raw.sh
dst="$repo/tests/fixtures/external/criu-image"
out="$work/out"
cp "$out/pipes-data.img" "$dst/raw-pipes-data.img"
cp "$out/sk-queues.img" "$dst/raw-sk-queues.img"
cp "$out/files.img" "$dst/raw-files.img"
cp "$out"/ghost-file-*.img "$dst/raw-ghost-file.img"
cp "$out"/ipcns-msg-*.img "$dst/raw-ipcns-msg.img"
cp "$out"/ipcns-sem-*.img "$dst/raw-ipcns-sem.img"
# The client's stream (it sent 31 bytes) and the server's (17 bytes).
for f in "$out"/tcp-stream-*.img; do
  if grep -q "server to client" "$f"; then
    cp "$f" "$dst/raw-tcp-stream-client.img"
  else
    cp "$f" "$dst/raw-tcp-stream-server.img"
  fi
done
