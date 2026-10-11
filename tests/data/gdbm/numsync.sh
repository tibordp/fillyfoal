#!/bin/sh
# Run inside debian:bookworm-slim by make.sh: an extended (numsync) database.
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq gdbmtool >/dev/null 2>&1
rm -f "$1"
printf 'store one 1\nstore two "second"\nstore three fillyfoal\nsync\nquit\n' > /tmp/cmds
gdbmtool -N -q -n -x -b 512 -f /tmp/cmds "$1"
