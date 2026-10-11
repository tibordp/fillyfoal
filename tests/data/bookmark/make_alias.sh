#!/bin/sh
# Builds tests/fixtures/external/bookmark/notes.alias with Foundation on
# macOS. The target lives on a throwaway 4 MiB RAM disk (HFS+ volume
# "fillyfoal") mounted under /tmp, so the alias records only that volume,
# file IDs on it and a path under /tmp. Foundation also records the volume
# holding the mount point (the boot volume) by name, UUID, size and
# creation date; scrub_alias.py replaces the UUIDs by neutral ones of the
# same length and zeroes that size and date, keeping the structure intact.
#
# Usage: sh make_alias.sh OUT_DIR   (prints the RAM disk it used)
set -eu
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
work=/tmp/fixtures/forensics-bookmark
mkdir -p "$work/mnt"
dev=$(hdiutil attach -nomount ram://8192 | awk '{print $1}')
echo "RAM disk: $dev"
trap 'hdiutil detach -quiet "$dev"' EXIT
newfs_hfs -v fillyfoal "$dev"
diskutil mount -mountPoint "$work/mnt" "$dev"
printf 'hello\n' > "$work/mnt/notes.txt"
swift "$here/make_alias.swift" "$work/mnt/notes.txt" "$out/notes.alias"
python3 -I "$here/scrub_alias.py" "$out/notes.alias"
