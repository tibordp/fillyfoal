#!/bin/sh
# Builds tests/fixtures/external/hfsplus/features.img.gz on macOS: an HFS+
# volume made by newfs_hfs (through hdiutil) and filled by the macOS HFS+
# driver with
#   - frag.bin: a 12-block data fork in 10 extents (the last two in the extents
#     overflow file), made by punching holes into a full volume first;
#   - docs/small.dat, docs/words.dat: decmpfs-compressed by
#     `ditto --hfsCompression` (LZVN in the resource fork, type 8: one and
#     three 64 KiB chunks; ditto leaves files under about 16 KiB alone and
#     wrote no inline type here);
#   - a.txt and docs/hard.txt: one file under two names (an indirect node in
#     the private metadata folder);
#   - xattr.txt: an extended attribute in the attributes B-tree.
# Content is generated here; names are neutral; Spotlight and fseventsd are
# kept out (`-nobrowse`, `.fseventsd/no_log`); the files record the
# numeric ids of the user who ran this (501/20 for the first macOS account).
# scrub.py then zeroes the id in the com.apple.provenance attributes.
#
# Usage: sh tests/data/hfsplus/make.sh <output dir>
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "${1:?output dir}" && pwd)
work=/tmp/fixtures/disk-b-hfsplus
mkdir -p "$work"
cd "$work"
test "$(pwd)" = "$work"
rm -f hfs.dmg
rm -rf src
mkdir src
python3 "$here/content.py" src
hdiutil create -size 2m -fs HFS+ -volname fillyfoal -layout NONE hfs.dmg
hdiutil attach -nobrowse -noverify -noautoopen -mountpoint "$work/mnt" hfs.dmg
cd mnt
test "$(pwd)" = "$work/mnt"
mkdir -p .fseventsd
touch .fseventsd/no_log
# Fill the volume with 4 KiB files and one filler, free every other small
# file and write frag.bin into the holes.
i=0
while [ $i -lt 24 ]; do
    head -c 4096 /dev/zero > "gap$i"
    i=$((i + 1))
done
avail=$(df -k . | awk 'NR==2 {print $4}')
head -c "$(( (avail - 8) * 1024 ))" /dev/zero > filler 2>/dev/null || true
i=0
while [ $i -lt 24 ]; do
    rm "gap$i"
    i=$((i + 2))
done
cp ../src/frag.bin frag.bin
rm filler gap*
mkdir docs
ditto --hfsCompression ../src/small.dat docs/small.dat
ditto --hfsCompression ../src/words.dat docs/words.dat
printf 'one file, two names\n' > a.txt
ln a.txt docs/hard.txt
printf 'has an extended attribute\n' > xattr.txt
xattr -w org.example.note "a neutral attribute value" xattr.txt
sync
cd "$work"
hdiutil detach "$work/mnt"
python3 "$here/scrub.py" hfs.dmg
gzip -9 -n -c hfs.dmg > "$out/features.img.gz"
