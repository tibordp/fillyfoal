#!/bin/sh
# SquashFS fixtures (tests/fixtures/external/squashfs/). From the repository
# root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/fs-squashfs
#   docker run --rm --hostname fillyfoal \
#     -v /tmp/fixtures/fs-squashfs:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-squashfs.sh
#
# mksquashfs 4.6.1 builds reproducible images by default; -mkfs-time,
# -all-time and -all-root fix the rest.
set -eu
export TZ=UTC
T=1704067200 # 2024-01-01 00:00:00 UTC
S=/tmp/tree
rm -rf "$S" ./*.sqfs
mkdir -p "$S/dir/sub" "$S/many"
printf 'Hello, fillyfoal!\n' > "$S/hello.txt"
printf 'Hello, fillyfoal!\n' > "$S/hello-copy.txt"   # a duplicate
seq -s ' ' 1 6000 > "$S/numbers.txt"                # one 28 KiB line
# 40 KiB of a binary pattern: several 16 KiB blocks plus a fragment.
python3 -c 'import sys; sys.stdout.buffer.write((bytes(range(128, 256)) + bytes(range(0, 128))) * 160)' > "$S/pattern.bin"
# A sparse file: a block of data, two empty blocks, a tail.
printf 'start' > "$S/sparse.bin"
printf 'end' | dd of="$S/sparse.bin" bs=1 seek=40000 conv=notrunc 2>/dev/null
ln -s hello.txt "$S/link"
ln "$S/hello.txt" "$S/dir/hardlink.txt"
printf 'nested\n' > "$S/dir/sub/nested.txt"
for i in $(seq -w 1 12); do printf '%s\n' "$i" > "$S/many/entry-$i"; done
mknod "$S/null" c 1 3
mknod "$S/loop0" b 7 0
mkfifo "$S/pipe"
python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("/tmp/tree/socket")'
setfattr -n user.comment -v 'an attribute' "$S/hello.txt"
setfattr -n user.comment -v 'an attribute' "$S/numbers.txt"
setfattr -n user.long -v "$(seq -s ' ' 1 400)" "$S/dir"
touch -h -d @$T "$S" "$S"/* "$S"/*/* "$S"/*/*/*

for comp in gzip lzma lzo xz lz4 zstd; do
  mksquashfs "$S" "$comp.sqfs" -quiet -no-progress -comp "$comp" -b 16K \
    -mkfs-time $T -all-time $T -all-root -processors 1 -xattrs
  unsquashfs -stat "$comp.sqfs" > "$comp.stat.txt"
done
# Uncompressed metadata and data, no fragments, no exports, no xattrs.
mksquashfs "$S" plain.sqfs -quiet -no-progress -no-compression -no-fragments \
  -no-exports -no-xattrs -b 4K -mkfs-time $T -all-time $T -all-root -processors 1 \
  -e numbers.txt pattern.bin
unsquashfs -lls gzip.sqfs > gzip.lls.txt
ls -l ./*.sqfs
