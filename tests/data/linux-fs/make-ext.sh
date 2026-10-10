#!/bin/sh
# ext2/3/4 fixtures (tests/fixtures/external/ext/). From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/fs-ext
#   docker run --rm --hostname fillyfoal \
#     -v /tmp/fixtures/fs-ext:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-ext.sh
#
# mke2fs (e2fsprogs 1.47.2) populates the images from a directory (-d), so
# no mount is needed; e2fsck -D then indexes the large directory (htree).
# E2FSPROGS_FAKE_TIME, -U and -E hash_seed make the images reproducible.
set -eu
export TZ=UTC
export E2FSPROGS_FAKE_TIME=1704067200 # 2024-01-01 00:00:00 UTC
STAMP=@1704067200
S=/tmp/tree
rm -rf "$S" ./*.img ./*.zst
mkdir -p "$S/dir" "$S/many"
printf 'Hello, fillyfoal!\n' > "$S/hello.txt"
printf 'tiny\n' > "$S/tiny.txt"
# 300 KiB of a repeating binary pattern: indirect blocks on ext2/ext3.
python3 -c 'import sys; sys.stdout.buffer.write((bytes(range(128, 256)) + bytes(range(0, 128))) * 1200)' > "$S/pattern.bin"
# A sparse file: data, a hole, data.
printf 'start' > "$S/sparse.bin"
printf 'end' | dd of="$S/sparse.bin" bs=1 seek=200000 conv=notrunc 2>/dev/null
ln -s hello.txt "$S/link"
ln -s "$(seq -f 'long-symlink-target-%02g' 1 10 | tr '\n' '/')end" "$S/longlink"
for i in $(seq -w 1 20); do : > "$S/many/entry-$i-$(printf '%052d' 0)"; done
printf 'nested\n' > "$S/dir/nested.txt"
mknod "$S/null" c 1 3
mkfifo "$S/pipe"
setfattr -n user.comment -v 'a short attribute' "$S/hello.txt"
setfattr -n user.big -v "$(seq -s ' ' 1 150)" "$S/tiny.txt"
setfacl -m u:1000:r "$S/hello.txt"
touch -h -d "$STAMP" "$S" "$S"/* "$S"/*/*

opts="-q -F -b 1024 -U 00000000-0000-4000-8000-0000000000e4 -E hash_seed=00000000-0000-4000-8000-0000000000a5,root_owner=0:0 -d $S"
# ext4: extents, flex_bg, metadata_csum, 64bit, inline data, a journal.
mke2fs $opts -t ext4 -O inline_data,^resize_inode -L fillyfoal-ext4 -J size=1 -N 64 ext4.img 4M
# ext3: block maps, a journal, hashed directories.
mke2fs $opts -t ext3 -L fillyfoal-ext3 -J size=1 -N 64 ext3.img 4M
# ext2: block maps, no journal.
mke2fs $opts -t ext2 -L fillyfoal-ext2 -N 64 ext2.img 2M
for f in ext4 ext3 ext2; do
  e2fsck -fyD $f.img >/dev/null 2>&1 || true
  e2fsck -fn $f.img
  dumpe2fs $f.img > $f.dumpe2fs.txt 2>&1
  zstd -q -19 -f $f.img -o $f.img.raw.zst
done
ls -l ./*.zst
