#!/bin/sh
# EROFS fixtures (tests/fixtures/external/erofs/). From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/fs-erofs
#   docker run --rm --hostname fillyfoal \
#     -v /tmp/fixtures/fs-erofs:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-erofs.sh
#
# mkfs.erofs (erofs-utils 1.8.6) reads the tree below; -T, -U and
# --all-root make the images reproducible byte for byte.
set -eu
export TZ=UTC
T=1704067200 # 2024-01-01 00:00:00 UTC
UUID=00000000-0000-4000-8000-0000000000e0
# The tree is built on the container's own filesystem, which keeps the
# extended attributes set below.
S=/tmp/tree
rm -rf "$S" ./*.erofs
mkdir -p "$S/dir" "$S/big"
printf 'Hello, fillyfoal!\n' > "$S/hello.txt"
seq -s ' ' 1 6000 > "$S/numbers.txt"     # one 28 KiB line: several clusters
seq -s ' ' 1 6000 > "$S/numbers-copy.txt" # identical: deduplicated
head -c 5000 /dev/zero | tr '\0' 'z' > "$S/zeros.txt"
ln -s hello.txt "$S/link"
# 25 entries with long names: a directory of two blocks.
for i in $(seq -w 1 25); do
  printf 'entry %s\n' "$i" > "$S/big/$(printf "directory-entry-$i-%0180d" 0)"
done
printf 'nested\n' > "$S/dir/nested.txt"
mknod "$S/null" c 1 3
mkfifo "$S/pipe"
setfattr -n user.comment -v 'an inline attribute' "$S/hello.txt"
for f in hello.txt numbers.txt zeros.txt dir; do
  setfattr -n user.shared -v 'shared by several inodes' "$S/$f"
done
setfacl -m u:1000:r "$S/numbers.txt"
touch -h -d @$T "$S" "$S"/* "$S"/*/*

common="-T $T -U $UUID --all-root -Lfillyfoal --workers=1 --quiet"
# Uncompressed: flat inline/plain files, extended inodes, chunk-based files
# (block map), shared and inline xattrs, a long xattr name prefix and the
# xattr name filter.
mkfs.erofs $common -x 1 -E force-inode-extended,xattr-name-filter \
  --chunksize=4096 --xattr-prefix=user.sha plain.erofs "$S"
# Uncompressed, compact inodes, chunk-based files with chunk indexes.
mkfs.erofs $common -E force-inode-compact,force-chunk-indexes \
  --chunksize=8192 chunk-indexes.erofs "$S"
# LZ4HC with big physical clusters, compact 2-byte indexes, tail packing,
# fragments (a packed inode) and deduplication.
mkfs.erofs $common -zlz4hc,level=12 -C 16384 -E ztailpacking,fragments,dedupe \
  lz4hc.erofs "$S"
# MicroLZMA with the legacy (full) cluster index.
mkfs.erofs $common -zlzma -E legacy-compress lzma.erofs "$S"
# DEFLATE and Zstandard.
mkfs.erofs $common -zdeflate -E ztailpacking deflate.erofs "$S"
mkfs.erofs $common -zzstd,level=19 zstd.erofs "$S"
for f in ./*.erofs; do dump.erofs -s "$f" > "$f.txt"; fsck.erofs "$f"; done
ls -l ./*.erofs
