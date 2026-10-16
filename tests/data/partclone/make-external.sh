#!/bin/sh
# Rebuilds the partclone fixtures made by the real tool:
#
#   tests/fixtures/external/partclone/fat16.img.raw.zst
#     `partclone.fat16 -c` of a 4 MiB FAT16 volume (image format 0002,
#     default CRC32 checksums);
#   tests/fixtures/external/partclone/ext2-k8-noreseed.img.raw.zst
#     `partclone.extfs -c -k 8 -K` of a 1 MiB ext2 volume (a checksum every
#     8 blocks, carried on from one to the next);
#   tests/fixtures/external/partclone/ext2-nocrc.img.raw.zst
#     `partclone.extfs -c -a 0` of the same volume (no checksums);
#   tests/fixtures/external/partclone/fat16-v1.img.raw.zst
#     partclone 0.2.73 (Debian 8) of the FAT16 volume: image format 0001;
#   tests/fixtures/external/gzip/partclone-ext2.img.gz
#     the ext2 volume saved to standard output (`-k 16`), through gzip -9 -n;
#   tests/fixtures/external/zstd/partclone-fat16.img.zst
#     the FAT16 volume saved to standard output, through zstd -19.
#
# (The four images are stored with `zstd -19`; the harness decompresses
# them.) Runs plain Debian containers (no loop devices: mkfs.fat, mcopy and
# mkfs.ext2 -d work on files), host name "fillyfoal", in a scratch
# directory outside the home directory:
#
#   sh tests/data/partclone/make-external.sh [scratch dir]
#
# Timestamps come from faketime and touch, volume ids and UUIDs are fixed,
# so the output is reproducible for the same package versions (the inner
# scripts print them).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/partclone}
mkdir -p "$work"
rm -rf "$work/out"
docker run --rm --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner.sh
docker run --rm --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian/eol:jessie sh /data/inner-v1.sh
ext="$repo/tests/fixtures/external"
mkdir -p "$ext/partclone" "$ext/gzip" "$ext/zstd"
for f in fat16.img ext2-k8-noreseed.img ext2-nocrc.img fat16-v1.img; do
  zstd -19 -q -f "$work/out/$f" -o "$ext/partclone/$f.raw.zst"
done
cp "$work/out/partclone-ext2.img.gz" "$ext/gzip/"
cp "$work/out/partclone-fat16.img.zst" "$ext/zstd/"
