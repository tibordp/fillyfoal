#!/bin/sh
# UFS and NILFS2 fixtures (tests/fixtures/external/ufs/, .../nilfs2/). From
# the repository root:
#
#   mkdir -p /tmp/fixtures/disk-b-misc
#   docker run --rm --hostname fillyfoal \
#     -v /tmp/fixtures/disk-b-misc:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     debian:trixie-slim sh /src/make-ufs-nilfs.sh
#
# makefs (NetBSD's, Debian 20190105) writes FFS images from a directory
# with no mount: UFS1 and UFS2, with fixed timestamps. mkfs.nilfs2
# (nilfs-tools 2.2.11) formats an empty NILFS2 volume (nothing fills one
# without a mount); its UUID and creation time are random/current, so it
# is not byte-reproducible.
set -eu
export TZ=UTC
apt-get update -qq
apt-get install -y -qq --no-install-recommends makefs nilfs-tools zstd >/dev/null
rm -rf tree ./*.img ./*.zst
mkdir -p tree/dir
printf 'Hello, fillyfoal!\n' > tree/hello.txt
printf 'nested\n' > tree/dir/nested.txt
seq 1 3000 > tree/numbers.txt
ln -s hello.txt tree/link
touch -h -d '2024-01-01 00:00:00' tree tree/* tree/dir/*
makefs -t ffs -o version=1 -s 1m -T 1704067200 ufs1.img tree
makefs -t ffs -o version=2 -s 1m -T 1704067200 ufs2.img tree
truncate -s 8m nilfs2.img
mkfs.nilfs2 -q -f -L fillyfoal -b 1024 -B 256 nilfs2.img
for f in ufs1 ufs2 nilfs2; do
  zstd -q -19 -f $f.img -o $f.img.raw.zst
done
ls -l ./*.zst
