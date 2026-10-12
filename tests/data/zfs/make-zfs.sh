#!/bin/sh
# Makes the ZFS fixtures on a disposable Linux VM with zfsutils-linux
# (run as root; host name "fillyfoal", TZ=UTC). Output: /tmp/fixtures/zfs.
#   tank.img           64 MiB single-file pool (ashift 9): lz4 and zstd
#                      datasets, files, a snapshot and a 4 MiB zvol; exported.
#   mirror-a.img, -b   64 MiB two-way mirror pool "mpool" (ashift 9), exported.
#   raidz-a.img, -b, -c 64 MiB raidz1 pool "rz" (ashift 12), exported.
# Then zdb's view of each, and every image compressed with zstd -19.
set -eu
export TZ=UTC LC_ALL=C
D=/tmp/fixtures/zfs
M=/tmp/fixtures/mnt
rm -rf "$D" "$M"; mkdir -p "$D" "$M"; cd "$D"
zgenhostid -f 0x0f1110f0
for f in tank mirror-a mirror-b raidz-a raidz-b raidz-c; do truncate -s 64M "$f.img"; done

zpool create -o ashift=9 -O mountpoint=$M/tank -O atime=off tank "$D/tank.img"
zfs create -o compression=lz4 tank/lz4
zfs create -o compression=zstd tank/zstd
for ds in lz4 zstd; do
  printf 'hello from fillyfoal (%s)\n' "$ds" > "$M/tank/$ds/hello.txt"
  seq 1 20000 > "$M/tank/$ds/numbers.txt"
  head -c 8192 /dev/zero | tr '\0' 'z' > "$M/tank/$ds/zeds.bin"
done
mkdir "$M/tank/lz4/dir"
echo nested > "$M/tank/lz4/dir/nested.txt"
zfs snapshot tank/lz4@snap1
echo after-snapshot >> "$M/tank/lz4/hello.txt"
zfs create -V 4M -o volblocksize=16K tank/vol
udevadm settle
printf 'fillyfoal zvol block 0\n' | dd of=/dev/zvol/tank/vol conv=notrunc status=none
sync
zpool export tank

zpool create -o ashift=9 -O mountpoint=$M/mirror mpool mirror "$D/mirror-a.img" "$D/mirror-b.img"
echo 'mirrored by fillyfoal' > "$M/mirror/readme.txt"
sync; zpool export mpool

zpool create -o ashift=12 -O mountpoint=$M/rz rz raidz1 "$D/raidz-a.img" "$D/raidz-b.img" "$D/raidz-c.img"
echo 'raidz by fillyfoal' > "$M/rz/readme.txt"
sync; zpool export rz

# Reference output (zdb on the exported pools).
for f in *.img; do zdb -l "$D/$f" > "$f.zdb-l.txt" 2>&1 || true; done
zdb -e -p "$D" -dd tank > tank.zdb-dd.txt 2>&1 || true
zdb -e -p "$D" -dd tank/lz4 > tank-lz4.zdb-dd.txt 2>&1 || true
zdb -e -p "$D" -uuu tank > tank.zdb-u.txt 2>&1 || true
zdb -e -p "$D" -uuu rz > rz.zdb-u.txt 2>&1 || true
for f in *.img; do zstd -q -19 -f "$f" -o "$f.raw.zst"; done
ls -l
