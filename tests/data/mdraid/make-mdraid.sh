#!/bin/sh
# Makes the Linux md RAID fixtures on a disposable Linux VM with mdadm and
# e2fsprogs (run as root; host name "fillyfoal", TZ=UTC). Output:
# /tmp/fixtures/mdraid.
#   r1-v090-a.img, -b   RAID1, metadata 0.90 (superblock in the last 64 KiB)
#   r1-v10-a.img, -b    RAID1, metadata 1.0 (superblock 8 KiB before the end)
#   r1-v11-a.img, -b    RAID1, metadata 1.1 (superblock at 0)
#   r1-v12-a.img, -b    RAID1, metadata 1.2 (superblock at 4 KiB)
#   r5-a.img, -b, -c    RAID5 over three members, metadata 1.2
# Every member is 8 MiB; each array holds a small ext4 file system (fixed
# UUID, hash seed and time) populated with mke2fs -d. Arrays are stopped
# cleanly; then mdadm --examine of every member, and each image
# compressed with zstd -19.
set -eu
export TZ=UTC LC_ALL=C E2FSPROGS_FAKE_TIME=1791763200
D=/tmp/fixtures/mdraid
rm -rf "$D"; mkdir -p "$D/content"; cd "$D"
echo 'hello from fillyfoal' > content/hello.txt
seq 1 10 > content/numbers.txt

# make NAME LEVEL METADATA MD-UUID FS-UUID MEMBER...
make() {
  name=$1 level=$2 meta=$3 uuid=$4 fsuuid=$5; shift 5
  loops=
  for m in "$@"; do
    truncate -s 8M "$m.img"
    loops="$loops $(losetup --show -f "$D/$m.img")"
  done
  set -- $loops
  mdadm --create "/dev/md/$name" --run --homehost=fillyfoal --name="$name" \
    --level="$level" --metadata="$meta" --uuid="$uuid" --raid-devices=$# \
    --assume-clean "$@"
  udevadm settle
  mke2fs -q -t ext4 -L "$name" -U "$fsuuid" \
    -E hash_seed=0f1110f0-0000-4000-8000-000000000000,root_owner=0:0 \
    -d content "/dev/md/$name"
  sync
  mdadm --stop "/dev/md/$name"
  for l in "$@"; do losetup -d "$l"; done
}

make r1-v090 1 0.90 0f1110f0:00000000:00000000:00000090 0f1110f0-0000-4000-8000-000000000090 r1-v090-a r1-v090-b
make r1-v10 1 1.0 0f1110f0:00000000:00000000:00000100 0f1110f0-0000-4000-8000-000000000100 r1-v10-a r1-v10-b
make r1-v11 1 1.1 0f1110f0:00000000:00000000:00000110 0f1110f0-0000-4000-8000-000000000110 r1-v11-a r1-v11-b
make r1-v12 1 1.2 0f1110f0:00000000:00000000:00000120 0f1110f0-0000-4000-8000-000000000120 r1-v12-a r1-v12-b
make r5 5 1.2 0f1110f0:00000000:00000000:00000500 0f1110f0-0000-4000-8000-000000000500 r5-a r5-b r5-c

for f in *.img; do
  l=$(losetup --show -r -f "$D/$f")
  mdadm --examine "$l" > "$f.examine.txt" 2>&1 || true
  losetup -d "$l"
  zstd -q -19 -f "$f" -o "$f.raw.zst"
done
ls -l
