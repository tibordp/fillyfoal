#!/bin/sh
# Runs inside debian:trixie-slim (see footers.sh); writes /work/out/*.
set -eu
export DEBIAN_FRONTEND=noninteractive SOURCE_DATE_EPOCH=0
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 e2fsprogs erofs-utils >/dev/null
dpkg-query -W e2fsprogs erofs-utils python3
AVB="python3 /avb/avbtool.py"
cd /work
mkdir -p in/tree out
printf 'fillyfoal avb footer fixture\n' > in/tree/README
seq 1 200 | sed 's/^/line /' > in/tree/notes.txt

footer() {
    $AVB add_hashtree_footer --image "$1" --partition_size "$2" \
        --partition_name "$3" --hash_algorithm sha256 --salt 66696c6c79666f616c \
        --do_not_generate_fec --algorithm NONE --prop "com.fillyfoal.partition:$3"
    $AVB info_image --image "$1"
}

# ext4, 256 KiB of 1 KiB blocks, in a 384 KiB partition.
E2FSPROGS_FAKE_TIME=1767225600 mke2fs -q -t ext4 -b 1024 -N 32 -L avb \
    -U 0f111f0a-0000-4000-8000-000000000001 \
    -E hash_seed=0f111f0a-0000-4000-8000-000000000002,root_owner=0:0 \
    -d in/tree out/ext4-avb.img 256k
footer out/ext4-avb.img 393216 system

# EROFS, padded by avbtool to 4 KiB blocks, in an 88 KiB partition (avbtool keeps 72 KiB for the vbmeta and footer).
mkfs.erofs --quiet -T0 --all-root -U 0f111f0a-0000-4000-8000-000000000003 \
    out/erofs-avb.erofs in/tree
footer out/erofs-avb.erofs 90112 vendor

# A bare data partition: 16 KiB of a byte ramp, in a 96 KiB partition.
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)) * 64)" > out/data-avb.img
footer out/data-avb.img 98304 data
