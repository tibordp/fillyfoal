#!/bin/sh
# Runs inside the container started by make-wof.sh; writes /w/out/wof.img.
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ntfs-3g attr wimtools python3-minimal > /dev/null 2>&1
for p in ntfs-3g attr wimtools; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
rm -rf "$OUT" /tmp/v
mkdir -p "$OUT" /tmp/v/src /mnt/n
cd /tmp/v
python3 /data/wim-resource.py payload /tmp/v/src

# wimlib compresses each file: XPRESS in 4 KiB chunks, LZX in 32 KiB.
compress() { # file wim-compression chunk-size
  mkdir -p "one-$1"
  cp "src/$1" "one-$1/"
  wimcapture "one-$1" "$1.wim" --compress="$2" --chunk-size="$3" > /dev/null
  python3 /data/wim-resource.py extract "$1.wim" "$(stat -c %s "src/$1")" "$1.wof"
}
compress xpress.txt XPRESS 4096
compress lzx.txt LZX 32768

truncate -s 2M wof.img
mkntfs -q -F -f -L fillyfoal -c 4096 wof.img
ntfs-3g -o streams_interface=windows wof.img /mnt/n
echo 'not compressed' > /mnt/n/plain.txt
# The WOF layout: the compressed resource as the named stream, the
# unnamed $DATA extended (sparse) to the content's size, then the reparse
# point: tag 0x80000017, 16 bytes of data: WOF_EXTERNAL_INFO (version 1,
# provider 2 = file) and FILE_PROVIDER_EXTERNAL_INFO_V1 (version 1,
# algorithm: 0 XPRESS4K, 1 LZX, 2 XPRESS8K, 3 XPRESS16K).
wof() { # file algorithm-as-little-endian-u32-hex
  : > "/mnt/n/$1"
  cat "$1.wof" > "/mnt/n/$1:WofCompressedData"
  truncate -s "$(stat -c %s "src/$1")" "/mnt/n/$1"
  setfattr -n system.ntfs_reparse_data \
    -v "0x1700008010000000010000000200000001000000$2" "/mnt/n/$1"
}
wof xpress.txt 00000000
wof lzx.txt 01000000
umount /mnt/n
mv wof.img "$OUT/"
ls -l "$OUT"
