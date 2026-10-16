#!/bin/sh
# Runs inside the container started by make-external.sh: archives a small
# neutral directory tree with `fsarchiver savedir` (no mount or device
# needed) once per compression algorithm, and once encrypted. The whole run
# is under faketime, so the creation dates are fixed (and the archive id,
# which came out equal to the faked creation time).
set -eu
apt-get update -qq > /dev/null
# fsarchiver 0.8.8-1 links libcom_err without depending on it.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  fsarchiver libcom-err2 faketime > /dev/null 2>&1
for p in fsarchiver faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
rm -rf "$OUT" /tmp/t
mkdir -p "$OUT" /tmp/t/tree/sub
cd /tmp/t
printf 'fillyfoal fsarchiver fixture\n' > tree/readme.txt
i=0
while [ $i -lt 100 ]; do
  printf 'fillyfoal line %05d of the fsarchiver fixture\n' $i
  i=$((i + 1))
done > tree/sub/lines.txt
# Large enough (312.5 KiB) to be stored in blocks of its own rather than
# packed with the small files; zeros, so that it compresses to almost
# nothing and its content is not a long text listing.
head -c 320000 /dev/zero > tree/large.bin
ln -s readme.txt tree/link
touch -h -d '2024-01-01 00:00:00' tree/readme.txt tree/sub/lines.txt tree/large.bin tree/link tree/sub tree
save() {
  out=$1
  shift
  faketime -f '2024-01-01 00:00:00' fsarchiver savedir "$@" "$OUT/$out" tree > /dev/null
}
save zstd.fsa -Z 3
save lz4.fsa -z 0
save lzo.fsa -z 1
save gzip.fsa -z 3
save bzip2.fsa -z 5
save xz.fsa -z 7
save blowfish.fsa -Z 3 -c fillyfoal
faketime -f '2024-01-01 00:00:00' fsarchiver archinfo "$OUT/zstd.fsa" 2>&1 | sed -n '/Archive type/,/Encryption/p'
ls -l "$OUT"
