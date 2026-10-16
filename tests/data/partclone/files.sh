#!/bin/sh
# Writes the neutral files the partclone fixtures' volumes hold, in the
# current directory: readme.txt and lines.txt (about 4.6 KiB), and a tree/
# copy of both for mkfs.ext2 -d. Shared by inner.sh and inner-v1.sh.
set -eu
printf 'fillyfoal partclone fixture\n' > readme.txt
i=0
while [ $i -lt 100 ]; do
  printf 'fillyfoal line %05d of the partclone fixture\n' $i
  i=$((i + 1))
done > lines.txt
touch -d '2024-01-01 00:00:00' readme.txt lines.txt
mkdir -p tree
cp -p readme.txt lines.txt tree/
touch -d '2024-01-01 00:00:00' tree
