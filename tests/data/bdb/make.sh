#!/bin/sh
# Writes the external Berkeley DB fixtures with db_load (macOS /usr/bin/db_load,
# Berkeley DB 4.7.25):
#
#   sh tests/data/bdb/make.sh OUTDIR
#
# - btree47.db: B-tree, 512-byte pages, 40 keys and one 1.5 KB value that
#   goes to overflow pages.
# - hash47.db: hash, 512-byte pages, the same pairs.
# - chksum47.db: B-tree with page checksums (-c chksum=1), 6 pairs.
# - recno47.db: recno, 512-byte pages, 300 records (internal + leaf pages).
set -eu
cd "$1"
rm -f btree47.db hash47.db chksum47.db recno47.db pairs.txt small.txt lines.txt
i=1
while [ "$i" -le 40 ]; do
    printf 'key-%03d\nvalue number %d\n' "$i" "$i" >> pairs.txt
    i=$((i + 1))
done
printf 'big\n' >> pairs.txt
i=1
while [ "$i" -le 30 ]; do printf 'fillyfoal-overflow-' >> pairs.txt; i=$((i + 1)); done
printf '\n' >> pairs.txt
printf 'alpha\none\nbeta\ntwo\ngamma\nthree\ndelta\nfour\nepsilon\nfive\nzeta\nsix\n' > small.txt
i=1
while [ "$i" -le 300 ]; do printf 'record-number-%d\n' "$i" >> lines.txt; i=$((i + 1)); done
db_load -T -t btree -c db_pagesize=512 -f pairs.txt btree47.db
db_load -T -t hash -c db_pagesize=512 -f pairs.txt hash47.db
db_load -T -t btree -c chksum=1 -f small.txt chksum47.db
db_load -T -t recno -c db_pagesize=512 -f lines.txt recno47.db
rm -f pairs.txt small.txt lines.txt
