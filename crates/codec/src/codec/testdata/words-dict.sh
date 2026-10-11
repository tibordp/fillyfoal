#!/bin/sh
# Generates the zstd dictionary test vectors with the zstd CLI (1.5.7):
#
#   sh words-dict.sh   (in this directory)
#
# words.zdict      a formatted dictionary (ID 4242) trained on 2000-byte
#                  pieces of words.txt
# words-dict.zst   three frames using it: the first 2000 bytes at level 3
#                  with a checksum, bytes 50000..110000 at level 19 with a
#                  4 KiB window (the dictionary stops being valid after the
#                  first window), and bytes 20000..20300 at level 1
# words-raw.zst    one frame using bytes 0..8192 of words.txt as a raw
#                  content dictionary (so the frame names no dictionary):
#                  bytes 30000..40000 at level 3
set -eu
t=$(mktemp -d)
split -b 2000 words.txt "$t/s."
zstd -q --train "$t"/s.* --maxdict=4096 --dictID=4242 -o words.zdict
head -c 2000 words.txt > "$t/a"
tail -c +50001 words.txt | head -c 60000 > "$t/b"
tail -c +20001 words.txt | head -c 300 > "$t/c"
tail -c +30001 words.txt | head -c 10000 > "$t/d"
head -c 8192 words.txt > "$t/raw"
{
    zstd -q -c -3 --check -D words.zdict "$t/a"
    zstd -q -c -19 --zstd=wlog=12 -D words.zdict "$t/b"
    zstd -q -c -1 --no-check -D words.zdict "$t/c"
} > words-dict.zst
zstd -q -c -3 -D "$t/raw" "$t/d" > words-raw.zst
rm -r "$t"
