#!/bin/sh
# Headerless BED files written by bedtools (Debian bookworm package).
#
#   docker run --rm -v "$OUT":/w -w /w -v "$PWD/tests/data/bed":/gen:ro \
#     debian:bookworm-slim sh /gen/make_bedtools.sh
#
# Writes, in the current directory:
# - random.bed: `bedtools random` (six columns: name, score, strand) of six
#   100-base features on a two-chromosome genome, sorted;
# - windows.bed: `bedtools makewindows` (three columns), 1000-base windows.
# Both reproduce byte for byte (fixed seed).
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq bedtools >/dev/null 2>&1
bedtools --version
printf 'chr1\t5000\nchr2\t3000\n' > genome.txt
bedtools random -l 100 -n 6 -seed 42 -g genome.txt | bedtools sort > random.bed
bedtools makewindows -g genome.txt -w 1000 > windows.bed
rm genome.txt
