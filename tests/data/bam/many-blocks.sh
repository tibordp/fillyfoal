#!/bin/sh
# Writes many-blocks.bam: a coordinate-sorted BAM of 100 synthetic reads,
# each with a 60000-byte array tag (about 6 MiB of records, so more than
# 64 BGZF blocks, most records spanning two) with samtools from
# Debian bookworm. Run from an empty directory:
#   docker run --rm -v "$PWD":/out -w /out debian:bookworm-slim sh /out/many-blocks.sh
set -eu
if ! command -v samtools >/dev/null; then
    apt-get update -qq && apt-get install -y -qq samtools >/dev/null
fi
awk 'BEGIN {
    seed = 12345
    ref = ""
    for (i = 0; i < 4096; i++) {
        seed = (seed * 1103515245 + 12345) % 2147483648
        ref = ref substr("ACGT", int(seed / 65536) % 4 + 1, 1)
    }
    array = ""
    for (i = 0; i < 60000; i++) array = array "," (i % 16)
    print "@HD\tVN:1.6\tSO:coordinate"
    print "@SQ\tSN:chr1\tLN:2000000"
    print "@RG\tID:rg1\tSM:sample1"
    for (n = 0; n < 100; n++) {
        pos = n * 1500 + 1
        flag = (n % 3 == 0) ? 16 : 0
        seq = substr(ref, (n * 37) % 4000 + 1, 50)
        printf "r%06d\t%d\tchr1\t%d\t60\t50M\t*\t0\t0\t%s\t*\tNM:i:%d\tRG:Z:rg1\tXB:B:C%s\n", n, flag, pos, seq, n % 4, array
    }
}' > reads.sam
samtools view -b --no-PG -o many-blocks.bam reads.sam
rm reads.sam
samtools --version | head -1
