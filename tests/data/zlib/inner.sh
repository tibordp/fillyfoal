#!/bin/sh
# Runs inside the container started by make-external.sh: compresses neutral
# text into zlib streams with Python's zlib module (levels 1, 9 and 0, the
# last made of stored blocks; the smallest window; a preset dictionary) and
# with pigz -z (zopfli, -11).
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  python3-minimal pigz > /dev/null 2>&1
dpkg-query -W -f '${Package} ${Version}\n' python3-minimal pigz
python3 -c 'import zlib; print("zlib", zlib.ZLIB_RUNTIME_VERSION)'
OUT=/w/out
rm -rf "$OUT"
mkdir -p "$OUT"
cd /tmp
i=0
while [ $i -lt 60 ]; do
  printf 'fillyfoal line %05d of the zlib fixture\n' $i
  i=$((i + 1))
done > lines.txt
python3 - "$OUT" << 'EOF'
import sys, zlib
out = sys.argv[1]
DICT = b"fillyfoal line of the zlib fixture\n"
data = open("lines.txt", "rb").read()
for name, level in (("python-level1.zlib", 1), ("python-level9.zlib", 9), ("python-stored.zlib", 0)):
    open(f"{out}/{name}", "wb").write(zlib.compress(data, level))
# The smallest window (wbits 9: CINFO 1, a 512-byte window), and a preset
# dictionary (FDICT, the dictionary's Adler-32 after the header).
c = zlib.compressobj(9, zlib.DEFLATED, 9)
open(f"{out}/python-wbits9.zlib", "wb").write(c.compress(data) + c.flush())
c = zlib.compressobj(9, zlib.DEFLATED, 15, zdict=DICT)
open(f"{out}/python-zdict.zlib", "wb").write(c.compress(data) + c.flush())
EOF
pigz -z -11 -c lines.txt > "$OUT/pigz.zz"
python3 -c 'import sys, zlib
for p in sys.argv[1:]:
    z = zlib.decompressobj(zdict=b"fillyfoal line of the zlib fixture\n") if "zdict" in p else zlib.decompressobj()
    d = z.decompress(open(p, "rb").read()); print(p, len(d), hex(zlib.adler32(d)))' "$OUT"/*
ls -l "$OUT"
