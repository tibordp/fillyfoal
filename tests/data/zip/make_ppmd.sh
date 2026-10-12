#!/bin/sh
# Real-tool fixture for ZIP method 98 (PPMd var. I rev. 1): 7-Zip's ZIP
# writer with its PPMd coder, two plain entries and one ZipCrypto-encrypted
# one (password "fillyfoal").
#
#   7-Zip 26.03 (7zz)
#
# Usage: sh tests/data/zip/make_ppmd.sh [outdir]   (default /tmp/fixtures/archive-zip-ppmd)
set -eu
out=${1:-/tmp/fixtures/archive-zip-ppmd}
mkdir -p "$out"
cd "$out"
rm -rf in ppmd.zip
mkdir in

# Generated text: a few thousand words of an English-like word list, and a
# small table of numbers.
python3 -I - <<'PY'
import random
r = random.Random(98)
words = ["filly", "foal", "archive", "model", "context", "symbol", "order", "escape",
         "range", "coder", "memory", "restart", "cut", "off", "binary", "frequency"]
with open("in/words.txt", "w") as f:
    for i in range(300):
        f.write(" ".join(r.choice(words) for _ in range(r.randint(3, 9))) + "\n")
with open("in/table.csv", "w") as f:
    f.write("n,square,cube\n")
    for n in range(60):
        f.write(f"{n},{n * n},{n * n * n}\n")
with open("in/secret.txt", "w") as f:
    for i in range(60):
        f.write(f"line {i}: the quick brown foal jumps over the lazy filly\n")
PY
TZ=UTC touch -t 202401020304 in/words.txt in/table.csv in/secret.txt
cd in
7zz a -tzip -mm=PPMd -mtc=off ../ppmd.zip words.txt table.csv > /dev/null
7zz a -tzip -mm=PPMd -mtc=off -pfillyfoal ../ppmd.zip secret.txt > /dev/null
cd ..
ls -l ppmd.zip
