#!/bin/sh
# Real-tool fixture for 7z BCJ2: an x86-64 executable we build ourselves,
# archived by 7-Zip with the BCJ2 filter (four packed streams).
#
#   Apple clang 21 (x86_64-apple-macos11 target), strip, 7-Zip 26.03 (7zz)
#
# Usage: sh tests/data/7z/make_bcj2.sh [outdir]   (default /tmp/fixtures/codecs-bcj2)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/tmp/fixtures/codecs-bcj2}
mkdir -p "$out"
cd "$out"
rm -f prog prog.c bcj2.7z

# Sixty small functions and a main that calls them 800 times: plenty of
# E8 CALLs for BCJ2 to convert.
python3 -I - > prog.c <<'PY'
n = 60
print("#include <stdio.h>")
for i in range(n):
    print(f"__attribute__((noinline)) int f{i}(int x) {{ return x * {i + 3} + {i}; }}")
print("int main(int argc, char **argv) { int s = argc;")
for k in range(400):
    print(f"  s = f{(k * 7) % n}(s) ^ f{(k * 13 + 5) % n}(s + {k});")
print('  if (s & 1) { s = f%d(s); } printf("%%d\\n", s); return 0; }' % (n - 1))
PY
clang -target x86_64-apple-macos11 -O1 -ffile-prefix-map="$out"=. -o prog prog.c
strip prog
TZ=UTC touch -t 202401020304 prog
7zz a -t7z -mf=BCJ2 -m0=LZMA2 -mhc=off bcj2.7z prog > /dev/null
ls -l prog bcj2.7z
