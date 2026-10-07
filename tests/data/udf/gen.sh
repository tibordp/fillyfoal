#!/bin/sh
# Generates the external UDF fixtures with macOS hdiutil and pycdlib.
# Usage: sh tests/data/udf/gen.sh FIXTURES   (e.g. tests/fixtures/external)
# Both stamp creation times (and hdiutil volume IDs), so output is not
# byte-reproducible. hdiutil writes the same image for -udf-version 1.50,
# 2.00 and 2.01 (all UDF 1.50, NSR02), so only 1.02 and 1.50 are kept.
set -eu
out=${1:?fixtures directory}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
mkdir -p "$work/src/docs/deep"
printf 'hello UDF\n' > "$work/src/hello.txt"
printf 'nested file\n' > "$work/src/docs/deep/note.txt"
printf '{"a":1}\n' > "$work/src/docs/data.json"
# A file large enough to need its own extent (not embedded in its ICB).
i=0
while [ $i -lt 200 ]; do printf 'line %03d of a longer text file\n' $i; i=$((i + 1)); done > "$work/src/long.txt"
chmod 600 "$work/src/hello.txt"
for v in 1.02 1.50; do
  hdiutil makehybrid -quiet -udf -udf-version "$v" -udf-volume-name FILLY \
    -o "$work/udf-$v.iso" "$work/src"
done
hdiutil makehybrid -quiet -iso -udf -udf-volume-name FILLY -o "$work/udf-bridge.iso" "$work/src"
uv run --with pycdlib==1.21.0 python -I "$here/pycdlib_udf.py" "$work/pycdlib-udf.iso"
mkdir -p "$out/udf" "$out/iso9660"
for v in 1.02 1.50; do
  gzip -9 -n -c "$work/udf-$v.iso" > "$out/udf/udf-$v.iso.gz"
done
gzip -9 -n -c "$work/udf-bridge.iso" > "$out/iso9660/udf-bridge.iso.gz"
gzip -9 -n -c "$work/pycdlib-udf.iso" > "$out/iso9660/pycdlib-udf.iso.gz"
rm -rf "$work"
