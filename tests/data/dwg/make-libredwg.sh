#!/bin/sh
# Writes the external dwg/ fixtures with GNU LibreDWG's dwgwrite (openSUSE
# Tumbleweed's libredwg-tools, 0.14.8413 when the fixtures were made) in
# Docker, from a small DXF drawing written by ezdxf (libredwg_dxf.py).
#
#   sh tests/data/dwg/make-libredwg.sh <repo root>
#
# dwgwrite --as r13 r14 r2000 r2004 r2010 r2013 r2018 all read back with
# dwgread. Not committed: r2007 (dwgwrite writes AC1024, i.e. R2010, for
# it), r9/r10/r11 (written, but dwgread rejects them). dxf2dwg writes the
# same bytes as dwgwrite for r14, r2000 and r2004. LibreDWG writes the
# R2004+ sections stored (uncompressed) in pages padded to 0x7400 bytes,
# so those files are 0.3-1.6 MB of mostly zeros: they are stored as
# <name>.dwg.raw.zst (zstd -19), which the test harness decompresses.
# The output is the same on every run.
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/science-dwg-libredwg
rm -rf "$work"
mkdir -p "$work"
PYTHONHASHSEED=0 uv run -q --with ezdxf==1.4.4 python -I \
    "$root/tests/data/dwg/libredwg_dxf.py" "$work/drawing.dxf"
docker run --rm -v "$work:/w" -w /w opensuse/tumbleweed sh -euc '
zypper --non-interactive -q in libredwg-tools >/dev/null
dwgwrite --version | head -1 >version.txt
for v in r13 r14 r2000 r2004 r2010 r2013 r2018; do
    dwgwrite -y --as $v -o libredwg-$v.dwg drawing.dxf >/dev/null 2>&1
    dwgread -O JSON -o libredwg-$v.json libredwg-$v.dwg >/dev/null 2>&1
done
'
out=$root/tests/fixtures/external/dwg
mkdir -p "$out"
for v in r13 r14 r2000; do
    cp "$work/libredwg-$v.dwg" "$out/libredwg-$v.dwg"
done
for v in r2004 r2010 r2013 r2018; do
    zstd -q -19 -f "$work/libredwg-$v.dwg" -o "$out/libredwg-$v.dwg.raw.zst"
done
cat "$work/version.txt"
