#!/bin/sh
# Writes the external CHM fixture with chmcmd from Free Pascal 3.2.2
# (Debian bookworm's fp-utils; needs Docker):
#
#   sh tests/data/chm/make.sh OUTDIR
#
# chm/chmcmd.chm: a help project of 40 generated HTML pages (about 130 KB
# of text, so the LZX section spans several reset intervals), a table of
# contents and an index, with a title and a default topic in #SYSTEM.
# IMAGE may name a prepared image that already has fp-utils.
set -eu
out=$(cd "$1" && pwd)
docker run --rm -v "$out:/out" "${IMAGE:-debian:bookworm-slim}" sh -c '
set -eu
if ! command -v chmcmd >/dev/null; then
    apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends fp-utils python3 >/dev/null 2>&1
fi
mkdir -p /tmp/proj && cd /tmp/proj
python3 -I - <<EOF
words = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike".split()
files = []
toc = ["<html><body><ul>"]
for p in range(40):
    name = "page%02d.html" % p
    files.append(name)
    paras = []
    for i in range(24):
        w = [words[(p * 11 + i * 7 + k * 3) % len(words)] for k in range(6 + (p + i) % 7)]
        paras.append("<p>Paragraph %d of page %d tells of %s.</p>" % (i, p, " ".join(w)))
    with open(name, "w") as f:
        f.write("<html><head><title>Page %d</title></head><body><h1>Page %d</h1>%s</body></html>\n" % (p, p, "\n".join(paras)))
    toc.append("<li><object type=\"text/sitemap\"><param name=\"Name\" value=\"Page %d\"><param name=\"Local\" value=\"%s\"></object>" % (p, name))
toc.append("</ul></body></html>")
with open("toc.hhc", "w") as f:
    f.write("\n".join(toc) + "\n")
with open("index.hhk", "w") as f:
    f.write("\n".join(toc) + "\n")
with open("sample.hhp", "w") as f:
    f.write("[OPTIONS]\nCompiled file=sample.chm\nContents file=toc.hhc\nIndex file=index.hhk\n"
            "Default topic=page00.html\nTitle=Fillyfoal Sample Help\nLanguage=0x409 English (United States)\n\n"
            "[FILES]\n" + "\n".join(files) + "\n")
EOF
chmcmd sample.hhp >/dev/null
mkdir -p /out/chm
cp sample.chm /out/chm/chmcmd.chm
'
