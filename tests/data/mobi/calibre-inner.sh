#!/bin/sh
# Run inside the container by calibre.sh.
set -eu
if ! command -v ebook-convert >/dev/null; then
    apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends calibre >/dev/null 2>&1
fi
cd /tmp
python3 -I - <<'PY'
words = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima".split()
lines = []
for i in range(220):
    w = [words[(i * 7 + k * 3) % len(words)] for k in range(6 + i % 5)]
    lines.append("Sentence %d tells of %s." % (i, " ".join(w)))
open("/tmp/book.txt", "w").write("\n\n".join(lines) + "\n")
PY
ebook-convert book.txt calibre.mobi --mobi-file-type old --title "Fillyfoal Sample" --authors fillyfoal >/dev/null
ebook-convert book.txt calibre.pdb --format doc --title "Fillyfoal Sample" --authors fillyfoal >/dev/null
mkdir -p /out/mobi /out/palmdoc
cp calibre.mobi /out/mobi/
cp calibre.pdb /out/palmdoc/
