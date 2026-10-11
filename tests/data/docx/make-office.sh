#!/bin/sh
# Builds the ZIP-based office fixtures with LibreOffice in Docker (Debian
# trixie, libreoffice-*-nogui) from the flat ODF sources already in
# tests/data, in a throwaway profile whose user name is "fillyfoal":
#
#   docx/letter.docx         Writer "MS Word 2007 XML" (every entry has bit 3
#                            set: sizes in data descriptors)
#   docx/letter-zipfile.docx the same package rewritten entry by entry by
#                            Python's zipfile (no bit 3, sizes in the local
#                            headers), see rewrite.py
#   xlsx/budget.xlsx         Calc "Calc MS Excel 2007 XML" (bit 3)
#   odt/letter.odt           Writer's own format
#   epub/letter.epub         Writer's EPUB export
#
# LibreOffice stamps the conversion time into the metadata, so reruns are
# not byte-for-byte identical.
#
#   sh tests/data/docx/make-office.sh [fixtures directory]
set -eu
DATA=$(cd "$(dirname "$0")/.." && pwd)
FIX=$(cd "${1:-$DATA/../fixtures/external}" && pwd)
B=/tmp/fixtures/archive-office
rm -rf "$B/in" "$B/out"
mkdir -p "$B/in" "$B/out"
cp "$DATA/doc/letter.fodt" "$DATA/xls/budget.fods" "$DATA/docx/rewrite.py" "$B/in/"

docker build -q -t fillyfoal-libreoffice - <<'EOF'
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libreoffice-writer-nogui libreoffice-calc-nogui && rm -rf /var/lib/apt/lists/*
EOF

docker run --rm -v "$B:/work" -w /work fillyfoal-libreoffice sh -eu -c '
mkdir -p /tmp/lo/user
cat > /tmp/lo/user/registrymodifications.xcu <<XCU
<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<item oor:path="/org.openoffice.UserProfile/Data"><prop oor:name="givenname" oor:op="fuse"><value>fillyfoal</value></prop></item>
<item oor:path="/org.openoffice.UserProfile/Data"><prop oor:name="sn" oor:op="fuse"><value></value></prop></item>
<item oor:path="/org.openoffice.UserProfile/Data"><prop oor:name="initials" oor:op="fuse"><value>FF</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Save/Document"><prop oor:name="GenerateThumbnail" oor:op="fuse"><value>false</value></prop></item>
</oor:items>
XCU
lo() { soffice -env:UserInstallation=file:///tmp/lo --headless --convert-to "$1" --outdir out "$2"; }
lo docx in/letter.fodt
lo odt in/letter.fodt
lo epub in/letter.fodt
lo xlsx in/budget.fods
'
docker run --rm -v "$B:/work" -w /work python:3.12-slim \
    python3 -I in/rewrite.py out/letter.docx out/letter-zipfile.docx

mkdir -p "$FIX/docx" "$FIX/xlsx" "$FIX/odt" "$FIX/epub"
cp "$B/out/letter.docx" "$B/out/letter-zipfile.docx" "$FIX/docx/"
cp "$B/out/budget.xlsx" "$FIX/xlsx/"
cp "$B/out/letter.odt" "$FIX/odt/"
cp "$B/out/letter.epub" "$FIX/epub/"
