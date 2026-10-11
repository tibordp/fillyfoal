#!/bin/sh
# Builds the larger text fixtures (past the 36 KiB probe head, so line and
# record counts are estimated and walks cross scan windows) with real
# writers: Python's csv module, jq, and iconv. Output in
# /tmp/fixtures/text-large; copy into tests/fixtures/external/.
set -eu
W=/tmp/fixtures/text-large
rm -rf "$W"
mkdir -p "$W"
cd "$W"
# CSV: quoted fields, embedded commas, quotes and line breaks (csv.writer,
# QUOTE_MINIMAL, CRLF records).
python3 -I - <<'EOF'
import csv
with open("records.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "name", "city", "note", "amount"])
    for i in range(1, 1001):
        note = f'line one of "{i}"\nline two, with a comma' if i % 50 == 0 else f"note {i}"
        w.writerow([i, f"Person {i:04}", ["Ljubljana", "Maribor", "Celje", "Koper"][i % 4], note, f"{i * 3.25:.2f}"])
EOF
# JSON: an array of objects, pretty-printed by jq.
jq -n '[range(1; 241) | {id: ., name: "item \(.)", tags: ["a", "b"], price: (. * 1.5), active: (. % 2 == 0), meta: {created: "2024-01-01T00:00:00Z", n: null}}]' > items.json
# UTF-16LE text with a byte order mark, transcoded by iconv.
python3 -I -c '
import sys
for i in range(1, 601):
    sys.stdout.write(f"Vrstica {i} čšž ÄÖÜ ελληνικά русский текст\n")
' > lines.utf8
{ printf '\377\376'; iconv -f UTF-8 -t UTF-16LE lines.utf8; } > lines-utf16le.txt
rm lines.utf8
ls -l "$W"
