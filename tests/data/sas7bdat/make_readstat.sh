#!/bin/sh
# A SAS7BDAT file written by ReadStat's command-line tool (Debian bookworm
# `readstat` package).
#
#   docker run --rm -v "$OUT":/w -w /w -v "$PWD/tests/data/sas7bdat":/gen:ro \
#     debian:bookworm-slim sh /gen/make_readstat.sh
#
# Writes readstat.sas7bdat in the current directory: `readstat` converts
# the CSV below, typed by the JSON metadata, into a Stata file (its CSV
# reader does not take SAS metadata), and that into a SAS data set (64-bit,
# little endian, uncompressed): a string and two numeric columns with
# labels, four rows, one missing value. The date format does not survive
# the conversion. Creation times differ on each run.
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq readstat >/dev/null 2>&1
readstat --version 2>&1 | head -1 || true
cat > cars.csv <<'EOF'
model,mpg,built
alpha,21.5,2001-03-04
beta,,1999-12-31
gamma,30.25,2010-07-01
delta,18,1985-01-15
EOF
cat > cars.json <<'EOF'
{
  "type": "STATA",
  "variables": [
    {"type": "STRING", "name": "model", "label": "Model"},
    {"type": "NUMERIC", "name": "mpg", "label": "Miles per gallon"},
    {"type": "NUMERIC", "name": "built", "label": "Built", "format": "DATE"}
  ]
}
EOF
readstat cars.csv cars.json cars.dta
readstat cars.dta readstat.sas7bdat
rm cars.csv cars.json cars.dta
