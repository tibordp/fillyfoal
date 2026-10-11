#!/bin/sh
# PDB files written by Open Babel (Debian bookworm package), which start
# with COMPND/AUTHOR records rather than HEADER.
#
#   docker run --rm -v "$OUT":/w -w /w -v "$PWD/tests/data/pdb-structure":/gen:ro \
#     debian:bookworm-slim sh /gen/make_obabel.sh
#
# Writes ethanol.pdb in the current directory: `obabel` of the hand-written
# XYZ coordinates of ethanol below (bonds perceived by Open Babel, so the
# file has HETATM and CONECT records). Reproduces byte for byte.
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq openbabel >/dev/null 2>&1
obabel -V
cat > ethanol.xyz <<'EOF'
9
ethanol
C   -0.0011   -0.0236    0.0000
C    1.5168   -0.0236    0.0000
O    2.0023    1.3055    0.0000
H   -0.3874   -1.0457    0.0000
H   -0.3874    0.4882    0.8850
H   -0.3874    0.4882   -0.8850
H    1.8854   -0.5450    0.8880
H    1.8854   -0.5450   -0.8880
H    2.9603    1.2662    0.0000
EOF
obabel -ixyz ethanol.xyz -opdb -O ethanol.pdb
rm ethanol.xyz
