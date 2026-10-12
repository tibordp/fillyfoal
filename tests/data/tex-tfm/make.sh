#!/bin/sh
# Writes the external TeX font metric and virtual font fixtures into OUTDIR
# with TeX Live 2026's pltotf and vptovf, from property lists written here:
#
#   sh tests/data/tex-tfm/make.sh OUTDIR
#
# - tex-tfm/pltotf.tfm: three characters (A, B, a) with widths, heights,
#   depths and an italic correction, a kerning/ligature program (A-B kern,
#   an f-i style ligature), seven parameters and a design size of 10pt
# - tex-vf/vptovf.vf (with its tex-tfm/vptovf.tfm, not kept): a virtual
#   font mapping A to pltotf's A and B to A followed by a rule
# The outputs are reproducible byte for byte.
set -eu
out=$(cd "$1" && pwd)
work=$(mktemp -d /tmp/fixtures-tex.XXXXXX)
cd "$work"
cat > pltotf.pl <<'EOF'
(FAMILY FILLYFOAL)
(FACE O 352)
(CODINGSCHEME TEST)
(DESIGNSIZE R 10.0)
(CHECKSUM O 12345670)
(FONTDIMEN
   (SLANT R 0.0)
   (SPACE R 0.333)
   (STRETCH R 0.166)
   (SHRINK R 0.111)
   (XHEIGHT R 0.43)
   (QUAD R 1.0)
   (EXTRASPACE R 0.111)
   )
(LIGTABLE
   (LABEL C A)
   (KRN C B R -0.05)
   (STOP)
   (LABEL C a)
   (LIG C a C B)
   (STOP)
   )
(CHARACTER C A
   (CHARWD R 0.75)
   (CHARHT R 0.68)
   )
(CHARACTER C B
   (CHARWD R 0.7)
   (CHARHT R 0.68)
   (CHARIC R 0.02)
   )
(CHARACTER C a
   (CHARWD R 0.5)
   (CHARHT R 0.43)
   (CHARDP R 0.01)
   )
EOF
pltotf pltotf.pl pltotf.tfm >/dev/null
cat > vptovf.vpl <<'EOF'
(VTITLE fillyfoal virtual font)
(FAMILY FILLYFOALV)
(DESIGNSIZE R 10.0)
(CHECKSUM O 7654321)
(MAPFONT D 0
   (FONTNAME pltotf)
   (FONTCHECKSUM O 12345670)
   (FONTAT R 1.0)
   (FONTDSIZE R 10.0)
   )
(CHARACTER C A
   (CHARWD R 0.75)
   (CHARHT R 0.68)
   (MAP (SETCHAR C A))
   )
(CHARACTER C B
   (CHARWD R 0.85)
   (CHARHT R 0.68)
   (MAP
      (SETCHAR C A)
      (SETRULE R 0.05 R 0.1)
      )
   )
EOF
vptovf vptovf.vpl vptovf.vf vptovf.tfm >/dev/null
mkdir -p "$out/tex-tfm" "$out/tex-vf"
cp pltotf.tfm "$out/tex-tfm/"
cp vptovf.vf "$out/tex-vf/"
cd /
rm -rf "$work"
