#!/bin/sh
# Writes the external PDF fixtures. Run from an empty directory outside the
# repository and the home directory (e.g. /tmp/fixtures/pdf-gen), with page.ps
# and make.py copied there. Ghostscript 10.07.1.
set -e
gs -q -dNOPAUSE -dBATCH -dSAFER -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 \
    -dPDFSETTINGS=/prepress -dAutoFilterColorImages=false -dColorImageFilter=/DCTEncode \
    -dDownsampleColorImages=false -sOutputFile=gs-1.4.pdf page.ps
gs -q -dNOPAUSE -dBATCH -dSAFER -sDEVICE=pdfwrite -dCompatibilityLevel=1.7 \
    -dPDFSETTINGS=/prepress -dWriteObjStms=true -dWriteXRefStm=true \
    -sOutputFile=gs-1.7.pdf page.ps
uv run --with pikepdf==10.16.0 --with pypdf==6.20.0 --with reportlab==5.0.1 \
    --with pillow==12.3.0 --with pyhanko==0.37.0 --with fonttools python -I make.py
