#!/bin/sh
# Writes the external PDF fixtures for the image and font filters:
#
#   gs-lzw.pdf        Ghostscript pdfwrite at PDF 1.1 (LZWDecode streams)
#   img2pdf-jpx.pdf   img2pdf of a JPEG 2000 file from OpenJPEG (JPXDecode)
#   pdftex-type1.pdf  pdfTeX with a Type 1 font of ours (/FontFile with
#                     Length1/2/3, subset by pdfTeX)
#   pdftex-jbig2.pdf  pdfTeX including a JBIG2 file of ours: pdfTeX splits
#                     it into the embedded organisation (/JBIG2Decode) and
#                     a /JBIG2Globals stream
#
# Run from an empty directory outside the repository and the home directory
# (e.g. /tmp/fixtures/pdf-filters) with page.ps copied there. Ghostscript
# 10.07.1, OpenJPEG 2.5, img2pdf (via uv), TeX Live's pdfTeX, t1asm,
# t1rawafm and afm2tfm. The JBIG2 segments and the font's glyphs are ours
# (no JBIG2 encoder is installed); the PDF files are the tools'. The pdfTeX
# files reproduce byte for byte; the Ghostscript and img2pdf ones differ in
# their dates (and IDs).
set -e
export SOURCE_DATE_EPOCH=1767225600 FORCE_SOURCE_DATE=1

# LZW: before PDF 1.2 there is no Flate, so pdfwrite falls back to LZW.
gs -q -dNOPAUSE -dBATCH -dSAFER -sDEVICE=pdfwrite -dCompatibilityLevel=1.1 \
    -sOutputFile=gs-lzw.pdf page.ps

# JPX: a 16x16 gradient, lossless JPEG 2000.
python3 -I - <<'EOF'
rows = bytes(v for y in range(16) for x in range(16) for v in (x * 16, y * 16, 128))
open("gradient.ppm", "wb").write(b"P6\n16 16\n255\n" + rows)
EOF
opj_compress -n 3 -i gradient.ppm -o gradient.jp2 >/dev/null
uv run -q --with img2pdf==0.6.1 img2pdf --creator fillyfoal --author fillyfoal \
    --title fillyfoal -o img2pdf-jpx.pdf gradient.jp2

# Type 1: three box-shaped glyphs, assembled by t1asm; metrics from the
# outlines (t1rawafm) and a TFM for pdfTeX (afm2tfm).
cat > fillyfoal.raw <<'EOF'
%!PS-AdobeFont-1.0: FillyfoalBox 001.000
%%Title: FillyfoalBox
11 dict begin
/FontInfo 6 dict dup begin
/version (001.000) readonly def
/Notice (Test fixture, no rights reserved) readonly def
/FullName (Fillyfoal Box) readonly def
/FamilyName (Fillyfoal Box) readonly def
/Weight (Regular) readonly def
/ItalicAngle 0 def
end readonly def
/FontName /FillyfoalBox def
/PaintType 0 def
/FontType 1 def
/FontMatrix [0.001 0 0 0.001 0 0] readonly def
/Encoding StandardEncoding def
/FontBBox {0 0 600 700} readonly def
currentdict end
currentfile eexec
dup /Private 8 dict dup begin
/RD{string currentfile exch readstring pop}executeonly def
/ND{noaccess def}executeonly def
/NP{noaccess put}executeonly def
/BlueValues [0 0 700 700] def
/MinFeature{16 16} def
/password 5839 def
/lenIV 4 def
/Subrs 4 array
dup 0 {
	3 0 callothersubr
	pop
	pop
	setcurrentpoint
	return
	} NP
dup 1 {
	0 1 callothersubr
	return
	} NP
dup 2 {
	0 2 callothersubr
	return
	} NP
dup 3 {
	return
	} NP
ND
2 index /CharStrings 4 dict dup begin
/.notdef {
	0 500 hsbw
	endchar
	} ND
/A {
	0 600 hsbw
	50 0 rmoveto
	500 0 rlineto
	0 700 rlineto
	-500 0 rlineto
	closepath
	endchar
	} ND
/B {
	0 500 hsbw
	50 0 rmoveto
	400 0 rlineto
	-200 700 rlineto
	closepath
	endchar
	} ND
/C {
	0 400 hsbw
	50 0 rmoveto
	300 0 rlineto
	0 350 rlineto
	-300 0 rlineto
	closepath
	endchar
	} ND
end
end
readonly put
noaccess put
dup /FontName get exch definefont pop
mark currentfile closefile
cleartomark
EOF
t1asm -b fillyfoal.raw fillyfoal.pfb
t1rawafm fillyfoal.pfb > fillyfoal.afm
afm2tfm fillyfoal.afm >/dev/null

# JBIG2: a file (sequential organisation) with a global symbol dictionary
# (page 0), page information, a text region referring to the dictionary,
# end of page and end of file. The region data is filler.
python3 -I - <<'EOF'
import struct

def seg(number, kind, page, data, refs=()):
    head = struct.pack(">IB", number, kind) + bytes([len(refs) << 5]) + bytes(refs)
    return head + bytes([page]) + struct.pack(">I", len(data)) + data

symbols = struct.pack(">HbbbbbbbbII", 0x0000, 3, -1, -3, -1, 2, -2, -2, -2, 1, 1) + bytes(8)
info = struct.pack(">IIIIBH", 64, 32, 2835, 2835, 0, 0)
text = struct.pack(">IIIIB", 64, 32, 0, 0, 0) + struct.pack(">HI", 0, 1) + bytes(8)
data = b"\x97JB2\r\n\x1a\n" + bytes([0x01]) + struct.pack(">I", 1)
data += seg(0, 0, 0, symbols)
data += seg(1, 48, 1, info)
data += seg(2, 6, 1, text, refs=(0,))
data += seg(3, 49, 1, b"")
data += seg(4, 51, 0, b"")
open("boxes.jb2", "wb").write(data)
EOF

cat > type1.tex <<'EOF'
\pdfoutput=1
\pdfcompresslevel=9
\pdfobjcompresslevel=0
\pdfinfoomitdate=1
\pdftrailerid{}
\pdfsuppressptexinfo=-1
\pdfinfo{/Title (fillyfoal) /Author (fillyfoal) /Creator (fillyfoal)}
\pdfmapline{=fillyfoal FillyfoalBox <fillyfoal.pfb}
\nopagenumbers
\pdfpagewidth=200pt \pdfpageheight=100pt
\hsize=180pt \vsize=80pt \hoffset=-1in \voffset=-1in
\font\f=fillyfoal at 24pt
\f ABC CAB
\bye
EOF
cat > jbig2.tex <<'EOF'
\pdfoutput=1
\pdfcompresslevel=9
\pdfobjcompresslevel=0
\pdfinfoomitdate=1
\pdftrailerid{}
\pdfsuppressptexinfo=-1
\pdfinfo{/Title (fillyfoal) /Author (fillyfoal) /Creator (fillyfoal)}
\nopagenumbers
\pdfpagewidth=200pt \pdfpageheight=100pt
\hsize=180pt \vsize=80pt \hoffset=-1in \voffset=-1in
\pdfximage{boxes.jb2}\pdfrefximage\pdflastximage
\bye
EOF
pdftex -interaction=batchmode type1.tex >/dev/null
pdftex -interaction=batchmode jbig2.tex >/dev/null
mv type1.pdf pdftex-type1.pdf
mv jbig2.pdf pdftex-jbig2.pdf
