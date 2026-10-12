"""Writes the synthetic Adobe Illustrator fixtures (no Illustrator runs
here):

- ai/compat.ai: a "PDF compatible" .ai as Illustrator 9 and later write
  it: a one-page PDF whose XMP packet uses the illustrator: namespace and
  whose page carries /PieceInfo /Illustrator << /LastModified /Private >>,
  /Private holding /AIMetaData (the PostScript header text) and an
  /AIPrivateData1 stream ("%AI12_CompressedData" and a zlib stream), with
  the version and block-count keys Illustrator writes. The native data is a
  placeholder.
- ai-ps/legacy.ai: a PostScript-based .ai (Illustrator 8 and earlier): an
  EPS whose DSC header names Adobe Illustrator as creator and interleaves
  Illustrator's %AIn_ comments, ending in %%EndComments; prolog, setup, one
  page of path operators and a trailer. Placeholder artwork.

    python tests/data/ai/make.py <fixtures dir>
"""

import os
import sys
import zlib

out = sys.argv[1]


def path(*parts):
    p = os.path.join(out, *parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


xmp = b"""<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:illustrator="http://ns.adobe.com/illustrator/1.0/">
   <xmp:CreatorTool>Adobe Illustrator 24.0 (fillyfoal placeholder)</xmp:CreatorTool>
   <illustrator:Type>Document</illustrator:Type>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""
meta = (
    b"%!PS-Adobe-3.0 \r%%Creator: Adobe Illustrator(R) 24.0\r"
    b"%%AI8_CreatorVersion: 24.0.0\r%%For: (fillyfoal) ()\r%%Title: (compat.ai)\r"
    b"%%CreationDate: 1/1/2026 12:00 AM\r%%BoundingBox: 0 0 200 100\r"
)
private = b"%AI12_CompressedData" + zlib.compress(
    b"%!PS-Adobe-3.0\r%%Creator: Adobe Illustrator(R) 24.0\r%AI9_DataStream\r"
    b"fillyfoal placeholder for Illustrator's native artwork\r",
    9,
)
content = b"0 0 1 rg 20 20 160 60 re f\n"

objects = [
    b"<< /Type /Catalog /Pages 3 0 R /Metadata 2 0 R >>",
    b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(xmp) + xmp + b"\nendstream",
    b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 3 0 R /MediaBox [0 0 200 100] /Contents 5 0 R"
    b" /PieceInfo << /Illustrator 6 0 R >> /LastModified (D:20260101000000Z) >>",
    b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    b"<< /LastModified (D:20260101000000Z) /Private 7 0 R >>",
    b"<< /AIMetaData 8 0 R /AIPrivateData1 9 0 R /ContainerVersion 12"
    b" /CreatorVersion 24 /NumBlock 1 /RoundtripStreamType 1 /RoundtripVersion 24 >>",
    b"<< /Length %d >>\nstream\n" % len(meta) + meta + b"\nendstream",
    b"<< /Length %d >>\nstream\n" % len(private) + private + b"\nendstream",
]
pdf = bytearray(b"%PDF-1.6\n%\xe2\xe3\xcf\xd3\n")
offsets = []
for i, body in enumerate(objects, 1):
    offsets.append(len(pdf))
    pdf += b"%d 0 obj\n" % i + body + b"\nendobj\n"
xref = len(pdf)
pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
for o in offsets:
    pdf += b"%010d 00000 n \n" % o
pdf += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
with open(path("ai", "compat.ai"), "wb") as f:
    f.write(pdf)

eps = b"""%!PS-Adobe-3.0 EPSF-3.0
%%Creator: Adobe Illustrator(R) 8.0
%%AI8_CreatorVersion: 8.0
%%For: (fillyfoal) ()
%%Title: (legacy.ai)
%%CreationDate: (1/1/2026) (12:00 AM)
%%BoundingBox: 0 0 200 100
%%HiResBoundingBox: 0 0 200 100
%%DocumentProcessColors: Cyan Magenta
%AI5_FileFormat 4.0
%AI3_ColorUsage: Color
%AI3_TemplateBox: 100.5 50.5 100.5 50.5
%AI3_TileBox: 0 0 200 100
%AI3_DocumentPreview: None
%AI5_ArtSize: 200 100
%AI5_RulerUnits: 2
%AI5_NumLayers: 1
%%EndComments
%%BeginProlog
/fillyfoal-placeholder-procset 10 dict def
%%EndProlog
%%BeginSetup
%AI5_BeginPalette
%AI5_EndPalette
%%EndSetup
%AI5_BeginLayer
1 1 1 1 0 0 0 79 128 255 Lb
(Layer 1) Ln
0 A
1 0 0 0 k
20 20 m
180 20 L
180 80 L
20 80 L
20 20 L
f
LB
%AI5_EndLayer--
%%PageTrailer
%%Trailer
%%EOF
"""
with open(path("ai-ps", "legacy.ai"), "wb") as f:
    f.write(eps)
