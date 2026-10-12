"""Writes the synthetic Adobe Illustrator fixtures (no Illustrator runs
here):

- ai/compat.ai: a "PDF compatible" .ai as Illustrator 9 and later write
  it: a one-page PDF whose XMP packet uses the illustrator: namespace and
  whose page carries /PieceInfo /Illustrator << /LastModified /Private >>,
  /Private holding /AIMetaData (the PostScript header text) and an
  /AIPrivateData1 stream ("%AI12_CompressedData" and a zlib stream), with
  the version and block-count keys Illustrator writes. The native data is a
  placeholder.
- ai/compat-zstd.ai: the same as Illustrator 2020 and later write it: the
  native data is "%AI24_ZStandard_Data" and a Zstandard frame, split over
  /AIPrivateData1 and /AIPrivateData2 (/NumBlock 2).
- ai-ps/legacy.ai: a PostScript-based .ai (Illustrator 8 and earlier): an
  EPS whose DSC header names Adobe Illustrator as creator and interleaves
  Illustrator's %AIn_ comments, ending in %%EndComments; prolog, setup, one
  page of path operators and a trailer. Placeholder artwork.

    uv run --with zstandard python tests/data/ai/make.py <fixtures dir>
"""

import os
import sys
import zlib

import zstandard

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
artwork = (
    b"%!PS-Adobe-3.0\r%%Creator: Adobe Illustrator(R) 24.0\r%AI9_DataStream\r"
    b"fillyfoal placeholder for Illustrator's native artwork\r"
)
content = b"0 0 1 rg 20 20 160 60 re f\n"


def compat(name, version, private, blocks):
    """A PDF-compatible .ai whose /Private holds `private` split into
    `blocks` AIPrivateData streams."""
    meta = (
        b"%%!PS-Adobe-3.0 \r%%%%Creator: Adobe Illustrator(R) %d.0\r"
        b"%%%%AI8_CreatorVersion: %d.0.0\r%%%%For: (fillyfoal) ()\r%%%%Title: (%s)\r"
        b"%%%%CreationDate: 1/1/2026 12:00 AM\r%%%%BoundingBox: 0 0 200 100\r"
        % (version, version, name.encode())
    )
    step = -(-len(private) // blocks)
    pieces = [private[i : i + step] for i in range(0, len(private), step)]
    assert len(pieces) == blocks
    first = 9
    refs = b" ".join(b"/AIPrivateData%d %d 0 R" % (i + 1, first + i) for i in range(blocks))
    objects = [
        b"<< /Type /Catalog /Pages 3 0 R /Metadata 2 0 R >>",
        b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(xmp) + xmp + b"\nendstream",
        b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 3 0 R /MediaBox [0 0 200 100] /Contents 5 0 R"
        b" /PieceInfo << /Illustrator 6 0 R >> /LastModified (D:20260101000000Z) >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /LastModified (D:20260101000000Z) /Private 7 0 R >>",
        b"<< /AIMetaData 8 0 R " + refs + b" /ContainerVersion 12"
        b" /CreatorVersion %d /NumBlock %d /RoundtripStreamType 1 /RoundtripVersion %d >>"
        % (version, blocks, version),
        b"<< /Length %d >>\nstream\n" % len(meta) + meta + b"\nendstream",
    ] + [b"<< /Length %d >>\nstream\n" % len(p) + p + b"\nendstream" for p in pieces]
    pdf = bytearray(b"%PDF-1.6\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(pdf)
    pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for o in offsets:
        pdf += b"%010d 00000 n \n" % o
    pdf += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    with open(path("ai", name), "wb") as f:
        f.write(pdf)


# Illustrator CS to 2019: "%AI12_CompressedData" and a zlib stream.
compat("compat.ai", 24, b"%AI12_CompressedData" + zlib.compress(artwork, 9), 1)
# Illustrator 2020 and later: "%AI24_ZStandard_Data" and a Zstandard
# frame, here split over two AIPrivateData streams (Illustrator splits the
# data into blocks of up to 64 KiB).
compat(
    "compat-zstd.ai",
    26,
    b"%AI24_ZStandard_Data" + zstandard.ZstdCompressor(level=19).compress(artwork * 4),
    2,
)

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
