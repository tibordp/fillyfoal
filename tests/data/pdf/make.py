"""Writes the external PDF fixtures made with Python libraries.

Run from an empty directory outside the repository, after make.sh has made
gs-1.4.pdf (Ghostscript pdfwrite) there:

    uv run --with pikepdf==10.16.0 --with pypdf==6.20.0 --with reportlab==5.0.1 \
        --with pillow==12.3.0 --with pyhanko==0.37.0 --with fonttools python -I make.py

Every document names "fillyfoal" as its title, author and creator; nothing
here reads the machine's user or host names.
"""

import io
import subprocess

import pikepdf
import pypdf
from PIL import Image, ImageCms
from reportlab import rl_config

rl_config.invariant = 1  # fixed dates and document IDs
from reportlab.lib.colors import blue, lightgrey  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402
from reportlab.pdfbase.ttfonts import TTFont  # noqa: E402
from reportlab.pdfgen import canvas  # noqa: E402
from reportlab.lib.utils import ImageReader  # noqa: E402


def neutral_info(c):
    c.setTitle("fillyfoal")
    c.setAuthor("fillyfoal")
    c.setCreator("fillyfoal")
    c.setSubject("fillyfoal fixture")


def tiny_font():
    """A small TrueType font of our own (every glyph a box), so the embedded
    subset is small and ours."""
    from fontTools.fontBuilder import FontBuilder
    from fontTools.pens.ttGlyphPen import TTGlyphPen

    letters = "abcdefghijklmnopqrstuvwxyz"
    names = [".notdef", "space"] + list(letters)
    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder(names)
    cmap = {ord(" "): "space"}
    cmap.update({ord(c): c for c in letters})
    fb.setupCharacterMap(cmap)
    glyphs = {}
    for i, name in enumerate(names):
        pen = TTGlyphPen(None)
        if name != "space":
            w = 300 + 10 * i
            pen.moveTo((50, 0)); pen.lineTo((50, 700)); pen.lineTo((w, 700))
            pen.lineTo((w, 0)); pen.closePath()
        glyphs[name] = pen.glyph()
    fb.setupGlyf(glyphs)
    fb.setupHorizontalMetrics({n: (400 + 10 * i, 50) for i, n in enumerate(names)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupNameTable({"familyName": "FillyfoalTest", "styleName": "Regular"})
    fb.setupOS2(sTypoAscender=800, usWinAscent=800, usWinDescent=200)
    fb.setupPost()
    fb.save("FillyfoalTest.ttf")


def reportlab_form():
    """A form with text and check box fields, a link annotation, outlines,
    an embedded TrueType subset (our own box font) and a JPEG image."""
    tiny_font()
    pdfmetrics.registerFont(TTFont("FillyfoalTest", "FillyfoalTest.ttf"))
    jpeg = io.BytesIO()
    img = Image.new("RGB", (16, 16))
    img.putdata([(x * 16, y * 16, 128) for y in range(16) for x in range(16)])
    img.save(jpeg, "JPEG", quality=60)
    jpeg.seek(0)
    c = canvas.Canvas("reportlab-form.pdf", pagesize=(300, 300), pageCompression=1)
    neutral_info(c)
    c.bookmarkPage("p1")
    c.addOutlineEntry("First page", "p1", level=0)
    c.addOutlineEntry("Form", "p1", level=1)
    c.setFont("FillyfoalTest", 14)
    c.drawString(20, 270, "fillyfoal form")
    c.drawImage(ImageReader(jpeg), 220, 220, 48, 48)
    form = c.acroForm
    form.textfield(name="name", tooltip="Name", x=20, y=200, width=180, height=20,
                   value="fillyfoal", fillColor=lightgrey, borderColor=blue)
    form.checkbox(name="agree", tooltip="Agree", x=20, y=160, size=16, checked=True)
    c.linkURL("https://example.com/", (20, 120, 160, 140), relative=0)
    c.drawString(20, 125, "a link")
    c.showPage()
    c.bookmarkPage("p2")
    c.addOutlineEntry("Second page", "p2", level=0)
    c.setFont("FillyfoalTest", 10)
    c.drawString(20, 270, "page two")
    c.showPage()
    c.save()


def qpdf_variants():
    src = pikepdf.open("gs-1.4.pdf")
    # Linearized (classic cross-reference tables, a hint stream).
    src.save("qpdf-linearized.pdf", linearize=True, deterministic_id=True)
    # Object streams, an attached file and an ICC output intent.
    pdf = pikepdf.open("gs-1.4.pdf")
    icc = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    profile = pikepdf.Stream(pdf, icc)
    profile.N = 3
    pdf.Root.OutputIntents = pikepdf.Array([pikepdf.Dictionary(
        Type=pikepdf.Name.OutputIntent, S=pikepdf.Name.GTS_PDFA1,
        OutputConditionIdentifier="sRGB", DestOutputProfile=profile)])
    page = pdf.pages[1]
    page.Resources.ColorSpace = pikepdf.Dictionary(
        CS0=pikepdf.Array([pikepdf.Name.ICCBased, profile]))
    spec = pikepdf.AttachedFileSpec(pdf, b"fillyfoal attachment\n", filename="note.txt",
                                    mime_type="text/plain")
    pdf.attachments["note.txt"] = spec
    pdf.save("qpdf-objstm.pdf", object_stream_mode=pikepdf.ObjectStreamMode.generate,
             deterministic_id=True)
    # Encrypted: AES-128 (R4, crypt filters) and AES-256 (R6, object streams).
    src.save("qpdf-aes128-r4.pdf", encryption=pikepdf.Encryption(
        user="", owner="fillyfoal", R=4, aes=True,
        allow=pikepdf.Permissions(extract=False, modify_annotation=False)))
    src.save("qpdf-aes256-r6.pdf", encryption=pikepdf.Encryption(
        user="", owner="fillyfoal", R=6, allow=pikepdf.Permissions(print_highres=False)),
        object_stream_mode=pikepdf.ObjectStreamMode.generate)


def pypdf_incremental():
    """Two incremental updates appended to the Ghostscript file."""
    data = open("gs-1.4.pdf", "rb").read()
    for title in ["fillyfoal, revised", "fillyfoal, revised twice"]:
        writer = pypdf.PdfWriter(io.BytesIO(data), incremental=True)
        writer.add_metadata({"/Title": title})
        out = io.BytesIO()
        writer.write(out)
        data = out.getvalue()
    open("pypdf-incremental.pdf", "wb").write(data)


def pyhanko_signed():
    """reportlab-form.pdf signed with a throwaway self-signed P-256 key."""
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "key.pem",
                    "-out", "cert.pem", "-days", "3650", "-subj", "/CN=fillyfoal test"],
                   check=True, capture_output=True)
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers

    signer = signers.SimpleSigner.load("key.pem", "cert.pem")
    with open("reportlab-form.pdf", "rb") as f:
        w = IncrementalPdfFileWriter(f)
        meta = signers.PdfSignatureMetadata(field_name="Signature1", name="fillyfoal test")
        with open("pyhanko-signed.pdf", "wb") as out:
            signers.PdfSigner(meta, signer=signer).sign_pdf(w, output=out)


if __name__ == "__main__":
    reportlab_form()
    qpdf_variants()
    pypdf_incremental()
    pyhanko_signed()
