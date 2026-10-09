"""Writes tests/fixtures/synthetic/pdf/hybrid-filters.pdf: a hand-assembled
PDF for structures the external fixtures lack.

- a hybrid-reference file: a classic table whose trailer has /XRefStm, a
  cross-reference stream for an object stream and the object in it;
- a free list with generation numbers (object 10 freed, object 11 reused at
  generation 2);
- filter chains: ASCIIHex + RunLength content, ASCII85 + Flate with a PNG
  predictor image, an LZW ToUnicode CMap, CCITT fax parameters;
- a Type 1 font program (/FontFile, Length1/2/3) with an eexec-encrypted
  private part.

    python3 tests/data/pdf/synthetic.py tests/fixtures/synthetic/pdf/hybrid-filters.pdf
"""

import base64
import sys
import zlib


def lzw(data):
    """LZWDecode encoding (early change 1, 9 to 12 bits)."""
    out, acc, nbits = bytearray(), 0, 0
    width = 9

    def emit(code):
        nonlocal acc, nbits
        acc = acc << width | code
        nbits += width
        while nbits >= 8:
            nbits -= 8
            out.append(acc >> nbits & 0xFF)

    table = {bytes([i]): i for i in range(256)}
    next_code = 258
    emit(256)
    w = b""
    for b in data:
        wc = w + bytes([b])
        if wc in table:
            w = wc
            continue
        emit(table[w])
        table[wc] = next_code
        next_code += 1
        if next_code + 1 > (1 << width) and width < 12:
            width += 1
        w = bytes([b])
    if w:
        emit(table[w])
        next_code += 1
        if next_code + 1 > (1 << width) and width < 12:
            width += 1
    emit(257)
    if nbits:
        out.append(acc << (8 - nbits) & 0xFF)
    return bytes(out)


def run_length(data):
    out = bytearray()
    i = 0
    while i < len(data):
        j = i
        while j < len(data) and j - i < 128 and data[j] == data[i]:
            j += 1
        if j - i >= 3:
            out += bytes([257 - (j - i), data[i]])
            i = j
        else:
            k = i
            while k < len(data) and k - i < 128 and not (
                k + 2 < len(data) and data[k] == data[k + 1] == data[k + 2]
            ):
                k += 1
            out += bytes([k - i - 1]) + data[i:k]
            i = k
    return bytes(out + b"\x80")


def eexec(plain, r=55665):
    out = bytearray()
    for p in plain:
        c = p ^ (r >> 8)
        r = ((c + r) * 52845 + 22719) & 0xFFFF
        out.append(c)
    return bytes(out)


def png_up(rows):
    out, prev = bytearray(), bytes(len(rows[0]))
    for row in rows:
        out += b"\x02" + bytes((a - b) & 0xFF for a, b in zip(row, prev))
        prev = row
    return bytes(out)


def stream(dict_body, data):
    return b"<< " + dict_body + b" /Length %d >>\nstream\n" % len(data) + data + b"\nendstream"


def main(path):
    content = b"BT /F1 12 Tf 20 60 Td (fillyfoal) Tj ET\nq 32 0 0 32 120 40 cm /Im1 Do Q\n"
    hexed = run_length(content).hex().encode() + b">"
    cmap = (b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
            b"/CMapName /Fillyfoal-UCS def\n/CMapType 2 def\n"
            b"1 begincodespacerange\n<00> <FF>\nendcodespacerange\n"
            b"2 beginbfchar\n<66> <0066>\n<6C> <006C>\nendbfchar\n"
            b"1 beginbfrange\n<61> <7A> <0061>\nendbfrange\n"
            b"endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n")
    clear = (b"%!PS-AdobeFont-1.0: Fillyfoal-Test 001.000\n"
             b"10 dict begin\n/FontName /Fillyfoal-Test def\n/FontType 1 def\n"
             b"/FontMatrix [0.001 0 0 0.001 0 0] readonly def\n"
             b"/Encoding StandardEncoding def\n/FontBBox {0 0 500 700} readonly def\n"
             b"currentdict end\ncurrentfile eexec\n")
    private = (b"\x00\x00\x00\x00dup /Private 8 dict dup begin\n/RD{string currentfile exch readstring pop}executeonly def\n"
               b"/ND{noaccess def}executeonly def\n/NP{noaccess put}executeonly def\n"
               b"/lenIV 4 def\n/MinFeature{16 16} def\n/password 5839 def\n"
               b"/Subrs 0 array\nND\n2 index /CharStrings 1 dict dup begin\n"
               b"/.notdef 9 RD \x00\x00\x00\x00\x8b\xf7\x8a\x0d\x0e ND\nend\nend\nreaddonly put\nnoaccess put\n"
               b"dup /FontName get exch definefont pop\nmark currentfile closefile\n")
    encrypted = eexec(private)
    trailer = b"0" * 64 + b"\ncleartomark\n"
    rows = [b"".join(bytes([x * 60, y * 60, 128]) for x in range(4)) for y in range(4)]
    image = base64.a85encode(zlib.compress(png_up(rows)), adobe=False) + b"~>"

    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] /Contents 4 0 R "
           b"/Resources << /Font << /F1 5 0 R >> /XObject << /Im1 8 0 R /Im2 9 0 R >> >> >>",
        4: stream(b"/Filter [/ASCIIHexDecode /RunLengthDecode]", hexed),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Fillyfoal-Test /FirstChar 97 /LastChar 122 "
           b"/FontDescriptor 6 0 R /ToUnicode 15 0 R >>",
        6: b"<< /Type /FontDescriptor /FontName /Fillyfoal-Test /Flags 32 /FontBBox [0 0 500 700] "
           b"/ItalicAngle 0 /Ascent 700 /Descent 0 /CapHeight 700 /StemV 80 /FontFile 7 0 R >>",
        7: stream(b"/Length1 %d /Length2 %d /Length3 %d" % (len(clear), len(encrypted), len(trailer)),
                  clear + encrypted + trailer),
        8: stream(b"/Type /XObject /Subtype /Image /Width 4 /Height 4 /ColorSpace /DeviceRGB "
                  b"/BitsPerComponent 8 /Filter [/ASCII85Decode /FlateDecode] "
                  b"/DecodeParms [null << /Predictor 12 /Colors 3 /Columns 4 >>]", image),
        9: stream(b"/Type /XObject /Subtype /Image /Width 8 /Height 2 /ImageMask true "
                  b"/Filter /CCITTFaxDecode /DecodeParms << /K -1 /Columns 8 /Rows 2 /BlackIs1 true >>",
                  b"\x26\xa0\x00\x10\x01"),
        11: b"(reused at generation 2)",
        15: stream(b"/Filter /LZWDecode", lzw(cmap)),
    }
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objects):
        gen = 2 if num == 11 else 0
        offsets[num] = len(out)
        out += b"%d %d obj\n" % (num, gen) + objects[num] + b"\nendobj\n"
    # An object stream with object 13, and the cross-reference stream for
    # it (found only through /XRefStm).
    inner = b"(compressed object 13)"
    header = b"13 0 "
    objstm = stream(b"/Type /ObjStm /N 1 /First %d /Filter /FlateDecode" % len(header),
                    zlib.compress(header + inner))
    # Flate here applies to the whole data (header and object).
    offsets[12] = len(out)
    out += b"12 0 obj\n" + objstm + b"\nendobj\n"
    offsets[14] = len(out)
    rows = bytes([1]) + offsets[12].to_bytes(2, "big") + b"\x00" + bytes([2, 0, 12, 0])
    out += b"14 0 obj\n" + stream(b"/Type /XRef /Size 16 /W [1 2 1] /Index [12 2]", rows) + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 12\n"
    # Free list: 0 -> 10 -> 0.
    for num in range(12):
        if num == 0:
            out += b"0000000010 65535 f\r\n"
        elif num == 10:
            out += b"0000000000 00001 f\r\n"
        else:
            out += b"%010d %05d n\r\n" % (offsets[num], 2 if num == 11 else 0)
    out += b"15 1\n%010d 00000 n\r\n" % offsets[15]
    out += (b"trailer\n<< /Size 16 /Root 1 0 R /XRefStm %d /ID [<00112233445566778899aabbccddeeff>"
            b"<00112233445566778899aabbccddeeff>] >>\nstartxref\n%d\n%%%%EOF\n" % (offsets[14], xref))
    open(path, "wb").write(bytes(out))


if __name__ == "__main__":
    main(sys.argv[1])
