#!/usr/bin/env python3
"""Writes the synthetic OneNote fixtures:

    tests/fixtures/synthetic/onenote/Notes.one
    tests/fixtures/synthetic/onetoc2/Notebook.onetoc2

Layouts are from memory of [MS-ONESTORE] / [MS-ONE] (no OneNote writer was
available), so these files show what our reader expects, not what OneNote
writes. Notes.one is also read back with pyOneNote (an independent reader)
by `check_with_pyonenote` below:

    uv run --with pyOneNote python tests/data/onenote/make_onenote.py --check

Unverified guesses: the transaction-sentinel CRC (crc32 of the entries
here), crcName, the FileData3 object JCID (0x00080039), and the onetoc2
property IDs (placeholders: the real table-of-contents schema is unknown
to us).
"""

import os
import struct
import sys
import uuid
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))

ONE = uuid.UUID("{7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}")
TOC = uuid.UUID("{43FF2FA1-EFD9-4C76-9EE2-10EA5722765F}")
FORMAT = uuid.UUID("{109ADD3F-911B-49F5-A5D0-1791EDC8AED8}")
FDSO_HEADER = uuid.UUID("{BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}")
FDSO_FOOTER = uuid.UUID("{71FBA722-0F79-4A0B-BB13-899256426B24}")
LIST_MAGIC = 0xA4567AB1F5F7F4C4
LIST_FOOTER = 0x8BC215C38233BA4B
NIL64 = (0xFFFFFFFFFFFFFFFF, 0)


def g(n):
    """A deterministic GUID."""
    return uuid.UUID(int=(0x0F11_1F0A_0000_4000_8000_0000_0000_0000 | n))


def exguid(guid, n):
    return guid.bytes_le + struct.pack("<I", n)


NIL_EX = b"\0" * 20


def compact(index, n):
    return struct.pack("<I", (index << 8) | n)


def sis(text):
    """StringInStorageBuffer."""
    data = text.encode("utf-16-le")
    return struct.pack("<I", len(data) // 2) + data


def pad8(data):
    return data + b"\0" * (-len(data) % 8)


# --- property sets --------------------------------------------------------

T_NODATA, T_BOOL, T_U8, T_U16, T_U32, T_U64, T_BYTES = 1, 2, 3, 4, 5, 6, 7
T_OID, T_OIDS, T_OSID, T_OSIDS = 8, 9, 10, 11


class Props:
    def __init__(self):
        self.prids = []
        self.data = b""
        self.oids = []
        self.osids = []

    def add(self, prid, value=None):
        kind = (prid >> 26) & 0x1F
        if kind == T_BOOL:
            if value:
                prid |= 0x80000000
        elif kind == T_U8:
            self.data += struct.pack("<B", value)
        elif kind == T_U16:
            self.data += struct.pack("<H", value)
        elif kind == T_U32:
            self.data += value if isinstance(value, bytes) else struct.pack("<I", value)
        elif kind == T_U64:
            self.data += struct.pack("<Q", value)
        elif kind == T_BYTES:
            self.data += struct.pack("<I", len(value)) + value
        elif kind == T_OID:
            self.oids.append(value)
        elif kind == T_OIDS:
            self.data += struct.pack("<I", len(value))
            self.oids.extend(value)
        elif kind == T_OSIDS:
            self.data += struct.pack("<I", len(value))
            self.osids.extend(value)
        self.prids.append(prid)
        return self

    def build(self):
        out = b""
        if self.osids:
            out += struct.pack("<I", len(self.oids)) + b"".join(self.oids)
            out += struct.pack("<I", len(self.osids)) + b"".join(self.osids)
        else:
            out += struct.pack("<I", len(self.oids) | 0x80000000) + b"".join(self.oids)
        out += struct.pack("<H", len(self.prids))
        out += b"".join(struct.pack("<I", p) for p in self.prids)
        out += self.data
        return pad8(out)


def utf16z(text):
    return text.encode("utf-16-le")


# Property IDs ([MS-ONE], from memory; they match pyOneNote's table).
ContentChildNodes = 0x24001C1F
ElementChildNodes = 0x24001C20
RichEditTextUnicode = 0x1C001C22
TextExtendedAscii = 0x1C003498
RichEditTextLangID = 0x10001CFE
CachedTitleString = 0x1C001CF3
PageLevel = 0x14001DFF
CreationTimeStamp = 0x14001D09
LastModifiedTimeStamp = 0x18001D77
TopologyCreationTimeStamp = 0x18001C65
PageWidth = 0x14001C01
PictureContainer = 0x20001C3F
ImageFilename = 0x1C001DD7
ImageAltText = 0x1C001E58
EmbeddedFileContainer = 0x20001D9B
EmbeddedFileName = 0x1C001D9C
SourceFilepath = 0x1C001D9D
ParagraphStyle = 0x2000342C
Font = 0x1C001C0A
FontSize = 0x10001C0B
Bold = 0x08001C04
NotebookManagementEntityGuid = 0x1C001C30
ChildGraphSpaceElementNodes = 0x2C001D63
SchemaRevisionInOrderToRead = 0x14001D82
FontColor = 0x14001C0C

# JCIDs
jcidSectionNode = 0x00060007
jcidPageSeriesNode = 0x00060008
jcidPageNode = 0x0006000B
jcidOutlineNode = 0x0006000C
jcidOutlineElementNode = 0x0006000D
jcidRichTextOENode = 0x0006000E
jcidImageNode = 0x00060011
jcidTitleNode = 0x0006002C
jcidPageMetaData = 0x00020030
jcidSectionMetaData = 0x00020031
jcidEmbeddedFileNode = 0x00060035
jcidPageManifestNode = 0x00060037
jcidParagraphStyleObject = 0x0012004D
jcidFileData = 0x00080039  # guess

FILETIME = 133_700_000_000_000_000  # 2024-09-03
TIME32 = 1_400_000_000  # seconds since 1980


# --- file nodes -----------------------------------------------------------

def ref_bytes(ref, sf, cf):
    stp, cb = ref
    nil = ref == NIL64
    if sf == 0:
        s = struct.pack("<Q", stp)
    elif sf == 1:
        s = struct.pack("<I", 0xFFFFFFFF if nil else stp)
    elif sf == 2:
        assert nil or stp % 8 == 0
        s = struct.pack("<H", 0xFFFF if nil else stp // 8)
    else:
        assert nil or stp % 8 == 0
        s = struct.pack("<I", 0xFFFFFFFF if nil else stp // 8)
    if cf == 0:
        c = struct.pack("<I", cb)
    elif cf == 1:
        c = struct.pack("<Q", cb)
    elif cf == 2:
        assert cb % 8 == 0 and cb // 8 < 256
        c = struct.pack("<B", cb // 8)
    else:
        assert cb % 8 == 0
        c = struct.pack("<H", cb // 8)
    return s + c


def fnode(node_id, body=b"", ref=None, sf=1, cf=0, base=None):
    data = b""
    if ref is not None:
        data += ref_bytes(ref, sf, cf)
    data += body
    size = 4 + len(data)
    if base is None:
        base = 0 if ref is None else 1
    hdr = node_id | (size << 10) | (sf << 23) | (cf << 25) | (base << 27) | (1 << 31)
    return struct.pack("<I", hdr) + data


class Writer:
    def __init__(self):
        self.buf = bytearray(1024)
        self.next_list = 0x10
        self.counts = {}  # list id -> committed node count

    def alloc(self, data):
        self.buf += b"\0" * (-len(self.buf) % 8)
        off = len(self.buf)
        self.buf += data
        return (off, len(data))

    def fragment(self, list_id, seq, nodes, nxt=NIL64):
        data = struct.pack("<QII", LIST_MAGIC, list_id, seq) + b"".join(nodes)
        data += struct.pack("<QI", *nxt) + struct.pack("<Q", LIST_FOOTER)
        return self.alloc(data)

    def list(self, nodes, count=None, split=None):
        """Writes a file node list; `split` puts nodes[split:] in a second
        fragment, after a ChunkTerminatorFND."""
        list_id = self.next_list
        self.next_list += 1
        counted = [n for n in nodes]
        if split is None:
            ref = self.fragment(list_id, 0, nodes)
        else:
            second = self.fragment(list_id, 1, nodes[split:])
            ref = self.fragment(list_id, 0, nodes[:split] + [fnode(0xFF)], second)
        self.counts[list_id] = len(counted) if count is None else count
        return ref, list_id

    def propset(self, props):
        return self.alloc(props.build())

    def fdso(self, guid, data):
        body = FDSO_HEADER.bytes_le + struct.pack("<QIQ", len(data), 0, 0) + data
        body += b"\0" * (-len(body) % 8) + FDSO_FOOTER.bytes_le
        return self.alloc(body)


def decl(w, oid_index, n, jcid, props, cref=1):
    """ObjectDeclaration2RefCountFND (stpFormat 3, cbFormat 2)."""
    ref = w.propset(props)
    flags = (1 if props.oids else 0) | (2 if props.osids else 0)
    body = compact(oid_index, n) + struct.pack("<IBB", jcid, flags, cref)
    return fnode(0x0A4, body, ref, sf=3, cf=2)


def ro_decl(w, oid_index, n, jcid, props):
    """ReadOnlyObjectDeclaration2RefCountFND with the MD5 of the data."""
    import hashlib

    ref = w.propset(props)
    data = bytes(w.buf[ref[0]:ref[0] + ref[1]])
    body = compact(oid_index, n) + struct.pack("<IBB", jcid, 0, 1) + hashlib.md5(data).digest()
    return fnode(0x0C4, body, ref, sf=3, cf=2)


def file_decl(oid_index, n, guid, ext):
    body = compact(oid_index, n) + struct.pack("<IB", jcidFileData, 1)
    body += sis("<ifndf>{%s}" % str(guid).upper()) + sis(ext)
    return fnode(0x072, body)


def group(w, gid, table, decls):
    nodes = [fnode(0x0B4, gid), fnode(0x022)]
    nodes += [fnode(0x024, struct.pack("<I", i) + guid.bytes_le) for i, guid in table]
    nodes += [fnode(0x028), fnode(0x08C, exguid(g(0x5160), 1))]
    nodes += decls
    nodes.append(fnode(0x0B8))
    ref, _ = w.list(nodes)
    return fnode(0x0B0, gid, ref, base=2)


def oid(n):
    return compact(0, n)


def png_dot():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    raw = b"".join(b"\0" + b"\xff\x00\x00" * 2 for _ in range(2))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


MINUTES = b"Minutes\r\n- budget approved\r\n- hire two people\r\n"


def make_one():
    w = Writer()
    section, page1, page2 = g(0x5EC), g(0x9A61), g(0x9A62)
    og1, og2, og2b = g(0x0B1), g(0x0B2), g(0x0B3)
    f1, f2 = g(0xF11E1), g(0xF11E2)

    # Free space, reported by the free chunk list.
    free = w.alloc(b"\0" * 64)

    # File data store.
    fdso1 = w.fdso(f1, png_dot())
    fdso2 = w.fdso(f2, MINUTES)
    store_ref, _ = w.list([
        fnode(0x094, f1.bytes_le, fdso1, sf=0, cf=1),
        fnode(0x094, f2.bytes_le, fdso2, sf=0, cf=1),
    ])

    def text(oidn, s, ascii_=False, style=None):
        p = Props()
        if ascii_:
            p.add(TextExtendedAscii, s.encode("cp1252"))
        else:
            p.add(RichEditTextUnicode, utf16z(s))
        p.add(RichEditTextLangID, 0x0409)
        if style is not None:
            p.add(ParagraphStyle, oid(style))
        return decl(w, 0, oidn, jcidRichTextOENode, p)

    def oe(oidn, children):
        return decl(w, 0, oidn, jcidOutlineElementNode,
                    Props().add(ContentChildNodes, [oid(c) for c in children]))

    def elements(oidn, jcid, children, extra=()):
        p = Props().add(ElementChildNodes, [oid(c) for c in children])
        for prid, v in extra:
            p.add(prid, v)
        return decl(w, 0, oidn, jcid, p)

    # Page 1: "Shopping list" with two paragraphs and an image.
    style = Props().add(Font, utf16z("Calibri")).add(FontSize, 22).add(Bold, True).add(FontColor, 0x000000FF)
    p1 = [
        decl(w, 0, 1, jcidPageManifestNode,
             Props().add(ContentChildNodes, [oid(2)]).add(TopologyCreationTimeStamp, FILETIME)),
        elements(2, jcidPageNode, [3, 5], [(PageWidth, struct.pack("<f", 17.0))]),
        elements(3, jcidTitleNode, [10]),
        elements(10, jcidOutlineNode, [11]),
        oe(11, [12]),
        text(12, "Shopping list"),
        elements(5, jcidOutlineNode, [6, 7, 8]),
        oe(6, [20]),
        oe(7, [21]),
        oe(8, [22]),
        text(20, "Milk \u2014 2 litres", style=50),
        text(21, "Bread (wholegrain) \u2013 1 loaf", ascii_=True),
        decl(w, 0, 22, jcidImageNode,
             Props().add(PictureContainer, oid(30)).add(ImageFilename, utf16z("dot.png"))
             .add(ImageAltText, utf16z("a red dot"))),
        file_decl(0, 30, f1, ".png"),
        ro_decl(w, 0, 50, jcidParagraphStyleObject, style),
        decl(w, 0, 40, jcidPageMetaData,
             Props().add(CachedTitleString, utf16z("Shopping list")).add(PageLevel, 1)
             .add(CreationTimeStamp, TIME32).add(LastModifiedTimeStamp, FILETIME + 36_000_000_000)),
    ]
    rid1 = g(0x1D01)
    p1_group = group(w, exguid(og1, 1), [(0, page1)], p1)
    overrides = struct.pack("<III", 1, 0, 0) + oid(20) + struct.pack("<B", 2)
    p1_revs, _ = w.list([
        fnode(0x014, exguid(page1, 1) + struct.pack("<I", 0)),
        fnode(0x01E, exguid(rid1, 1) + NIL_EX + struct.pack("<IH", 1, 0)),
        p1_group,
        fnode(0x084, overrides, NIL64),
        fnode(0x05A, exguid(page1, 1) + struct.pack("<I", 1)),
        fnode(0x05A, exguid(page1, 40) + struct.pack("<I", 2)),
        fnode(0x01C),
    ])

    # Page 2: "Meeting notes" (a subpage), an attachment, and a second
    # revision that depends on the first and changes its outline.
    p2a = [
        decl(w, 0, 1, jcidPageManifestNode, Props().add(ContentChildNodes, [oid(2)])),
        elements(2, jcidPageNode, [3, 5]),
        elements(3, jcidTitleNode, [10]),
        elements(10, jcidOutlineNode, [11]),
        oe(11, [12]),
        text(12, "Meeting notes"),
        elements(5, jcidOutlineNode, [6, 7]),
        oe(6, [20]),
        oe(7, [21]),
        text(20, "Agenda: budget"),
        decl(w, 0, 21, jcidEmbeddedFileNode,
             Props().add(EmbeddedFileContainer, oid(30)).add(EmbeddedFileName, utf16z("minutes.txt"))
             .add(SourceFilepath, utf16z("C:\\Users\\me\\minutes.txt"))),
        file_decl(0, 30, f2, ".txt"),
        decl(w, 0, 40, jcidPageMetaData,
             Props().add(CachedTitleString, utf16z("Meeting notes")).add(PageLevel, 2)),
    ]
    p2b = [
        elements(5, jcidOutlineNode, [6, 7, 8]),
        oe(8, [22]),
        text(20, "Agenda: budget, hiring"),
        text(22, "Action items: send the minutes"),
    ]
    rid2a, rid2b = g(0x2D01), g(0x2D02)
    g2a = group(w, exguid(og2, 1), [(0, page2)], p2a)
    g2b = group(w, exguid(og2b, 1), [(0, page2)], p2b)
    p2_nodes = [
        fnode(0x014, exguid(page2, 1) + struct.pack("<I", 0)),
        fnode(0x01E, exguid(rid2a, 1) + NIL_EX + struct.pack("<IH", 1, 0)),
        g2a,
        fnode(0x05A, exguid(page2, 1) + struct.pack("<I", 1)),
        fnode(0x05A, exguid(page2, 40) + struct.pack("<I", 2)),
        fnode(0x01C),
        fnode(0x01F, exguid(rid2b, 1) + exguid(rid2a, 1) + struct.pack("<IH", 1, 0) + NIL_EX),
        g2b,
        fnode(0x01C),
        fnode(0x05C, exguid(rid2b, 1) + struct.pack("<I", 1)),
    ]
    p2_revs, p2_list = w.list(p2_nodes)

    # The section: a page series listing both pages.
    sec = [
        elements(1, jcidSectionNode, [2],
                 [(NotebookManagementEntityGuid, g(0xE7).bytes_le)]),
        decl(w, 0, 2, jcidPageSeriesNode,
             Props().add(ChildGraphSpaceElementNodes, [compact(1, 1), compact(2, 1)])),
        decl(w, 0, 3, jcidSectionMetaData, Props().add(SchemaRevisionInOrderToRead, 0x2B)),
    ]
    sec_group = group(w, exguid(g(0x0B0), 1), [(0, section), (1, page1), (2, page2)], sec)
    sec_revs, _ = w.list([
        fnode(0x014, exguid(section, 1) + struct.pack("<I", 0)),
        fnode(0x01E, exguid(g(0x5D01), 1) + NIL_EX + struct.pack("<IH", 1, 0)),
        sec_group,
        fnode(0x05A, exguid(section, 1) + struct.pack("<I", 1)),
        fnode(0x05A, exguid(section, 3) + struct.pack("<I", 2)),
        fnode(0x01C),
    ])

    def manifest(gosid, revs):
        ref, _ = w.list([fnode(0x00C, exguid(gosid, 1)), fnode(0x010, b"", revs, base=2)])
        return fnode(0x008, exguid(gosid, 1), ref, base=2)

    root, root_id = w.list(
        [
            manifest(section, sec_revs),
            manifest(page1, p1_revs),
            manifest(page2, p2_revs),
            fnode(0x004, exguid(section, 1)),
            fnode(0x090, b"", store_ref, base=2),
        ],
        split=3,
    )

    # Hashed chunk list: one descriptor for the page 1 style object.
    style_ref = w.propset(style)
    import hashlib

    blob = bytes(w.buf[style_ref[0]:style_ref[0] + style_ref[1]])
    hashed, _ = w.list([fnode(0x0C2, hashlib.md5(blob).digest(), style_ref)])

    # Transaction log: the first transaction commits page 2 with one
    # revision, the second its second revision.
    first = dict(w.counts)
    first[p2_list] = 6
    tx = b""
    for counts in (first, w.counts):
        entries = b"".join(struct.pack("<II", k, v) for k, v in sorted(counts.items()))
        tx += entries + struct.pack("<II", 1, zlib.crc32(entries))
    log = w.alloc(tx + struct.pack("<QI", *NIL64))

    free_list = w.alloc(struct.pack("<I", 0) + struct.pack("<QI", *NIL64) + struct.pack("<QQ", *free))

    w.buf += b"\0" * (-len(w.buf) % 8)
    header = header_bytes(
        ONE, 0x2A, transactions=2, hashed=hashed, log=log, root=root, free=free_list,
        length=len(w.buf), free_space=free[1], name="Notes.one",
    )
    w.buf[0:1024] = header
    return bytes(w.buf)


def header_bytes(kind, ffv, transactions, hashed, log, root, free, length, free_space, name):
    zero32 = struct.pack("<II", 0, 0)
    nil32 = struct.pack("<II", 0xFFFFFFFF, 0)
    zero64x32 = struct.pack("<QI", 0, 0)

    def r(ref):
        return struct.pack("<QI", *ref)

    h = kind.bytes_le + g(0xF11E).bytes_le + b"\0" * 16 + FORMAT.bytes_le
    h += struct.pack("<IIII", ffv, ffv, ffv, ffv)
    h += zero32 + nil32 + struct.pack("<II", transactions, 0) + struct.pack("<Q", 0) + nil32
    h += struct.pack("<I", 0) + bytes([0, 0, 0, 0])
    h += b"\0" * 16 + struct.pack("<I", zlib.crc32(name.encode("utf-16-le") + b"\0\0"))
    h += r(hashed) + r(log) + r(root) + r(free)
    h += struct.pack("<QQ", length, free_space)
    h += g(0xFE5).bytes_le + struct.pack("<Q", 2) + g(0xDE11).bytes_le
    h += struct.pack("<I", 0) + zero64x32 + zero64x32
    h += struct.pack("<IIII", 0x3A4F, 0x3A4F, 0x3A4F, 0x3A4F)
    assert len(h) == 0x128, hex(len(h))
    return h + b"\0" * 728


def make_toc():
    """A table of contents in the older (onetoc2) node set: global ID table
    and object declarations directly in the revision manifest."""
    w = Writer()
    toc = g(0x70C)
    gid = g(0x70C1)
    Name = 0x1C001C99  # placeholder property, not a known ID

    def entry(n, name):
        p = Props().add(NotebookManagementEntityGuid, g(0xE000 + n).bytes_le).add(Name, utf16z(name))
        ref = w.propset(p)
        body = compact(0, n) + struct.pack("<H", 0x0001) + struct.pack("<I", 0) + struct.pack("<B", 1)
        return fnode(0x02D, body, ref)

    root_props = Props().add(ElementChildNodes, [oid(2), oid(3)])
    root_ref = w.propset(root_props)
    revised = Props().add(NotebookManagementEntityGuid, g(0xE002).bytes_le).add(Name, utf16z("Groceries"))
    revised_ref = w.propset(revised)
    revs, _ = w.list([
        fnode(0x014, exguid(toc, 1) + struct.pack("<I", 0)),
        fnode(0x01B, exguid(g(0x7D01), 1) + NIL_EX + struct.pack("<QIH", FILETIME, 1, 0)),
        fnode(0x021, b"\0"),
        fnode(0x024, struct.pack("<I", 0) + gid.bytes_le),
        fnode(0x028),
        fnode(0x02E, compact(0, 1) + struct.pack("<H", 0x0001) + struct.pack("<I", 1) + struct.pack("<I", 1), root_ref),
        entry(2, "Shopping"),
        entry(3, "Meetings"),
        fnode(0x042, compact(0, 2) + struct.pack("<II", 0, 1), revised_ref),
        fnode(0x059, compact(0, 1) + struct.pack("<I", 1)),
        fnode(0x01C),
    ])
    manifest, _ = w.list([fnode(0x00C, exguid(toc, 1)), fnode(0x010, b"", revs, base=2)])
    root, _ = w.list([fnode(0x008, exguid(toc, 1), manifest, base=2), fnode(0x004, exguid(toc, 1))])
    entries = b"".join(struct.pack("<II", k, v) for k, v in sorted(w.counts.items()))
    log = w.alloc(entries + struct.pack("<II", 1, zlib.crc32(entries)) + struct.pack("<QI", *NIL64))
    w.buf += b"\0" * (-len(w.buf) % 8)
    w.buf[0:1024] = header_bytes(
        TOC, 0x1B, transactions=1, hashed=(0, 0), log=log, root=root, free=(0, 0),
        length=len(w.buf), free_space=0, name="Notebook.onetoc2",
    )
    return bytes(w.buf)


def check_with_pyonenote(path):
    from pyOneNote.OneDocument import OneDocment

    with open(path, "rb") as f:
        doc = OneDocment(f)
    files = doc.get_files()
    contents = sorted(bytes(v["content"]) for v in files.values())
    assert contents == sorted([png_dot(), MINUTES]), contents
    exts = sorted(v["extension"] for v in files.values())
    assert exts == [".png", ".txt"], exts
    texts = [p["val"].get("RichEditTextUnicode") for p in doc.get_properties()]
    titles = [p["val"].get("CachedTitleString") for p in doc.get_properties()]
    assert "Shopping list" in texts and "Agenda: budget, hiring" in texts, texts
    assert "Meeting notes" in titles, titles
    print("pyOneNote:", len(files), "files,", len(doc.get_properties()), "property sets")


def main():
    one = os.path.join(ROOT, "tests/fixtures/synthetic/onenote/Notes.one")
    toc = os.path.join(ROOT, "tests/fixtures/synthetic/onetoc2/Notebook.onetoc2")
    os.makedirs(os.path.dirname(one), exist_ok=True)
    os.makedirs(os.path.dirname(toc), exist_ok=True)
    with open(one, "wb") as f:
        f.write(make_one())
    with open(toc, "wb") as f:
        f.write(make_toc())
    if "--check" in sys.argv:
        check_with_pyonenote(one)


if __name__ == "__main__":
    main()
