#!/usr/bin/env python3
"""Synthetic installer fixtures: NSIS, Inno Setup and InstallShield.

    uv run --with dclimplode python tests/data/installer/make.py

None of the real producers runs here (makensis is not installed, Inno Setup
and InstallShield need Windows), so the installer data is written from our
understanding of the formats (see the dissectors' module docs). The pieces
around it are real: setup programs are linked by clang + LLD (lld-link) from
stub.c, with resources compiled by llvm-rc; compressed data comes from
Python's zlib, lzma and bz2 (rewritten into NSIS's bzip2 variant by
nsisbz.py) and from the dclimplode package (StormLib's PKWARE DCL).
7-Zip (7zz) lists and extracts the NSIS fixtures.
"""

import binascii
import bz2  # noqa: F401  (used through nsisbz)
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from nsisbz import nsis_bzip2  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FIX = os.path.join(ROOT, "tests", "fixtures", "synthetic")
LLVM = os.environ.get("LLVM_BIN", "/opt/homebrew/opt/llvm@21/bin")
LLD = os.environ.get("LLD_BIN", "/opt/homebrew/opt/lld@21/bin")

u8 = lambda v: struct.pack("<B", v)  # noqa: E731
u16 = lambda v: struct.pack("<H", v)  # noqa: E731
u32 = lambda v: struct.pack("<I", v & 0xFFFFFFFF)  # noqa: E731
i32 = lambda v: struct.pack("<i", v)  # noqa: E731
u64 = lambda v: struct.pack("<Q", v)  # noqa: E731


def write(rel, data):
    path = os.path.join(FIX, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{rel}: {len(data)} bytes")


def setup_program(resources=None):
    """A minimal Windows program (the setup stub), with RCDATA resources."""
    with tempfile.TemporaryDirectory() as tmp:
        obj = os.path.join(tmp, "stub.obj")
        exe = os.path.join(tmp, "stub.exe")
        subprocess.run(
            [f"{LLVM}/clang", "--target=x86_64-pc-windows-msvc", "-Os", "-c",
             os.path.join(HERE, "stub.c"), "-o", obj],
            check=True,
        )
        inputs = [obj]
        if resources:
            lines = []
            for rid, data in resources.items():
                name = os.path.join(tmp, f"r{rid}.bin")
                with open(name, "wb") as f:
                    f.write(data)
                lines.append(f'{rid} RCDATA "{name}"\n')
            rc = os.path.join(tmp, "res.rc")
            with open(rc, "w") as f:
                f.writelines(lines)
            res = os.path.join(tmp, "res.res")
            subprocess.run([f"{LLVM}/llvm-rc", "/fo", res, rc], check=True)
            inputs.append(res)
        subprocess.run(
            [f"{LLD}/lld-link", "/entry:setup", "/subsystem:windows",
             "/nodefaultlib", "/Brepro", f"/out:{exe}", *inputs],
            check=True,
        )
        with open(exe, "rb") as f:
            return f.read()


def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def lzma_raw(data, dict_size=1 << 20):
    """NSIS/Inno LZMA: the properties byte and dictionary size, then the
    raw stream (liblzma ends it with a marker)."""
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3, "lp": 0, "pb": 2}]
    return b"\x5d" + u32(dict_size) + lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)


def png_1x1():
    def chunk(kind, body):
        return u32be(len(body)) + kind + body + u32be(zlib.crc32(kind + body))

    u32be = lambda v: struct.pack(">I", v)  # noqa: E731
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\0\xff\x80\x00")) + chunk(b"IEND", b"")


README = b"Filly Foal 1.0\r\n\r\nA tiny program installed by a tiny installer.\r\n"
MANUAL = b"Run filly.exe and look at files.\r\n" * 3
CONFIG = b"[filly]\r\ncolor=chestnut\r\nmane=long\r\n"

# ---------------------------------------------------------------------------
# NSIS

VAR_INSTDIR = 21
CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS = 0x02, 0x17


class NsisStrings:
    """The string table: strings are lists of text and codes."""

    def __init__(self, unicode, nsis2=False):
        self.unicode = unicode
        # (skip, var, shell, lang)
        self.codes = (252, 253, 254, 255) if nsis2 else (4, 3, 2, 1)
        self.buf = bytearray()
        self.seen = {}
        self.add("")

    def _char(self, c):
        self.out += u16(c) if self.unicode else u8(c)

    def _param(self, x):
        # Two bytes of 7 bits each with the high bit set (a UTF-16 unit
        # holding them in Unicode installers).
        self.out += bytes([(x & 0x7F) | 0x80, ((x >> 7) & 0x7F) | 0x80])

    def add(self, *parts):
        key = repr(parts)
        if key in self.seen:
            return self.seen[key]
        skip, var, shell, lang = self.codes
        self.out = bytearray()
        for p in parts:
            if isinstance(p, str):
                for ch in p:
                    if ord(ch) in self.codes:
                        self._char(skip)
                    self._char(ord(ch) if self.unicode else ch.encode("cp1252")[0])
            elif p[0] == "var":
                self._char(var)
                self._param(p[1])
            elif p[0] == "lang":
                self._char(lang)
                self._param(p[1])
            elif p[0] == "shell":
                self._char(shell)
                if self.unicode:
                    self.out += u16(p[1] | p[2] << 8)
                else:
                    self.out += bytes([p[1], p[2]])
        self._char(0)
        offset = len(self.buf) // (2 if self.unicode else 1)
        self.buf += self.out
        self.seen[key] = offset
        return offset


def nsis_installer(unicode, nsis2, method, solid, files_time=0x01DA1B2C3D4E5F60):
    """Builds NSIS installer data: first header, header and data blocks."""
    s = NsisStrings(unicode, nsis2)
    pfd = s.add("ProgramFilesDir")  # registry-based shell folders need a low offset
    assert pfd < 0x40
    instdir = ("var", VAR_INSTDIR)
    # Data blocks (offsets into the data section).
    datas = []
    blocks = bytearray()

    def data_block(content):
        offset = len(blocks)
        datas.append(content)
        if solid or method == "stored":
            blocks.extend(u32(len(content)) + content)
        else:
            packed = compress(method, content)
            if len(packed) < len(content):
                blocks.extend(u32(len(packed) | 0x80000000) + packed)
            else:
                blocks.extend(u32(len(content)) + content)
        return offset

    lo, hi = files_time & 0xFFFFFFFF, files_time >> 32
    ent = []

    def entry(op, *p):
        ent.append([op, *p] + [0] * (6 - len(p)))
        return len(ent) - 1

    # Section 0: "Program files" (entries 0-5).
    entry(11, s.add(instdir), 1)  # SetOutPath $INSTDIR
    entry(20, 0, s.add("readme.txt"), data_block(README), lo, hi, 0)
    entry(20, 0, s.add("logo.png"), data_block(png_1x1()), lo, hi, 0)
    entry(11, s.add(instdir, "\\docs"), 1)
    entry(20, 2, s.add("manual.txt"), data_block(MANUAL), lo, hi, 0)
    entry(1)
    # Section 1: "Shortcuts" (entries 6-9).
    entry(11, s.add(("shell", CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS), "\\Filly"), 0)  # CreateDirectory
    entry(45, s.add(("shell", CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS), "\\Filly\\Filly.lnk"),
          s.add(instdir, "\\filly.exe"), 0, 0, 0)
    entry(6, s.add("Created shortcuts in ", ("lang", 2)))
    entry(1)
    # A function (.onInit): entries 10-12.
    entry(25, 0, s.add("filly"), 0, 0)  # StrCpy $0 "filly"
    entry(20, 0, s.add(("var", 26), "\\config.ini"), data_block(CONFIG), 0xFFFFFFFF, 0xFFFFFFFF, 0)
    entry(1)

    names = ["Filly Setup", "&Next >", "Filly", "Cancel", "< &Back"]
    lang_strings = [s.add(n) for n in names]
    install_dir = s.add(("shell", 0x80 | pfd, 0x80 | pfd), "\\Filly")
    sec0 = s.add("Program files")
    sec1 = s.add("Shortcuts")
    strings = bytes(s.buf)

    cs = 2 if unicode else 1
    pages = b""
    for kind in (2, 3):  # Directory, Install files
        pages += i32(0) + i32(kind) + i32(-1) * 3 + i32(0)
        pages += i32(~0) + i32(~4) + i32(~1) + i32(0) + i32(~3) + i32(0) * 5
    sections = b""
    for name, code, size_, kb in ((sec0, 0, 6, 1), (sec1, 6, 4, 0)):
        sections += i32(name) + i32(1) + i32(1) + i32(code) + i32(size_) + i32(kb)
        sections += b"\0" * (1024 * cs)
    entries = b"".join(b"".join(u32(v) for v in e) for e in ent)
    langtab = u16(1033) + i32(0) + i32(0) + b"".join(i32(v) for v in lang_strings)

    head_size = 0x12C
    offs = []
    pos = head_size
    for part in (pages, sections, entries, strings, langtab):
        offs.append(pos)
        pos += len(part)
    end = pos
    counts = [2, 2, len(ent), len(strings), 1]
    hdr = bytearray(u32(0))  # flags
    for o, n in zip(offs, counts):
        hdr += u32(o) + u32(n)
    hdr += (u32(end) + u32(0)) * 3  # control colours, background font, data
    hdr += u32(0) * 3  # install_reg_rootkey, key, value
    hdr += u32(0xFFFFFFFF) * 2 + u32(0x00FFFFFF)  # background colours
    hdr += u32(0xFFFFFFFF) * 2  # details colours
    hdr += u32(len(langtab))
    hdr += u32(0xFFFFFFFF)  # license background
    hdr += i32(10) + i32(-1) * 9  # .onInit is entry 10
    hdr += u32(0) * 33  # install types
    hdr += u32(install_dir) + u32(0)
    hdr += u32(0) * 3
    assert len(hdr) == head_size, hex(len(hdr))
    header = bytes(hdr) + pages + sections + entries + strings + langtab

    if solid:
        stream = u32(len(header)) + header + bytes(blocks)
        body = compress(method, stream)
    elif method == "stored":
        body = u32(len(header)) + header + bytes(blocks)
    else:
        packed = compress(method, header)
        body = u32(len(packed) | 0x80000000) + packed + bytes(blocks)
    first = u32(0) + u32(0xDEADBEEF) + b"NullsoftInst" + u32(len(header)) + u32(28 + len(body) + 4)
    return first + body, datas


def compress(method, data):
    if method == "zlib":
        return deflate(data)
    if method == "lzma":
        return lzma_raw(data)
    if method == "bzip2":
        return nsis_bzip2(data)
    raise ValueError(method)


def with_crc(prefix, data):
    """NSIS's CRC-32 covers the setup program and the data before it."""
    return data + u32(binascii.crc32(prefix + data))


def make_nsis():
    stub = setup_program()
    data, _ = nsis_installer(unicode=True, nsis2=False, method="zlib", solid=False)
    write("pe/nsis-setup.exe", stub + with_crc(stub, data))
    data, _ = nsis_installer(unicode=False, nsis2=False, method="lzma", solid=True)
    write("nsis/solid-lzma.bin", with_crc(b"", data))
    data, _ = nsis_installer(unicode=False, nsis2=True, method="bzip2", solid=False)
    write("nsis/bzip2-nsis2.bin", with_crc(b"", data))


# ---------------------------------------------------------------------------
# Inno Setup


class InnoWriter:
    def __init__(self, unicode):
        self.unicode = unicode
        self.out = bytearray()

    def s(self, text):
        """A `String`: UTF-16 in Unicode builds."""
        b = text.encode("utf-16-le") if self.unicode else text.encode("cp1252")
        self.out += u32(len(b)) + b

    def a(self, data):
        """An `AnsiString`: bytes."""
        if isinstance(data, str):
            data = data.encode("cp1252")
        self.out += u32(len(data)) + data

    def raw(self, data):
        self.out += data


def winver(major=6, minor=1, build=0):
    """TSetupVersionData: Windows and NT versions, NT service pack."""
    v = u16(build) + u8(minor) + u8(major)
    return v + v + u16(0)


def inno_block(data, compressed=True):
    """A compressed block: CRC of the next 9 bytes, stored size, flag, then
    4 KiB chunks each after its CRC-32."""
    payload = lzma_raw(data, 1 << 16) if compressed else data
    stored = bytearray()
    for i in range(0, len(payload), 4096):
        piece = payload[i : i + 4096]
        stored += u32(binascii.crc32(piece)) + piece
    head = u32(len(stored)) + u8(1 if compressed else 0)
    return u32(binascii.crc32(head)) + head + bytes(stored)


def lzma2_raw(data):
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}]
    return u8(16) + lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)


def inno_setup_data(ver, unicode, files, chunk_layout):
    """setup-0: version string, header block, location block.

    `files`: (destination, content, location index); `chunk_layout`:
    (start offset, chunk compressed size, [(sub offset, content)]) per
    location, in location order."""
    major, minor, patch = ver
    w = InnoWriter(unicode)
    strings = [
        "Filly Foal", "Filly Foal 1.0", "{A1B2C3D4-FILLY}", "(c) Filly", "Filly Ltd",
        "https://example.invalid/", "", "https://example.invalid/support", "", "1.0",
        "{autopf}\\Filly", "Filly", "setup", "{app}", "", "", "", "{sysuserinfoname}",
        "{sysuserinfoorg}", "", "", "", "", "", "yes", "yes", "*.exe,*.dll,*.chm",
    ]
    if ver >= (5, 5, 6):
        strings.append("")  # SetupMutex
    if ver >= (5, 6, 1):
        strings += ["no", "no"]  # ChangesEnvironment, ChangesAssociations
    for t in strings:
        w.s(t)
    for t in ("", "", "", b"IFPS\x17\x00\x00\x00"):  # license, info, compiled code
        w.a(t)
    if not unicode:
        w.raw(b"\0" * 32)  # LeadBytes
    counts = [1, 1, 0, 1, 1, 1, 1, len(files), len(chunk_layout), 1, 0, 0, 0, 0, 0, 0]
    w.raw(b"".join(u32(c) for c in counts))
    # Settings (see inno.rs `settings`).
    w.raw(winver() + winver(0, 0, 0))
    w.raw(u32(0x00400000) + u32(0x00000000))  # BackColor, BackColor2
    if ver >= (6, 0, 0):
        w.raw(u8(1) + u32(100) + u32(100))  # WizardStyle modern, size percent
    w.raw(u8(0))  # ImageAlphaFormat
    w.raw(b"\0" * 20 + b"\0" * 8)  # PasswordHash, PasswordSalt
    w.raw(u64(0) + u32(1))  # ExtraDiskSpaceRequired, SlicesPerDisk
    w.raw(u8(0) + u8(0) + u8(2))  # UninstallLogMode, DirExistsWarning, PrivilegesRequired admin
    if ver >= (6, 0, 0):
        w.raw(u8(0))  # PrivilegesRequiredOverridesAllowed
    w.raw(u8(2) + u8(0) + u8(4 if ver >= (6, 0, 0) else 3))  # ShowLanguageDialog, detection, LZMA2/LZMA
    w.raw(u8(0x0E) + u8(0x08))  # ArchitecturesAllowed, InstallIn64BitMode
    w.raw(u8(0) + u8(0))  # DisableDirPage, DisableProgramGroupPage
    w.raw(u64(0x30000))  # UninstallDisplaySize
    w.raw(b"\x45\x30\x02\x01\x00\x80\x00" if ver >= (6, 0, 0) else b"\x45\x30\x02\x01\x00\x80")
    # Language.
    for t in ("english", "English", "Tahoma", "Arial", "Verdana", "Arial"):
        w.s(t)
    w.a(b"[LangOptions]\r\nLanguageName=English\r\n")
    for t in ("", "", ""):
        w.a(t)
    w.raw(u32(1033))
    if not unicode:
        w.raw(u32(1252))
    w.raw(u32(8) + u32(29) + u32(12) + u32(8) + u8(0))
    # Custom message.
    w.s("LaunchProgram")
    w.s("Launch %1")
    w.raw(i32(-1))
    # Type.
    for t in ("full", "Full installation", "", ""):
        w.s(t)
    w.raw(winver(0, 0, 0) * 2 + u8(0) + u8(0) + u64(0))
    # Component.
    for t in ("main", "Main files", "full", "", ""):
        w.s(t)
    w.raw(u64(0) + i32(0) + u8(1) + winver(0, 0, 0) * 2 + u8(1) + u64(4096))
    # Task.
    for t in ("desktopicon", "Create a &desktop icon", "Additional icons:", "", "", ""):
        w.s(t)
    w.raw(i32(0) + u8(1) + winver(0, 0, 0) * 2 + u8(0))
    # Directory.
    for t in ("{app}\\docs", "", "", "", "", "", ""):
        w.s(t)
    w.raw(u32(0) + winver(0, 0, 0) * 2 + struct.pack("<h", -1) + u8(0))
    # Files.
    for dest, _content, loc in files:
        for t in ("", dest, "", "", "main", "", "", "", "", ""):
            w.s(t)
        w.raw(winver(0, 0, 0) * 2 + i32(loc) + u32(0xFFFFFFFF) + u64(0) + struct.pack("<h", -1))
        w.raw(u32(1 << 17) + u8(0))  # IgnoreVersion; UserFile
    # Icon (only its first strings are read back).
    for t in ("{group}\\Filly Foal", "{app}\\filly.exe", "", "", "", "", ""):
        w.s(t)
    w.raw(winver(0, 0, 0) * 2 + i32(0) + i32(0) + u8(1) + u8(0) + u16(0))
    w.raw(u32(0))  # wizard images
    header = bytes(w.out)

    locs = bytearray()
    for start, packed, members in chunk_layout:
        for sub, content in members:
            sha1 = __import__("hashlib").sha1(content).digest()
            locs += u32(0) + u32(0) + u32(start) + u64(sub) + u64(len(content)) + u64(packed)
            locs += sha1 + u64(0x01DA1B2C3D4E5F60) + u32(0x00010000) + u32(0x00000000)
            locs += u16(0x0080 | 0x0004 | 0x0002)  # ChunkCompressed, TimeStampInUTC, VersionInfoNotValid
    tag = f"Inno Setup Setup Data ({major}.{minor}.{patch})" + (" (u)" if unicode else "")
    version = tag.encode().ljust(64, b"\0")
    return version + inno_block(header) + inno_block(bytes(locs))


def inno_files():
    files = [("{app}\\readme.txt", README, 0), ("{app}\\docs\\manual.txt", MANUAL, 1), ("{app}\\logo.png", png_1x1(), 2)]
    data = bytearray()
    layout = []
    # Chunk 0: readme and manual (solid); chunk 1: the logo.
    for members in ([README, MANUAL], [png_1x1()]):
        start = len(data)
        joined = b"".join(members)
        packed = lzma2_raw(joined)
        data += b"zlb\x1a" + packed
        subs = []
        off = 0
        for m in members:
            subs.append((off, m))
            off += len(m)
        layout.append((start, len(packed), subs))
    # One location per file, in file order.
    chunk_layout = [(layout[0][0], layout[0][1], [layout[0][2][0]]),
                    (layout[0][0], layout[0][1], [layout[0][2][1]]),
                    (layout[1][0], layout[1][1], [layout[1][2][0]])]
    return files, chunk_layout, bytes(data)


def make_inno():
    files, chunk_layout, file_data = inno_files()
    setup0 = inno_setup_data((6, 2, 2), True, files, chunk_layout)
    # Stands in for the compressed setup program (not decoded).
    setup_e32 = deflate(b"setup.e32 " * 16)

    def build(table):
        return setup_program({11111: table})

    placeholder = build(b"\0" * 44)
    exe_at = len(placeholder)
    offset0 = exe_at + len(setup_e32)
    offset1 = offset0 + len(setup0)
    total = offset1 + len(file_data)
    table = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a" + u32(1) + u32(total) + u32(exe_at)
    table += u32(len(setup_e32)) + u32(binascii.crc32(setup_e32)) + u32(offset0) + u32(offset1)
    table += u32(binascii.crc32(table))
    exe = build(table)
    assert len(exe) == exe_at
    write("pe/inno-setup.exe", exe + setup_e32 + setup0 + file_data)
    # A standalone setup-0 of an ANSI 5.5.9 installer (no file data).
    write("inno-setup/setup-0.bin", inno_setup_data((5, 5, 9), False, files, chunk_layout))


# ---------------------------------------------------------------------------
# InstallShield


def dcl_implode(data):
    import dclimplode

    c = dclimplode.compressobj(dclimplode.CMP_ASCII, 4096)
    return c.compress(data) + c.flush()


def dos_time(y, mo, d, h, mi, s):
    return ((y - 1980) << 9 | mo << 5 | d), (h << 11 | mi << 5 | s // 2)


def make_installshield_z():
    """An InstallShield 3 .z: header, imploded data, directories, files."""
    members = [("", "README.TXT", README), ("DOCS", "MANUAL.TXT", MANUAL), ("DOCS", "LOGO.PNG", png_1x1())]
    dirs = ["", "DOCS"]
    data = bytearray()
    entries = []
    for dname, name, content in members:
        packed = dcl_implode(content)
        entries.append((dirs.index(dname), name, len(content), len(packed), 0xFF + len(data)))
        data += packed
    dir_table = bytearray()
    for d in dirs:
        n = sum(1 for m in members if m[0] == d)
        size_ = 6 + len(d)
        size_ += size_ % 2
        dir_table += (u16(n) + u16(size_) + u16(len(d)) + d.encode()).ljust(size_, b"\0")
    file_table = bytearray()
    date, time = dos_time(1996, 7, 14, 12, 30, 0)
    for di, name, size_, packed, offset in entries:
        n = 0x1E + len(name)
        fixed = u8(0) + u16(di) + u32(size_) + u32(packed) + u32(offset) + u16(date) + u16(time)
        fixed += u32(0x20) + u16(n) + u32(0) + u8(len(name))
        assert len(fixed) == 0x1E
        file_table += fixed + name.encode()
    dirs_at = 0xFF + len(data)
    total = dirs_at + len(dir_table) + len(file_table)
    head = bytearray(0xFF)
    head[0:4] = b"\x13\x5d\x65\x8c"
    head[4:12] = b"\x00\x00\x01\x02\x00\x00\x00\x00"
    head[0x0C:0x0E] = u16(len(members))
    head[0x12:0x16] = u32(total)
    head[0x29:0x2D] = u32(dirs_at)
    head[0x2D:0x31] = u32(len(dir_table))
    head[0x31:0x33] = u16(len(dirs))
    write("installshield-z/setup.z", bytes(head) + bytes(data) + bytes(dir_table) + bytes(file_table))


def is_chunks(content):
    out = bytearray()
    for i in range(0, len(content), 0x8000):
        packed = deflate(content[i : i + 0x8000])
        out += u16(len(packed)) + packed
    return bytes(out)


def is_obfuscate(data):
    out = bytearray()
    for i, b in enumerate(data):
        x = (b + i % 0x47) & 0xFF
        out.append((((x << 2) | (x >> 6)) & 0xFF) ^ 0xD5)
    return bytes(out)


def is_cabinet(major, members, with_data):
    """A cabinet: common header, (volume header,) descriptor, file table,
    file groups, components, (data)."""
    import hashlib

    D = 0x200
    desc = bytearray(0x276)
    # Desc-relative area after the descriptor: names, file table, groups.
    area = bytearray()
    area_at = 0x276

    def put(b):
        nonlocal area
        off = area_at + len(area)
        area += b
        return off

    def cstr(t):
        return put(t.encode() + b"\0")

    dirs = sorted({m[0] for m in members}, key=lambda d: (d != "", d))
    fto = area_at
    ft = bytearray()  # the file table, built relative to fto
    nslots = len(dirs) + (len(members) if major == 5 else 0)
    ft += b"\0" * (4 * nslots)

    def ft_put(b):
        off = len(ft)
        ft.extend(b)
        return off

    for i, d in enumerate(dirs):
        ft[4 * i : 4 * i + 4] = u32(ft_put(d.encode() + b"\0"))
    # Data.
    data = bytearray()
    data_at = 0x700
    descs = []
    for i, (d, name, content, flags) in enumerate(members):
        stored = content
        if flags & 4:
            stored = is_chunks(content)
        if flags & 2:
            stored = is_obfuscate(stored)
        offset = data_at + len(data)
        data += stored
        name_off = ft_put(name.encode() + b"\0")
        md5 = hashlib.md5(content).digest()
        descs.append((name_off, dirs.index(d), flags, len(content), len(stored), offset, md5))
    fto2 = 0
    if major == 5:
        for i, (name_off, di, flags, size_, packed, offset, md5) in enumerate(descs):
            rec = u32(name_off) + u32(di) + u16(flags) + u32(size_) + u32(packed) + b"\0" * 0x14 + u32(offset) + md5
            assert len(rec) == 0x3A
            ft[4 * (len(dirs) + i) : 4 * (len(dirs) + i) + 4] = u32(ft_put(rec))
    else:
        while len(ft) % 4:
            ft.append(0)
        fto2 = len(ft)
        for name_off, di, flags, size_, packed, offset, md5 in descs:
            rec = u16(flags) + u64(size_) + u64(packed) + u64(offset) + md5 + b"\0" * 16
            rec += u32(name_off) + u16(di) + b"\0" * 12 + u32(0) + u32(0) + u8(0) + u16(1)
            assert len(rec) == 0x57
            ft_put(rec)
    put(bytes(ft))
    # File groups and components.
    group_name = cstr("Program Files")
    group = put(u32(group_name) + b"\0" * (0x48 if major == 5 else 0x12) + u32(0) + u32(len(members) - 1))
    group_list = put(u32(group_name) + u32(group) + u32(0))
    comp_name = cstr("Application")
    names_table = put(u32(group_name))
    comp = put(u32(comp_name) + b"\0" * (0x6C if major == 5 else 0x6B) + u16(1) + u32(names_table))
    comp_list = put(u32(comp_name) + u32(comp) + u32(0))
    desc[0x0C:0x10] = u32(fto)
    desc[0x14:0x18] = u32(len(ft))
    desc[0x18:0x1C] = u32(len(ft))
    desc[0x1C:0x20] = u32(len(dirs))
    desc[0x28:0x2C] = u32(len(members))
    desc[0x2C:0x30] = u32(fto2)
    desc[0x3E:0x42] = u32(group_list)
    desc[0x15A:0x15E] = u32(comp_list)
    version = 0x01005000 if major == 5 else (0x02000000 | major * 100)
    blob = bytes(desc) + bytes(area)
    out = bytearray(b"ISc(" + u32(version) + u32(0) + u32(D) + u32(len(blob)))
    if with_data:
        first, last = descs[0], descs[-1]
        if major == 5:
            vol = u32(data_at) + u32(0) + u32(0) + u32(len(members) - 1)
            vol += u32(first[5]) + u32(first[3]) + u32(first[4]) + u32(last[5]) + u32(last[3]) + u32(last[4])
        else:
            vol = u32(data_at) + u32(0) + u32(0) + u32(len(members) - 1)
            for v in (first[5], first[3], first[4], last[5], last[3], last[4]):
                vol += u32(v) + u32(0)
        out += vol
    out = out.ljust(D, b"\0") + blob
    assert len(out) <= data_at
    if with_data:
        out = out.ljust(data_at, b"\0") + data
    return bytes(out)


def make_installshield_cab():
    members = [
        ("", "readme.txt", README, 4),
        ("docs", "manual.txt", MANUAL, 4 | 2),
        ("docs", "logo.png", png_1x1(), 0),
    ]
    write("installshield-cab/data1.cab", is_cabinet(5, members, True))
    write("installshield-cab/data1.hdr", is_cabinet(12, members, False))


def make_installshield():
    make_installshield_z()
    make_installshield_cab()


if __name__ == "__main__":
    what = sys.argv[1:] or ["nsis", "inno", "installshield"]
    for name in what:
        globals()[f"make_{name.replace('-', '_')}"]()
