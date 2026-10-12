"""Minimal OLE2/CFB inspector (no third-party deps).

Lists streams, dumps SummaryInformation / DocumentSummaryInformation string/time properties,
the PowerPoint "Current User" stream user name, and the .xls FILEPASS record.

Usage: python -I olecheck.py <file>...
"""
import struct
import sys
import datetime

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF


class CFB:
    def __init__(self, data):
        if data[:8] != bytes.fromhex("D0CF11E0A1B11AE1"):
            raise ValueError("not an OLE2 file")
        self.d = data
        self.ss = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        self.mss = 1 << struct.unpack_from("<H", data, 0x20)[0]
        nfat, fdir = struct.unpack_from("<II", data, 0x2C)
        self.cutoff, fminifat, nminifat, fdifat, ndifat = struct.unpack_from("<IIIII", data, 0x38)
        difat = list(struct.unpack_from("<109I", data, 0x4C))
        s = fdifat
        while s not in (ENDOFCHAIN, FREESECT) and ndifat:
            sec = self.sector(s)
            vals = struct.unpack("<%dI" % (self.ss // 4), sec)
            difat += vals[:-1]
            s = vals[-1]
            ndifat -= 1
        self.fat = []
        for x in difat[:nfat]:
            self.fat += struct.unpack("<%dI" % (self.ss // 4), self.sector(x))
        dirdata = self.chain(fdir)
        self.entries = []
        for i in range(len(dirdata) // 128):
            e = dirdata[i * 128:(i + 1) * 128]
            nl = struct.unpack_from("<H", e, 0x40)[0]
            name = e[:max(nl - 2, 0)].decode("utf-16le", "replace")
            typ = e[0x42]
            start, size = struct.unpack_from("<IQ", e, 0x74)
            self.entries.append((name, typ, start, size))
        root = self.entries[0]
        self.ministream = self.chain(root[2])
        self.minifat = []
        if nminifat:
            m = self.chain(fminifat)
            self.minifat = list(struct.unpack("<%dI" % (len(m) // 4), m))

    def sector(self, n):
        o = 512 + n * self.ss if self.ss == 512 else self.ss * (n + 1)
        return self.d[o:o + self.ss]

    def chain(self, s):
        out = []
        seen = 0
        while s not in (ENDOFCHAIN, FREESECT) and seen < 1 << 20:
            out.append(self.sector(s))
            s = self.fat[s]
            seen += 1
        return b"".join(out)

    def stream(self, name):
        for n, typ, start, size in self.entries:
            if n == name and typ == 2:
                if size < self.cutoff:
                    out = []
                    s = start
                    while s not in (ENDOFCHAIN, FREESECT):
                        out.append(self.ministream[s * self.mss:(s + 1) * self.mss])
                        s = self.minifat[s]
                    return b"".join(out)[:size]
                return self.chain(start)[:size]
        return None


def props(data):
    out = []
    if not data:
        return out
    nsets = struct.unpack_from("<I", data, 24)[0]
    for k in range(nsets):
        off = struct.unpack_from("<I", data, 28 + k * 20 + 16)[0]
        n = struct.unpack_from("<I", data, off + 4)[0]
        cp = 1252
        items = []
        for i in range(n):
            pid, po = struct.unpack_from("<II", data, off + 8 + i * 8)
            items.append((pid, off + po))
        for pid, p in items:
            vt = struct.unpack_from("<H", data, p)[0]
            if pid == 1 and vt == 2:
                cp = struct.unpack_from("<H", data, p + 4)[0]
        for pid, p in items:
            vt = struct.unpack_from("<H", data, p)[0]
            if vt == 0x1E:
                ln = struct.unpack_from("<I", data, p + 4)[0]
                raw = data[p + 8:p + 8 + ln]
                v = raw.decode("utf-16le" if cp == 1200 else "cp1252", "replace").rstrip("\0")
            elif vt == 0x1F:
                ln = struct.unpack_from("<I", data, p + 4)[0]
                v = data[p + 8:p + 8 + ln * 2].decode("utf-16le", "replace").rstrip("\0")
            elif vt == 0x40:
                ft = struct.unpack_from("<Q", data, p + 4)[0]
                v = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)).isoformat() if ft > 10 ** 15 else "duration %ds" % (ft // 10 ** 7)
            elif vt in (2, 3, 11):
                v = struct.unpack_from("<i" if vt == 3 else "<h", data, p + 4)[0]
            else:
                v = "<vt 0x%x>" % vt
            out.append((k, pid, v))
    return out


SI = {2: "Title", 3: "Subject", 4: "Author", 5: "Keywords", 6: "Comments", 7: "Template",
      8: "LastAuthor", 9: "RevNumber", 10: "EditTime", 12: "Created", 13: "LastSaved",
      14: "Pages", 18: "AppName", 19: "Security", 1: "Codepage"}
DSI = {15: "Company", 14: "Manager", 2: "Category", 1: "Codepage", 23: "AppVersion"}


def main():
    for fn in sys.argv[1:]:
        print("==", fn)
        d = open(fn, "rb").read()
        c = CFB(d)
        for n, typ, start, size in c.entries:
            if typ in (1, 2):
                print("  %s %r size=%d" % ("stream" if typ == 2 else "storage", n, size))
        for sn, names in (("\x05SummaryInformation", SI), ("\x05DocumentSummaryInformation", DSI)):
            for k, pid, v in props(c.stream(sn)):
                print("  %s[%d] %s = %r" % (sn[1:], k, names.get(pid, pid) if k == 0 else pid, v))
        cu = c.stream("Current User")
        if cu:
            reclen = struct.unpack_from("<I", cu, 4)[0]
            size, hdr, off, lenu, ver = struct.unpack_from("<IIIHH", cu, 8)
            tok = {0xE391C05F: "unencrypted", 0xF3D1C4DF: "encrypted"}.get(hdr, "?")
            ansi = cu[28:28 + lenu]
            uni = cu[28 + lenu + 4:8 + reclen].decode("utf-16le", "replace")
            print("  CurrentUser: docFileVersion=%x headerToken=%08x (%s) ansiUser=%r unicodeUser=%r" % (ver, hdr, tok, ansi, uni))
        wb = c.stream("Workbook")
        if wb:
            o = 0
            while o + 4 <= len(wb):
                rt, ln = struct.unpack_from("<HH", wb, o)
                if rt == 0x2F:
                    body = wb[o + 4:o + 4 + ln]
                    et = struct.unpack_from("<H", body, 0)[0]
                    s = "  FILEPASS wEncryptionType=%d" % et
                    if et == 1:
                        vmaj, vmin = struct.unpack_from("<HH", body, 2)
                        s += " RC4 header version %d.%d (%s)" % (vmaj, vmin, "CryptoAPI" if vmaj in (2, 3, 4) and vmin == 2 else "RC4 basic" if vmaj == 1 else "?")
                        if vmaj in (2, 3, 4):
                            flags, hsize = struct.unpack_from("<II", body, 6)
                            alg, halg, keybits, prov = struct.unpack_from("<IIII", body, 14 + 8)
                            csp = body[14 + 32:14 + hsize].decode("utf-16le", "replace").rstrip("\0")
                            s += " AlgID=%x HashAlg=%x KeySize=%d CSP=%r" % (alg, halg, keybits, csp)
                    print(s)
                    break
                if rt == 0x0A:
                    break
                o += 4 + ln


if __name__ == "__main__":
    main()

