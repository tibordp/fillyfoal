"""Synthetic RedSea (TempleOS) images, written the way TempleOS V5.03 writes
them (public-domain source: Kernel/BlkDev/FileSysRedSea.HC, DskAddDev.HC,
DskFmt.HC, Adam/ABlkDev/DskPrt.HC, Adam/Opt/Boot/DskISORedSea.HC), packing
real files from the TempleOS V5.03 distribution ISO:

    python3 make_image.py REPO_ROOT

writes
  tests/fixtures/synthetic/redsea/templeos.img.gz   a bare 64-block RedSea
      volume (drv_offset 0, as on a RAM drive), with a file written and then
      deleted (RedSeaFilesDel: entry marked, blocks freed)
  tests/fixtures/synthetic/mbr/templeos-redsea.img.gz   the same tree in the
      first partition of an MBR disk, at block 63 as DskPrt puts it, with the
      FAT32 type RedSeaFmt gives it ("to fool BIOS"); block numbers are
      absolute, so the volume is written for drv_offset 63
  tests/fixtures/synthetic/iso9660/templeos.iso.gz   an ISO as RedSeaISO
      writes it: sized by RedSeaISOPass1, an empty ISO 9660 shell
      (RedSeaISO9660: TempleOS's CISOPriDesc layout, El Torito catalog)
      with the RedSea volume at block 88 (no stage-2 loader, so the boot
      image sector stays empty)

Not reproduced: what a TempleOS session would add besides these steps (the
real ISO also has ARCHIVE attributes on some entries), and directory growth
(RedSeaDirNew's reallocation is implemented but no directory here fills
up).

The packed files: Demo/DateTime.HC.Z, Doc/FileLowLevel.DD.Z (from
tests/fixtures/external/templeos-z/, copied out of the ISO by extract.py),
and DateTime.HC (TOSZ's expansion of DateTime.HC.Z, from
tests/data/templeos-z/), with the ISO's timestamps. Formatting time and the
volume ID are fixed. Gzipped with mtime 0 for storage.
"""
import gzip
import os
import struct
import sys

BLK = 512
ENTRY = 64
SIG = 0x88
DIR, ARCHIVE, DELETED, COMPRESSED, CONTIGUOUS = 0x10, 0x20, 0x100, 0x400, 0x800
# The ISO's build time (CDate: time, date), used for "Now".
NOW = (0xF1362161, 0xB3F0F)
UNIQUE_ID = 0x7E3D_5EA0_0000_0001

def ceil(a, b):
    return (a + b - 1) // b


class Vol:
    """A RedSea drive: blocks drv_offset .. drv_offset+sects-1."""

    def __init__(self, drv_offset, sects, root_dir_blks):
        self.drv_offset = drv_offset
        self.sects = sects
        self.img = bytearray(sects * BLK)
        self.free = None
        self.fmt(root_dir_blks)

    def at(self, blk):
        return (blk - self.drv_offset) * BLK

    def read(self, blk, n):
        return bytes(self.img[self.at(blk):self.at(blk) + n * BLK])

    def write(self, blk, data):
        self.img[self.at(blk):self.at(blk) + len(data)] = data

    # RedSeaFmt
    def fmt(self, root_dir_blks):
        self.bitmap_sects = ceil(self.sects, BLK * 8)
        self.data_area = self.drv_offset + self.bitmap_sects
        self.root = 0
        self.write_boot()
        self.free = None
        self.alloc(1)  # Alloc #1: the bitmap's last block
        self.root = self.alloc(root_dir_blks)
        self.write_boot()
        d = self.entry(DIR | CONTIGUOUS, b'.', self.root, BLK * root_dir_blks, NOW)
        d += self.entry(DIR | CONTIGUOUS, b'..', self.root, 0, NOW)
        self.write(self.root, d.ljust(BLK * root_dir_blks, b'\0'))
        self.free = None

    def write_boot(self):
        b = bytearray(BLK)
        b[3] = SIG
        struct.pack_into('<qqqqQ', b, 8, self.drv_offset, self.sects, self.root,
                         self.bitmap_sects, UNIQUE_ID)
        b[510:512] = b'\x55\xaa'
        self.write(self.drv_offset, b)

    @staticmethod
    def entry(attr, name, clus, size, dt):
        assert len(name) < 38
        return struct.pack('<H38sqqIi', attr, name, clus, size, dt[0], dt[1])

    # The bitmap: bit c - data_area, LSB first, from block drv_offset + 1.
    def bit(self, c):
        i = c - self.data_area
        return self.img[self.at(self.drv_offset + 1) + i // 8] >> (i % 8) & 1

    def set_bit(self, c, v):
        i = c - self.data_area
        o = self.at(self.drv_offset + 1) + i // 8
        if v:
            self.img[o] |= 1 << (i % 8)
        else:
            self.img[o] &= ~(1 << (i % 8)) & 0xFF

    # RedSeaFreeLstBuild
    def build_free(self):
        self.free = []
        first, max_blk = self.data_area, self.sects + self.drv_offset
        while first < max_blk:
            i = 0
            while first + i < max_blk and not self.bit(first + i):
                i += 1
            if i:
                self.free.append([first, i])
            first += i + 1

    # RedSeaAllocClus: best fit
    def alloc(self, cnt):
        if self.free is None:
            self.build_free()
        best = None
        for run in self.free:
            if run[1] >= cnt and (best is None or run[1] < best[1]):
                best = run
                if run[1] == cnt:
                    break
        assert best, 'volume full'
        first = best[0]
        for i in range(cnt):
            self.set_bit(first + i, 1)
        best[1] -= cnt
        if best[1]:
            best[0] += cnt
        else:
            self.free.remove(best)
        return first

    # RedSeaFreeClus
    def free_clus(self, c, cnt):
        if not c:
            return
        if self.free is None:
            self.build_free()
        for run in self.free:
            if run[0] + run[1] == c:
                run[1] += cnt
                break
            if c + cnt == run[0]:
                run[1] += cnt
                run[0] = c
                break
        else:
            self.free.append([c, cnt])
        for i in range(cnt):
            self.set_bit(c + i, 0)

    def dir_size(self, clus):
        return struct.unpack_from('<q', self.img, self.at(clus) + 48)[0]

    # RedSeaDirNew: `path` is the list of (directory block, name) from the
    # root down to the directory the entry goes in.
    def dir_new(self, path, de, free_old_chain):
        clus = path[-1][0]
        size = self.dir_size(clus)
        buf = bytearray(self.read(clus, size // BLK))
        written = False
        i = 1
        while True:
            e = buf[i * ENTRY:(i + 1) * ENTRY]
            attr = struct.unpack_from('<H', e)[0]
            name = e[2:40].split(b'\0')[0]
            if not name:
                if not written:
                    buf[i * ENTRY:(i + 1) * ENTRY] = de
                if (i + 1) * ENTRY < size:
                    self.write(clus, buf)
                else:
                    buf += bytes(BLK)
                    self.free_clus(clus, size // BLK)
                    size += BLK
                    c = self.alloc(size // BLK)
                    struct.pack_into('<qq', buf, 40, c, size)
                    self.write(c, buf)
                    if len(path) == 1:
                        self.root = c
                        self.write_boot()
                    else:
                        parent = path[:-1]
                        pbuf = self.read(parent[-1][0], self.dir_size(parent[-1][0]) // BLK)
                        for k in range(len(pbuf) // ENTRY):
                            pe = bytearray(pbuf[k * ENTRY:(k + 1) * ENTRY])
                            if pe[2:40].split(b'\0')[0] == path[-1][1] and k > 1:
                                struct.pack_into('<qq', pe, 40, c, size)
                                self.dir_new(parent, bytes(pe), False)
                                break
                    path[-1] = (c, path[-1][1])
                return
            elif attr & DELETED:
                if not written:
                    buf[i * ENTRY:(i + 1) * ENTRY] = de
                    self.write(clus, buf)
                    written = True
            elif name == de[2:40].split(b'\0')[0]:
                if free_old_chain:
                    old_clus, old_size = struct.unpack_from('<qq', e, 40)
                    self.free_clus(old_clus, ceil(old_size, BLK))
                if not written:
                    buf[i * ENTRY:(i + 1) * ENTRY] = de
                else:
                    buf[i * ENTRY] |= DELETED & 0xFF
                    buf[i * ENTRY + 1] |= DELETED >> 8
                self.write(clus, buf)
                return
            i += 1

    # RedSeaFileWrite
    def file_write(self, path, name, data, dt, attr):
        blks = ceil(len(data), BLK)
        c = self.alloc(blks) if blks else -1
        self.write(c, data.ljust(blks * BLK, b'\0'))
        self.dir_new(path, self.entry(attr | CONTIGUOUS, name, c, len(data), dt), True)
        return c

    # RedSeaMkDir (through FileWrite)
    def mkdir(self, path, name, entry_cnt):
        size = ceil((entry_cnt + 3) * ENTRY, BLK) * BLK
        c = self.file_write(path, name, bytes(size), NOW, DIR)
        d = self.entry(DIR | CONTIGUOUS, name, c, size, NOW)
        d += self.entry(DIR | CONTIGUOUS, b'..', path[-1][0], 0, NOW)
        self.write(c, d)
        return path + [(c, name)]

    # RedSeaFilesDel, for one file
    def delete(self, path, name):
        clus = path[-1][0]
        size = self.dir_size(clus)
        buf = bytearray(self.read(clus, size // BLK))
        for i in range(size // ENTRY):
            e = buf[i * ENTRY:(i + 1) * ENTRY]
            if e[2:40].split(b'\0')[0] == name:
                attr = struct.unpack_from('<H', e)[0] | DELETED
                struct.pack_into('<H', buf, i * ENTRY, attr)
                self.write(clus, buf)
                c, s = struct.unpack_from('<qq', e, 40)
                self.free_clus(c, ceil(s, BLK))
                return
        raise KeyError(name)


def tree(repo):
    z = os.path.join(repo, 'tests/fixtures/external/templeos-z')
    data = os.path.join(repo, 'tests/data/templeos-z')
    rd = lambda p: open(p, 'rb').read()
    # (name, contents or subtree, CDate); sorted as FilesFind lists them.
    return [
        (b'DateTime.HC', rd(os.path.join(data, 'DateTime.HC')), (0x877C048D, 0xB3D56)),
        (b'Demo', [
            (b'DateTime.HC.Z', rd(os.path.join(z, 'DateTime.HC.Z')), (0x877C048D, 0xB3D56)),
        ], NOW),
        (b'Doc', [
            (b'FileLowLevel.DD.Z', rd(os.path.join(z, 'FileLowLevel.DD.Z')), (0x22345678, 0xB3DCF)),
        ], NOW),
    ]


def attr_for(name):
    return COMPRESSED if name.endswith(b'.Z') else 0


def copy_tree(vol, path, entries, dirs):
    """CopyTree2: directories depth first, files as they come. Collects
    the path of each directory in `dirs`."""
    for name, body, dt in entries:
        if isinstance(body, list):
            sub = vol.mkdir(path, name, len(body))
            dirs[name] = sub
            copy_tree(vol, sub, body, dirs)
        else:
            vol.file_write(path, name, body, dt, attr_for(name))


def pass1(entries):
    """RedSeaISOPass1: bytes the tree needs."""
    res = 0
    for _, body, _ in entries:
        if isinstance(body, list):
            res += pass1(body) if body else BLK
        else:
            res += ceil(len(body), BLK) * BLK
    return res + ceil((len(entries) + 3) * ENTRY, BLK) * BLK


def volume(repo, drv_offset):
    """A 64-block drive (one bitmap block, a one-block root) starting at
    `drv_offset`, with the tree, and one file written and then deleted (its
    entry stays, marked, and its blocks are free)."""
    vol = Vol(drv_offset, 64, 1)
    dirs = {}
    entries = tree(repo)
    copy_tree(vol, [(vol.root, b'')], entries, dirs)
    old = [b for n, b, _ in entries[2][1] if n == b'FileLowLevel.DD.Z'][0]
    vol.file_write(dirs[b'Doc'], b'Old.DD.Z', old, (0x22345678, 0xB3DCF), COMPRESSED)
    vol.delete(dirs[b'Doc'], b'Old.DD.Z')
    return vol


def mbr(vol):
    m = bytearray(BLK)
    # CMBRPrt as DskPrt fills it; RedSeaFmt sets the type to MBR_PT_FAT32a.
    struct.pack_into('<BBHBBHII', m, 446, 0x80, 0, 0x101, 0x0B, 0xFE, 0xFFFF,
                     vol.drv_offset, vol.sects)
    m[510:512] = b'\x55\xaa'
    return bytes(m) + bytes((vol.drv_offset - 1) * BLK) + bytes(vol.img)


def iso(repo):
    entries = tree(repo)
    drv_offset = (19 << 2) + (2048 * 2 + 2048) // BLK
    root_dir_blks = ceil((len(entries) + 3) << 6, BLK)
    res = pass1(entries) // BLK
    bitmap_blks = 1
    while True:
        prev = bitmap_blks
        bitmap_blks = (res + bitmap_blks + BLK * 8 - 1) // (BLK * 8)
        if bitmap_blks == prev:
            break
    max_blk = ceil(drv_offset + 1 + bitmap_blks + res, 4) * 4 - 1
    vol = Vol(drv_offset, max_blk + 1 - drv_offset, root_dir_blks)
    copy_tree(vol, [(vol.root, b'')], entries, {})
    img = bytearray(drv_offset * BLK) + vol.img
    iso_size = len(img) // 2048

    def desc(kind):
        d = bytearray(2048)
        d[0] = kind
        d[1:6] = b'CD001'
        d[6] = 1
        return d

    def palindrome(fmt, v):
        return struct.pack('<' + fmt, v) + struct.pack('>' + fmt, v)

    pri = desc(1)  # CISOPriDesc
    pri[80:88] = palindrome('I', iso_size)
    pri[120:124] = palindrome('H', 1)  # vol_set_size
    pri[124:128] = palindrome('H', 1)  # vol_seq_num
    pri[128:132] = palindrome('H', 2048)  # log_block_size
    # FillU32Palindrome(&root_dir_record, root_clus): at the record's start.
    pri[152:160] = palindrome('I', vol.root)
    pri[314:314 + 15] = b'TempleOS RedSea'
    pri[877] = 1
    sup = bytearray(pri)
    sup[0] = 2
    boot = desc(0)
    boot[7:7 + 23] = b'EL TORITO SPECIFICATION'
    struct.pack_into('<I', boot, 0x47, 20)
    term = desc(255)
    et = bytearray(2048)  # CElTorito
    w = [0] * 16
    w[0] = 1
    name = b'TempleOS'
    for k in range(0, len(name), 2):
        w[2 + k // 2] = name[k] | name[k + 1] << 8
    w[15] = 0xAA55
    w[14] = -sum(w) & 0xFFFF
    struct.pack_into('<16H', et, 0, *w)
    struct.pack_into('<BBHBBHI', et, 32, 0x88, 0, 0, 0, 0, 4, 21)
    for sector, d in ((16, pri), (17, boot), (18, sup), (19, term), (20, et)):
        img[sector * 2048:(sector + 1) * 2048] = d
    return bytes(img)


def save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(gzip.compress(data, compresslevel=9, mtime=0))


def main():
    repo = sys.argv[1]
    fx = os.path.join(repo, 'tests/fixtures/synthetic')
    save(os.path.join(fx, 'redsea/templeos.img.gz'), bytes(volume(repo, 0).img))
    # DskPrt's first partition starts at DRV_HEADER (63).
    save(os.path.join(fx, 'mbr/templeos-redsea.img.gz'), mbr(volume(repo, 63)))
    save(os.path.join(fx, 'iso9660/templeos.iso.gz'), iso(repo))


main()
