"""Extract the files of a RedSea volume (TempleOS), bare or inside the
TempleOS distribution ISO (where the volume starts at byte 0xB000).

    python3 extract.py TempleOS.ISO OUTDIR

Writes every file at its path under OUTDIR (as stored: `.Z` files stay
compressed) and OUTDIR/manifest.tsv (path, attributes, first block, size,
CDate time and date, in hex). Follows `Kernel/BlkDev/FileSysRedSea.HC`:
block numbers are absolute 512-byte blocks counted from the start of the
drive, where the boot sector's `drv_offset` says the volume begins; a
directory is a run of 64-byte entries whose first ("." ) gives the
directory's size, ended by an entry with an empty name.

The fixtures in tests/fixtures/external/templeos-z/ and the files packed by
make_image.py came from TempleOS V5.03's ISO this way (see SOURCES.md).
"""
import os
import struct
import sys


def boot_offset(img):
    for at in (0, 0xB000):
        b = img[at:at + 512]
        if len(b) == 512 and b[3] == 0x88 and b[510:512] == b'\x55\xaa':
            return at
    raise SystemExit('no RedSea boot sector at 0 or 0xB000')


def main():
    img = open(sys.argv[1], 'rb').read()
    out = sys.argv[2]
    base = boot_offset(img)
    drv_offset, _sects, root, _bitmap, _uid = struct.unpack_from('<qqqqq', img, base + 8)

    def at(blk):
        return base + (blk - drv_offset) * 512

    manifest = []

    def walk(blk, path, depth):
        if depth > 64:
            raise SystemExit('directories nested too deep')
        off = at(blk)
        size = struct.unpack_from('<q', img, off + 48)[0]
        for i in range(size // 64):
            e = img[off + i * 64:off + i * 64 + 64]
            attr = struct.unpack_from('<H', e)[0]
            name = e[2:40].split(b'\0')[0].decode('latin1')
            if not name:
                break
            if i < 2:  # "." and ".."
                continue
            clus, length, time, date = struct.unpack_from('<qqIi', e, 40)
            p = path + '/' + name
            manifest.append((p, attr, clus, length, time, date))
            if attr & 0x100:  # RS_ATTR_DELETED
                continue
            if attr & 0x10:  # RS_ATTR_DIR
                walk(clus, p, depth + 1)
            else:
                dst = os.path.join(out, p.lstrip('/'))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, 'wb') as f:
                    f.write(img[at(clus):at(clus) + length])

    walk(root, '', 0)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'manifest.tsv'), 'w') as f:
        for p, *rest in manifest:
            f.write(p + '\t' + '\t'.join(hex(v & 0xffffffffffffffff) for v in rest) + '\n')
    files = sum(1 for m in manifest if not m[1] & 0x10)
    print(f'{files} files', file=sys.stderr)


main()
