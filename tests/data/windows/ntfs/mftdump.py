"""Offline check of a fixed VHD containing an MBR + one NTFS partition.

Lists every in-use MFT record of user files (record >= 24 or named), with its attributes
(type, name, resident/non-resident), and decodes $ATTRIBUTE_LIST and WOF reparse data.
Usage: python -I mftdump.py <file.vhd>
"""
import struct
import sys

ATTR_NAMES = {0x10: '$STANDARD_INFORMATION', 0x20: '$ATTRIBUTE_LIST', 0x30: '$FILE_NAME',
              0x40: '$OBJECT_ID', 0x50: '$SECURITY_DESCRIPTOR', 0x60: '$VOLUME_NAME',
              0x70: '$VOLUME_INFORMATION', 0x80: '$DATA', 0x90: '$INDEX_ROOT',
              0xA0: '$INDEX_ALLOCATION', 0xB0: '$BITMAP', 0xC0: '$REPARSE_POINT',
              0x100: '$LOGGED_UTILITY_STREAM'}
WOF_ALGOS = {0: 'XPRESS4K', 1: 'LZX', 2: 'XPRESS8K', 3: 'XPRESS16K'}


def runs(data):
    pos, lcn, out = 0, 0, []
    while pos < len(data) and data[pos]:
        h = data[pos]
        ln, lo = h & 0xF, h >> 4
        length = int.from_bytes(data[pos + 1:pos + 1 + ln], 'little')
        off = int.from_bytes(data[pos + 1 + ln:pos + 1 + ln + lo], 'little', signed=True) if lo else 0
        lcn += off
        out.append((lcn, length))
        pos += 1 + ln + lo
    return out


def main(path):
    img = open(path, 'rb').read()
    footer = img[-512:]
    assert footer[:8] == b'conectix', 'not a VHD footer'
    lba = struct.unpack_from('<I', img, 0x1BE + 8)[0]
    part = lba * 512
    bs = img[part:part + 512]
    assert bs[3:11] == b'NTFS    '
    bps = struct.unpack_from('<H', bs, 11)[0]
    spc = bs[13]
    cl = bps * spc
    mft_lcn = struct.unpack_from('<Q', bs, 0x30)[0]
    c = struct.unpack_from('<b', bs, 0x40)[0]
    rec = c * cl if c > 0 else 1 << -c
    print(f'partition at LBA {lba}, cluster {cl}, MFT LCN {mft_lcn}, record size {rec}')

    def record(buf):
        buf = bytearray(buf)
        if buf[:4] != b'FILE':
            return None
        uo, uc = struct.unpack_from('<HH', buf, 4)
        usn = buf[uo:uo + 2]
        for i in range(1, uc):
            end = i * bps - 2
            assert buf[end:end + 2] == usn, 'fixup mismatch'
            buf[end:end + 2] = buf[uo + 2 * i:uo + 2 * i + 2]
        return bytes(buf)

    def attrs(r):
        off = struct.unpack_from('<H', r, 0x14)[0]
        while off + 8 <= len(r):
            t, ln = struct.unpack_from('<II', r, off)
            if t == 0xFFFFFFFF or ln == 0:
                break
            yield off, r[off:off + ln]
            off += ln

    # $MFT data runs from record 0
    r0 = record(img[part + mft_lcn * cl:part + mft_lcn * cl + rec])
    mft = b''
    for _, a in attrs(r0):
        if struct.unpack_from('<I', a, 0)[0] == 0x80 and a[8]:
            for lcn, n in runs(a[struct.unpack_from('<H', a, 0x20)[0]:]):
                mft += img[part + lcn * cl:part + (lcn + n) * cl]

    def nonres_bytes(a):
        size = struct.unpack_from('<Q', a, 0x30)[0]
        d = b''.join(img[part + l * cl:part + (l + n) * cl] for l, n in runs(a[struct.unpack_from('<H', a, 0x20)[0]:]))
        return d[:size]

    for i in range(len(mft) // rec):
        r = record(mft[i * rec:(i + 1) * rec])
        if r is None:
            continue
        flags = struct.unpack_from('<H', r, 0x16)[0]
        base = struct.unpack_from('<Q', r, 0x20)[0] & 0xFFFFFFFFFFFF
        if not flags & 1 or i < 24:
            continue
        fname = None
        lines = []
        for off, a in attrs(r):
            t, ln, nonres, nlen, noff = struct.unpack_from('<IIBBH', a, 0)
            name = a[noff:noff + 2 * nlen].decode('utf-16le')
            tn = ATTR_NAMES.get(t, hex(t))
            res = 'non-resident' if nonres else 'resident'
            extra = ''
            if not nonres:
                vlen, voff = struct.unpack_from('<IH', a, 0x10)
                val = a[voff:voff + vlen]
            else:
                val = None
                extra = f' size={struct.unpack_from("<Q", a, 0x30)[0]}'
                if struct.unpack_from('<H', a, 0x0C)[0] & 1:
                    extra += f' compressed(unit=2^{struct.unpack_from("<H", a, 0x22)[0]})'
            if t == 0x30 and val:
                fname = val[0x42:0x42 + 2 * val[0x40]].decode('utf-16le')
                extra = f' {fname!r} ns={val[0x41]}'
            if t == 0x10 and val:
                extra = f' fileattrs=0x{struct.unpack_from("<I", val, 0x20)[0]:08x}'
            if t == 0x20:
                data = val if val is not None else nonres_bytes(a)
                n, p, kinds = 0, 0, []
                while p + 26 <= len(data):
                    at, al = struct.unpack_from('<IH', data, p)
                    if al == 0:
                        break
                    ref = struct.unpack_from('<Q', data, p + 16)[0] & 0xFFFFFFFFFFFF
                    kinds.append(ref)
                    n += 1
                    p += al
                extra += f' len={len(data)} entries={n} records={sorted(set(kinds))}'
            if t == 0xC0 and val:
                tag = struct.unpack_from('<I', val, 0)[0]
                extra = f' tag=0x{tag:08x}'
                if tag == 0x80000017:
                    ver, prov, fver, alg = struct.unpack_from('<IIII', val, 8)
                    extra += f' WOF ver={ver} provider={prov} filever={fver} algorithm={alg} ({WOF_ALGOS.get(alg)})'
            lines.append(f'    {tn}:{name} {res}{extra}')
        print(f'record {i} base={base} flags=0x{flags:x} name={fname!r}')
        print('\n'.join(lines))


if __name__ == '__main__':
    main(sys.argv[1])
