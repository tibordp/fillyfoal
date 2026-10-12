"""Print IT/MPTM header and per-sample flags (Flg, Cvt) to verify sample compression.
Flg 0x08 = compressed sample; Cvt 0x04 = IT 2.15 compression variant (only meaningful with 0x08).
Usage: python -I check_it.py file.it [...]
"""
import struct
import sys

for path in sys.argv[1:]:
    b = open(path, "rb").read()
    assert b[:4] == b"IMPM", path
    title = b[4:30].split(b"\0")[0].decode("latin-1")
    ordnum, insnum, smpnum, patnum, cwt, cmwt, flags, special = struct.unpack_from("<8H", b, 0x20)
    print(f"{path}: title={title!r} cwt=0x{cwt:04X} cmwt=0x{cmwt:04X} flags=0x{flags:04X} "
          f"special=0x{special:04X} ord={ordnum} ins={insnum} smp={smpnum} pat={patnum} size={len(b)}")
    base = 0xC0 + ordnum + 4 * insnum
    for i in range(smpnum):
        off = struct.unpack_from("<I", b, base + 4 * i)[0]
        h = b[off:off + 80]
        flg, cvt = h[0x12], h[0x2E]
        name = h[0x14:0x2E].split(b"\0")[0].decode("latin-1")
        length, = struct.unpack_from("<I", h, 0x30)
        ptr, = struct.unpack_from("<I", h, 0x48)
        bits = []
        if flg & 0x02: bits.append("16bit")
        if flg & 0x04: bits.append("stereo")
        if flg & 0x08: bits.append("COMPRESSED")
        if flg & 0x08 and cvt & 0x04: bits.append("IT215")
        print(f"  smp{i+1} {name!r} flg=0x{flg:02X} cvt=0x{cvt:02X} len={length} ptr=0x{ptr:X} {' '.join(bits)}")
