"""Synthetic MPEG transport stream exercising PSI/SI tables and descriptors
that FFmpeg does not write: CAT, NIT, an SDT with DVB-encoded strings
(ISO/IEC 6937 diacritics and UTF-8), an EIT event long enough to span two
packets, TDT and TOT, a PMT with registration, video, AC-3, teletext,
subtitling, language and maximum-bitrate descriptors, an SCTE-35
splice_insert section, PCRs at both ends, and one continuity counter
error.

    python3 tests/data/mpegts/dvb_si.py

Written from ISO/IEC 13818-1, ETSI EN 300 468 and ANSI/SCTE 35.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(
    os.path.join(HERE, "..", "..", "fixtures", "synthetic", "mpegts", "dvb-si-scte35.ts")
)


def crc32_mpeg(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else (crc << 1)
            crc &= 0xFFFFFFFF
    return crc


def desc(tag, body):
    return bytes([tag, len(body)]) + body


def section(table_id, ext, body, syntax=True, crc=True, version=0):
    if syntax:
        payload = struct.pack(">HBBB", ext, 0xC1 | (version << 1), 0, 0) + body
        length = len(payload) + 4
        head = bytes([table_id]) + struct.pack(">H", 0xB000 | length)
        data = head + payload
    else:
        length = len(body) + (4 if crc else 0)
        head = bytes([table_id]) + struct.pack(">H", 0x7000 | length)
        data = head + body
    if crc:
        data += struct.pack(">I", crc32_mpeg(data))
    return data


def mjd_bcd(y, mo, d, h, mi, s):
    # Modified Julian Date (EN 300 468 Annex C).
    l = 1 if mo in (1, 2) else 0
    mjd = 14956 + d + int((y - 1900 - l) * 365.25) + int((mo + 1 + l * 12) * 30.6001)
    bcd = lambda v: ((v // 10) << 4) | (v % 10)
    return struct.pack(">HBBB", mjd, bcd(h), bcd(mi), bcd(s))


class Mux:
    def __init__(self):
        self.out = bytearray()
        self.cc = {}

    def packet(self, pid, payload, pusi=False, adaptation=None, cc_skip=False):
        cc = self.cc.get(pid, 0)
        if cc_skip:
            cc = (cc + 1) & 15
        afc = 1
        af = b""
        room = 184
        if adaptation is not None:
            afc = 3 if payload else 2
            af = adaptation
        room -= len(af)
        if len(payload) < room:
            # Pad with an adaptation field of stuffing.
            pad = room - len(payload)
            if af:
                af = bytes([af[0] + pad]) + af[1:] + b"\xff" * pad
            elif pad == 1:
                af = b"\x00"
            else:
                af = bytes([pad - 1, 0x00]) + b"\xff" * (pad - 2)
            afc = 3 if payload else 2
        if not afc & 1:
            # Without a payload the counter repeats the previous packet's.
            cc = (cc - 1) & 15
        head = struct.pack(">BHB", 0x47, (0x4000 if pusi else 0) | pid, (afc << 4) | cc)
        pkt = head + af + payload
        assert len(pkt) == 188, len(pkt)
        self.out += pkt
        if afc & 1:
            self.cc[pid] = (cc + 1) & 15

    def section(self, pid, data):
        first = True
        data = b"\x00" + data
        while data:
            chunk, data = data[:184], data[184:]
            self.packet(pid, chunk, pusi=first)
            first = False

    def pcr(self, pid, ticks):
        base, ext = divmod(ticks, 300)
        b = struct.pack(">IH", (base >> 1) & 0xFFFFFFFF, ((base & 1) << 15) | 0x7E00 | ext)
        self.packet(pid, b"", adaptation=bytes([7, 0x10]) + b)


def pes(stream_id, pts, data):
    p = 0x21 | ((pts >> 29) & 0x0E), ((pts >> 22) & 0xFF), 0x01 | ((pts >> 14) & 0xFE), ((pts >> 7) & 0xFF), 0x01 | ((pts << 1) & 0xFE)
    header = bytes([0x80, 0x80, 5]) + bytes(p)
    body = header + data
    return b"\x00\x00\x01" + bytes([stream_id]) + struct.pack(">H", len(body)) + body


def main():
    m = Mux()
    # PAT: program 1 -> PMT 0x100, network PID 0x10.
    pat = struct.pack(">HH", 0, 0xE010) + struct.pack(">HH", 1, 0xE100)
    m.section(0x0000, section(0x00, 0x0042, pat))
    # CAT: one CA descriptor (Conax, ECM PID 0x1FF0).
    cat = desc(0x09, struct.pack(">HH", 0x0B00, 0xFFF0))
    m.section(0x0001, section(0x01, 0xFFFF, cat))
    # PMT.
    prog_info = desc(0x05, b"CUEI")
    streams = b""
    video = desc(0x02, bytes([0x1A, 0x48, 0x5F])) + desc(0x0E, struct.pack(">I", 0x00C00000 | 37500)[1:])
    video += desc(0x06, bytes([0x02]))
    streams += struct.pack(">BHH", 0x02, 0xE101, 0xF000 | len(video)) + video
    ac3 = desc(0x6A, bytes([0x00])) + desc(0x0A, b"eng\x00")
    streams += struct.pack(">BHH", 0x06, 0xE102, 0xF000 | len(ac3)) + ac3
    ttx = desc(0x56, b"deu" + bytes([0x09, 0x88]))
    streams += struct.pack(">BHH", 0x06, 0xE103, 0xF000 | len(ttx)) + ttx
    sub = desc(0x59, b"fra" + bytes([0x10]) + struct.pack(">HH", 1, 2))
    streams += struct.pack(">BHH", 0x06, 0xE104, 0xF000 | len(sub)) + sub
    cue = desc(0x8A, bytes([0x00]))
    streams += struct.pack(">BHH", 0x86, 0xE105, 0xF000 | len(cue)) + cue
    pmt = struct.pack(">HH", 0xE101, 0xF000 | len(prog_info)) + prog_info + streams
    m.section(0x0100, section(0x02, 0x0001, pmt))
    # SDT: ISO/IEC 6937 name with a non-spacing grave accent, UTF-8 provider.
    name = b"Cr\xc1eme TV"
    provider = b"\x15" + "Füllyfoal".encode("utf-8")
    svc = desc(0x48, bytes([0x19, len(provider)]) + provider + bytes([len(name)]) + name)
    sdt = struct.pack(">HB", 0x2000, 0xFF) + struct.pack(">HBH", 1, 0xFD, 0x8000 | len(svc)) + svc
    m.section(0x0011, section(0x42, 0x0042, sdt))
    # NIT: network name, one transport stream with a service list.
    nn = desc(0x40, b"Test Network")
    sl = desc(0x41, struct.pack(">HB", 1, 0x19))
    ts_loop = struct.pack(">HHH", 0x0042, 0x2000, 0xF000 | len(sl)) + sl
    nit = struct.pack(">H", 0xF000 | len(nn)) + nn + struct.pack(">H", 0xF000 | len(ts_loop)) + ts_loop
    m.section(0x0010, section(0x40, 0x2000, nit))
    # EIT present/following: one event, long extended text -> two packets.
    short = desc(0x4D, b"eng" + bytes([4]) + b"News" + bytes([18]) + b"The evening bullet")
    text = (b"Headlines, weather and sport from around the region. " * 4)[:200]
    ext = desc(0x4E, bytes([0x00]) + b"eng" + bytes([0]) + bytes([len(text)]) + text)
    content = desc(0x54, bytes([0x21, 0x00]))
    rating = desc(0x55, b"DEU" + bytes([0x09]))
    loop = short + ext + content + rating
    event = struct.pack(">H", 0x1234) + mjd_bcd(2026, 10, 9, 20, 0, 0) + bytes([0x00, 0x30, 0x00]) + struct.pack(">H", 0x8000 | len(loop)) + loop
    eit = struct.pack(">HHBB", 0x0042, 0x2000, 0, 0x4E) + event
    m.section(0x0012, section(0x4E, 0x0001, eit))
    # TDT and TOT.
    now = mjd_bcd(2026, 10, 9, 19, 59, 30)
    m.section(0x0014, section(0x70, 0, now, syntax=False, crc=False))
    lto = desc(0x58, b"DEU" + bytes([0x02]) + bytes([0x01, 0x00]) + mjd_bcd(2026, 10, 25, 1, 0, 0) + bytes([0x00, 0x00]))
    tot = now + struct.pack(">H", 0xF000 | len(lto)) + lto
    m.section(0x0014, section(0x73, 0, tot, syntax=False, crc=True))
    # PCR, then a video PES with an MPEG-2 sequence header and extension.
    m.pcr(0x0101, 27_000_000)
    # 720x576, 4:3, 25 fps, 6 Mb/s; Main@Main, interlaced 4:2:0.
    seq = bytes.fromhex("000001b3 2d0240 23 0ea62380 000001b5 148200010000")
    m.packet(0x0101, pes(0xE0, 90_000, seq), pusi=True)
    # AC-3: 48 kHz, 192 kb/s, 3/2 + LFE.
    ac3_frame = bytes.fromhex("0b770000 1440 e100") + bytes(24)
    m.packet(0x0102, pes(0xBD, 90_000, ac3_frame), pusi=True)
    # A packet whose continuity counter skips one.
    m.packet(0x0102, bytes(184), cc_skip=True)
    # SCTE-35 splice_insert: out of network at PTS 2 s, for 30 s.
    cmd = struct.pack(">IB", 0x4800_0001, 0x7F)
    cmd += bytes([0b1110_1111])  # out_of_network, program_splice, duration, not immediate
    cmd += bytes([0xFE]) + struct.pack(">I", 180_000)  # time_specified + 33-bit pts
    cmd += bytes([0xFE]) + struct.pack(">I", 2_700_000)  # auto_return + duration
    cmd += struct.pack(">HBB", 1, 0, 0)
    # protocol_version, encrypted/algorithm/pts_adjustment (40 bits), cw_index,
    # tier (12) + splice_command_length (12), command type.
    body = bytes([0x00]) + bytes(5) + bytes([0xFF]) + bytes([0xFF, 0xF0 | (len(cmd) >> 8), len(cmd) & 0xFF]) + bytes([0x05]) + cmd + struct.pack(">H", 0)
    m.section(0x0105, section(0xFC, 0, body, syntax=False, crc=True))
    # Null packets, then the closing PCR.
    for _ in range(2):
        m.packet(0x1FFF, b"\xff" * 184)
    m.pcr(0x0101, 27_000_000 + 2 * 27_000_000)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(m.out)


if __name__ == "__main__":
    main()
