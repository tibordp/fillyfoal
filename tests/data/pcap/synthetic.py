"""Hand-built captures for corners the real captures do not reach.

Writes tests/fixtures/synthetic/pcap/*.pcap and
tests/fixtures/synthetic/pcapng/*.pcapng (run from the repository root with
`python3 tests/data/pcap/synthetic.py`). Addresses are from the
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32) and
locally administered MACs; checksums are computed.
"""
import struct
import zlib

T0 = 1_791_600_000  # 2026-10-10 UTC


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(a):
    return bytes(int(x) for x in a.split("."))


def ip6(a):
    import ipaddress
    return ipaddress.IPv6Address(a).packed


MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
BCAST = b"\xff" * 6


def ether(dst, src, etype, payload):
    return dst + src + struct.pack("!H", etype) + payload


def ipv4(src, dst, proto, payload, opts=b"", ident=1, flags=0x4000, ttl=64, tos=0):
    ihl = 5 + len(opts) // 4
    total = ihl * 4 + len(payload)
    h = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, tos, total, ident, flags, ttl, proto, 0, ip4(src), ip4(dst)) + opts
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return h + payload


def pseudo4(src, dst, proto, length):
    return ip4(src) + ip4(dst) + struct.pack("!BBH", 0, proto, length)


def pseudo6(src, dst, proto, length):
    return ip6(src) + ip6(dst) + struct.pack("!IxxxB", length, proto)


def udp(src_port, dst_port, payload, pseudo):
    h = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    c = csum(pseudo(17, 8 + len(payload)) + h + payload) or 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), c) + payload


def tcp(sp, dp, seq, ack, flags, payload, pseudo, opts=b"", win=65535):
    off = (20 + len(opts)) // 4
    h = struct.pack("!HHIIHHHH", sp, dp, seq, ack, (off << 12) | flags, win, 0, 0) + opts
    c = csum(pseudo(6, len(h) + len(payload)) + h + payload)
    return h[:16] + struct.pack("!H", c) + h[18:] + payload


def icmp(t, code, rest, data):
    h = struct.pack("!BBH", t, code, 0) + rest + data
    return h[:2] + struct.pack("!H", csum(h)) + h[4:]


def icmp6(t, code, body, src, dst):
    h = struct.pack("!BBH", t, code, 0) + body
    c = csum(pseudo6(src, dst, 58, len(h)) + h)
    return h[:2] + struct.pack("!H", c) + h[4:]


def ipv6(src, dst, nh, payload, hops=64):
    return struct.pack("!IHBB", 0x60000000, len(payload), nh, hops) + ip6(src) + ip6(dst) + payload


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"


def pcap(path, link, packets, nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 262144, link)
    for i, p in enumerate(packets):
        out += struct.pack("<IIII", T0 + i, 1000 * i, len(p), len(p)) + p
    open(path, "wb").write(out)


S = "tests/fixtures/synthetic/"

# --- 802.11 with radiotap -------------------------------------------------


def radiotap(fields_present, fields, fcs=True):
    # present word 0 with EXT and RADIOTAP_NS, word 1 (radiotap namespace
    # again: an antenna signal per antenna), then the fields.
    body = fields
    hdr_len = 8 + 4 + len(body)
    return struct.pack("<BBHII", 0, 0, hdr_len, fields_present | 0xA0000000, 0x00000820) + body


def rt_fields(rate, freq, signal, ant_signal2, flags=0x10):
    # TSFT (8, aligned 8: header is 12 bytes so pad 4), flags, rate,
    # channel (aligned 2), dBm signal, antenna; then word-1 fields:
    # dBm signal, antenna.
    f = b"\0" * 4 + struct.pack("<Q", 123456789)
    f += struct.pack("<BB", flags, rate)
    f += struct.pack("<HH", freq, 0x00A0)
    f += struct.pack("<bB", signal, 0)
    f += struct.pack("<bB", ant_signal2, 1)
    return f


PRESENT0 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 11)


def wlan_beacon():
    fc = struct.pack("<H", 0x0080)
    hdr = fc + struct.pack("<H", 0) + BCAST + MAC_A + MAC_A + struct.pack("<H", 0x0010)
    fixed = struct.pack("<QHH", 987654321, 100, 0x0411)
    ies = b"\x00\x0efillyfoal-test"
    ies += b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
    ies += b"\x03\x01\x06"
    ies += b"\x05\x04\x00\x01\x00\x00"
    ies += b"\x07\x06XX\x20\x01\x0b\x14"
    rsn = struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
    rsn += struct.pack("<H", 1) + b"\x00\x0f\xac\x02" + struct.pack("<H", 0x000C)
    ies += bytes([48, len(rsn)]) + rsn
    ies += b"\x32\x04\x30\x48\x60\x6c"
    ies += b"\xdd\x07\x00\x50\xf2\x02\x00\x01\x00"
    frame = hdr + fixed + ies
    return frame + struct.pack("<I", zlib.crc32(frame))


def wlan_qos_data():
    fc = struct.pack("<H", 0x0188)  # QoS data, to DS
    hdr = fc + struct.pack("<H", 44) + MAC_A + MAC_B + BCAST + struct.pack("<H", 0x0020) + struct.pack("<H", 0x0000)
    q = struct.pack("!HHHHHH", 0x5151, 0x0100, 1, 0, 0, 0) + dns_name("www.example.com") + struct.pack("!HH", 1, 1)
    p4 = lambda proto, n: pseudo4("192.0.2.10", "192.0.2.1", proto, n)
    ip = ipv4("192.0.2.10", "192.0.2.1", 17, udp(40000, 53, q, p4))
    frame = hdr + b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + ip
    return frame + struct.pack("<I", zlib.crc32(frame))


def wlan_protected():
    fc = struct.pack("<H", 0x4288)  # QoS data, from DS, protected
    hdr = fc + struct.pack("<H", 44) + MAC_B + MAC_A + MAC_A + struct.pack("<H", 0x0030) + struct.pack("<H", 0x0000)
    ccmp = bytes([1, 0, 0, 0x20, 0, 0, 0, 0])
    frame = hdr + ccmp + bytes(range(32)) + b"\x11" * 8
    return frame + struct.pack("<I", zlib.crc32(frame))


def wlan_probe_req():
    fc = struct.pack("<H", 0x0040)
    hdr = fc + struct.pack("<H", 0) + BCAST + MAC_B + BCAST + struct.pack("<H", 0x0040)
    frame = hdr + b"\x00\x00" + b"\x01\x04\x02\x04\x0b\x16"
    return frame + struct.pack("<I", zlib.crc32(frame))


def wlan_ack():
    frame = struct.pack("<HH", 0x00D4, 0) + MAC_A
    return frame + struct.pack("<I", zlib.crc32(frame))


wl = [
    radiotap(PRESENT0, rt_fields(2, 2437, -42, -45)) + wlan_beacon(),
    radiotap(PRESENT0, rt_fields(108, 2437, -50, -51)) + wlan_qos_data(),
    radiotap(PRESENT0, rt_fields(108, 2437, -50, -52)) + wlan_protected(),
    radiotap(PRESENT0, rt_fields(4, 2437, -70, -71)) + wlan_probe_req(),
    radiotap(PRESENT0, rt_fields(4, 2437, -40, -41, flags=0x50)) + wlan_ack()[:-4] + b"\0\0\0\0",
]
pcap(S + "pcap/wlan-radiotap.pcap", 127, wl)

# --- BSD loopback (NULL, host order) and OpenBSD LOOP ---------------------

A, B = "192.0.2.10", "198.51.100.20"
p4 = lambda proto, n: pseudo4(A, B, proto, n)
r4 = lambda proto, n: pseudo4(B, A, proto, n)
syn_opts = b"\x02\x04\x05\xb4" + b"\x01\x03\x03\x07" + b"\x04\x02" + b"\x08\x0a" + struct.pack("!II", 1000, 0)
sack_opts = b"\x01\x01\x05\x12" + struct.pack("!IIII", 5000, 6000, 7000, 8000)
mptcp = b"\x1e\x0c\x00\x81" + bytes(8)  # MP_CAPABLE v0 with key
tfo = b"\x22\x0a" + bytes.fromhex("0102030405060708")
uto = b"\x1c\x04\x80\x05"
quote = ipv4(A, B, 17, udp(40001, 33434, b"", p4), ttl=1)[:28]
null = [
    struct.pack("<I", 2) + ipv4(A, B, 6, tcp(40000, 443, 1000, 0, 0x002, b"", p4, syn_opts)),
    struct.pack("<I", 2) + ipv4(B, A, 6, tcp(443, 40000, 9000, 1001, 0x010, b"", r4, sack_opts)),
    struct.pack("<I", 2) + ipv4(A, B, 6, tcp(40000, 443, 1001, 9001, 0x018, b"", p4, mptcp + tfo + uto + b"\x01\x01")),
    struct.pack("<I", 2) + ipv4(B, A, 1, icmp(11, 0, b"\0\0\0\0", quote)),
    struct.pack("<I", 30) + ipv6("2001:db8::1", "2001:db8::2", 58,
                                icmp6(128, 0, struct.pack("!HH", 7, 1) + b"ping", "2001:db8::1", "2001:db8::2")),
]
pcap(S + "pcap/loopback-null.pcap", 0, null)

loop = [struct.pack("!I", 2) + ipv4(A, B, 1, icmp(8, 0, struct.pack("!HH", 9, 1), b"openbsd"))]
pcap(S + "pcap/loop-openbsd.pcap", 108, loop)

# --- Raw IP: IPv4 options, IPv6 extension headers, tunnels -----------------

S6, D6 = "2001:db8::10", "2001:db8::20"
p6 = lambda proto, n: pseudo6(S6, D6, proto, n)
ts_opt = bytes([68, 12, 5, 0x01]) + ip4("192.0.2.1") + struct.pack("!I", 3600000)
lsrr = bytes([131, 11, 4]) + ip4("192.0.2.1") + ip4("192.0.2.2") + b"\x00"
raw = []
raw.append(ipv4(A, B, 1, icmp(8, 0, struct.pack("!HH", 1, 1), b"ts"), opts=ts_opt))
raw.append(ipv4(A, B, 1, icmp(8, 0, struct.pack("!HH", 1, 2), b"lsrr"), opts=lsrr))
# IPv6: hop-by-hop (router alert, PadN), routing (SRH, 2 segments),
# destination options (PadN), fragment (first fragment of UDP).
u = udp(5000, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + dns_name("example.com") + b"\x00\x01\x00\x01", p6)
frag = struct.pack("!BBHI", 17, 0, 0x0001, 0xABCDEF01)
dst = struct.pack("!BB", 44, 0) + b"\x01\x04\x00\x00\x00\x00"
srh = struct.pack("!BBBBBBH", 60, 4, 4, 1, 1, 0, 0) + ip6("2001:db8::30") + ip6(D6)
hbh = struct.pack("!BB", 43, 0) + b"\x05\x02\x00\x00" + b"\x01\x00"
raw.append(ipv6(S6, D6, 0, hbh + srh + dst + frag + u))
# A later fragment.
raw.append(ipv6(S6, D6, 44, struct.pack("!BBHI", 17, 0, 0x0100, 0xABCDEF01) + b"tail of the datagram"))
# AH then ICMPv6 echo; ESP.
ah = struct.pack("!BBHII", 58, 4, 0, 0x100, 1) + bytes(12)
raw.append(ipv6(S6, D6, 51, ah + icmp6(128, 0, struct.pack("!HH", 3, 1), S6, D6)))
raw.append(ipv4(A, B, 50, struct.pack("!II", 0x1234, 7) + bytes(24)))
# GRE (key, sequence) carrying IPv4/UDP; IPv6-in-IPv4.
inner = ipv4("10.0.0.1", "10.0.0.2", 17, udp(1, 2, b"x", lambda p, n: pseudo4("10.0.0.1", "10.0.0.2", p, n)))
raw.append(ipv4(A, B, 47, struct.pack("!HHII", 0x3000, 0x0800, 42, 1) + inner))
raw.append(ipv4(A, B, 41, ipv6(S6, D6, 58, icmp6(129, 0, struct.pack("!HH", 3, 1), S6, D6))))
# ICMPv6 router advertisement with options; packet too big quoting IPv6.
ra = struct.pack("!BBHII", 64, 0xC0, 1800, 0, 0)
ra += b"\x01\x01" + MAC_A
ra += b"\x05\x01\x00\x00" + struct.pack("!I", 1500)
ra += struct.pack("!BBBBIII", 3, 4, 64, 0xC0, 86400, 14400, 0) + ip6("2001:db8:1::")
ra += struct.pack("!BBHI", 25, 3, 0, 600) + ip6("2001:db8::53")
raw.append(ipv6("fe80::1", "ff02::1", 58, icmp6(134, 0, ra, "fe80::1", "ff02::1"), hops=255))
big = ipv6(D6, S6, 17, udp(53, 5000, b"y" * 40, lambda p, n: pseudo6(D6, S6, p, n)))
raw.append(ipv6("2001:db8::1", S6, 58, icmp6(2, 0, struct.pack("!I", 1280) + big, "2001:db8::1", S6)))
# SCTP INIT.
init = struct.pack("!BBHIIHHI", 1, 0, 20, 0x11111111, 65536, 10, 10, 1)
raw.append(ipv4(A, B, 132, struct.pack("!HHII", 5000, 38412, 0, 0) + init))
# DNS response with compression, mDNS-style cache flush, a TXT record,
# and a malformed message with a pointer loop.
q = dns_name("svc.example.com")
ans = b"\xc0\x0c" + struct.pack("!HHIH", 16, 0x8001, 120, 12) + b"\x05hello\x05world"
ans += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 6) + b"\x03www\xc0\x10"
msg = struct.pack("!HHHHHH", 0, 0x8400, 1, 2, 0, 0) + q + struct.pack("!HH", 255, 1) + ans
raw.append(ipv4(A, "224.0.0.251", 17, udp(5353, 5353, msg, lambda p, n: pseudo4(A, "224.0.0.251", p, n)), ttl=255))
bad = struct.pack("!HHHHHH", 0x6666, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
raw.append(ipv4(A, B, 17, udp(5555, 53, bad, p4)))
# TLS ClientHello split over two segments (the first holds the record
# header and part of the message), and HTTP with a JSON body.
ch_body = struct.pack("!H", 0x0303) + bytes(32) + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00"
sni = b"\x00\x00\x00\x10\x00\x0e\x00\x00\x0bexample.com"
grease = b"\x0a\x0a\x00\x00"
ext = grease + sni
ch_body += struct.pack("!H", len(ext)) + ext
hs = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body
rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
raw.append(ipv4(A, B, 6, tcp(40002, 443, 1, 1, 0x018, rec[:30], p4)))
raw.append(ipv4(A, B, 6, tcp(40002, 443, 31, 1, 0x018, rec[30:], p4)))
body = b'{"name": "fillyfoal test", "ok": true}\n'
req = b"POST /api HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body) + body
raw.append(ipv4(A, B, 6, tcp(40003, 80, 1, 1, 0x018, req, p4)))
pcap(S + "pcap/raw-tunnels.pcap", 101, raw)

# --- Ethernet odds and ends: 802.3/LLC (STP), SNAP, MPLS, VXLAN, EAPOL ---

stp = b"\x42\x42\x03" + bytes(35)
eth = [ether(bytes.fromhex("0180c2000000"), MAC_A, len(stp), stp) + bytes(60 - 14 - len(stp))]
snap = b"\xaa\xaa\x03\x00\x00\x00\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + MAC_A + ip4(A) + bytes(6) + ip4(B)
eth.append(ether(BCAST, MAC_A, len(snap), snap))
mpls = struct.pack("!II", (100 << 12) | 64, (200 << 12) | 0x100 | 63)
eth.append(ether(MAC_B, MAC_A, 0x8847, mpls + ipv4(A, B, 1, icmp(8, 0, struct.pack("!HH", 5, 1), b"mpls"))))
inner_eth = ether(MAC_B, MAC_A, 0x0800, ipv4("10.0.0.1", "10.0.0.2", 1, icmp(8, 0, struct.pack("!HH", 6, 1), b"vx")))
vx = struct.pack("!BxxxI", 0x08, 5001 << 8) + inner_eth
eth.append(ether(MAC_B, MAC_A, 0x0800, ipv4(A, B, 17, udp(54321, 4789, vx, p4))))
eth.append(ether(bytes.fromhex("0180c2000003"), MAC_A, 0x888E, struct.pack("!BBH", 2, 1, 0)))
pcap(S + "pcap/ethernet-misc.pcap", 1, eth)

# --- pcapng: big-endian section with every block type, then a little-endian
# one --------------------------------------------------------------------


def opt(e, code, val):
    pad = (-len(val)) % 4
    return struct.pack(e + "HH", code, len(val)) + val + b"\0" * pad


def block(e, kind, body):
    body += b"\0" * ((-len(body)) % 4)
    n = len(body) + 12
    return struct.pack(e + "II", kind, n) + body + struct.pack(e + "I", n)


def ng_section(e, packet, first):
    out = block(e, 0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1)
                + opt(e, 2, b"fixture hardware") + opt(e, 3, b"fillyfoal OS") + opt(e, 4, b"synthetic.py")
                + opt(e, 2988, struct.pack(e + "I", 32473) + b"custom text") + opt(e, 0, b""))
    # Interface 0: binary resolution 2^-20 s, offset +3600 s.
    out += block(e, 1, struct.pack(e + "HHI", 1, 0, 0)
                 + opt(e, 2, b"eth0") + opt(e, 9, b"\x94") + opt(e, 14, struct.pack(e + "q", 3600))
                 + opt(e, 10, struct.pack(e + "i", 0)) + opt(e, 11, b"\x00udp port 53")
                 + opt(e, 13, b"\x00") + opt(e, 7, bytes.fromhex("0200000000000001"))
                 + opt(e, 5, ip6("2001:db8::10") + b"\x40") + opt(e, 0, b""))
    ts = (first + 0) << 20 | 0x80000
    hi, lo = ts >> 32, ts & 0xFFFFFFFF
    epb_opts = (opt(e, 2, struct.pack(e + "I", 0x0000_0001 | (1 << 2)))
                + opt(e, 3, b"\x02" + struct.pack(e + "I", zlib.crc32(packet)))
                + opt(e, 4, struct.pack(e + "Q", 0)) + opt(e, 5, struct.pack(e + "Q", 99))
                + opt(e, 6, struct.pack(e + "I", 1)) + opt(e, 7, b"\x02" + struct.pack(e + "Q", 2))
                + opt(e, 8, struct.pack(e + "II", 1234, 5678)) + opt(e, 1, b"enhanced packet") + opt(e, 0, b""))
    out += block(e, 6, struct.pack(e + "IIIII", 0, hi, lo, len(packet), len(packet)) + packet + b"\0" * ((-len(packet)) % 4) + epb_opts)
    out += block(e, 3, struct.pack(e + "I", len(packet)) + packet)
    out += block(e, 2, struct.pack(e + "HHIIII", 0, 0, hi, lo + 1, len(packet), len(packet)) + packet + b"\0" * ((-len(packet)) % 4) + opt(e, 2, struct.pack(e + "I", 2)) + opt(e, 0, b""))
    nrb = struct.pack(e + "HH", 1, 16) + ip4("192.0.2.1") + b"ns.example\0\0"
    nrb += struct.pack(e + "HH", 2, 32) + ip6("2001:db8::53") + b"ns6.example.net\0"
    nrb += struct.pack(e + "HH", 0, 0)
    out += block(e, 4, nrb + opt(e, 2, b"ns.example") + opt(e, 3, ip4("192.0.2.1")) + opt(e, 0, b""))
    out += block(e, 5, struct.pack(e + "III", 0, hi, lo + 2)
                 + opt(e, 2, struct.pack(e + "II", hi, lo)) + opt(e, 3, struct.pack(e + "II", hi, lo + 2))
                 + opt(e, 4, struct.pack(e + "Q", 3)) + opt(e, 5, struct.pack(e + "Q", 0))
                 + opt(e, 6, struct.pack(e + "Q", 3)) + opt(e, 7, struct.pack(e + "Q", 0))
                 + opt(e, 8, struct.pack(e + "Q", 3)) + opt(e, 0, b""))
    keylog = b"CLIENT_RANDOM 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 000102030405060708090a0b0c0d0e0f\n"
    out += block(e, 10, struct.pack(e + "II", 0x544C534B, len(keylog)) + keylog)
    out += block(e, 9, b"__REALTIME_TIMESTAMP=1791600000000000\nMESSAGE=fillyfoal test\n")
    out += block(e, 0x0BAD, struct.pack(e + "I", 32473) + b"custom block data")
    out += block(e, 0x0000_0BAE, b"unknown block type")
    return out


dnsq = struct.pack("!HHHHHH", 0x0101, 0x0100, 1, 0, 0, 0) + dns_name("example.com") + struct.pack("!HH", 1, 1)
pkt = ether(MAC_B, MAC_A, 0x0800, ipv4(A, B, 17, udp(40000, 53, dnsq, p4)))
ng = ng_section(">", pkt, T0) + ng_section("<", pkt, T0 + 10)
open(S + "pcapng/big-endian.pcapng", "wb").write(ng)
print("ok")
