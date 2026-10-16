"""A small neutral packet capture for nfpcapd to turn into flows.

    python3 -I tests/data/nfdump/flows_pcap.py /tmp/fixtures/nfdump/flows.pcap

Documentation addresses only (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32),
locally administered MACs, fixed timestamps (2024-01-01 12:00 UTC on).
Flows: a TCP connection (SYN, data, FIN, both ways), a DNS-like UDP
exchange, an ICMP echo and reply, and a UDP flow over IPv6.
"""

import struct
import sys

T0 = 1_704_110_400  # 2024-01-01 12:00:00 UTC
A = bytes([192, 0, 2, 10])
B = bytes([198, 51, 100, 20])
C = bytes([192, 0, 2, 53])
A6 = bytes.fromhex("20010db8000000000000000000000010")
B6 = bytes.fromhex("20010db8000000000000000000000020")
MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(src, dst, proto, payload):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), proto, 64, src, dst) + payload


def tcp(sport, dport, seq, ack, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data


def udp(sport, dport, data):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


def eth(src, dst, ethertype, payload):
    return dst + src + struct.pack("!H", ethertype) + payload


packets = []


def add(t, frame):
    packets.append((t, frame))


# TCP: 192.0.2.10:49152 -> 198.51.100.20:80
SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
seq = [
    (0.000, True, SYN, b""),
    (0.010, False, SYN | ACK, b""),
    (0.011, True, ACK, b""),
    (0.012, True, PSH | ACK, req),
    (0.030, False, PSH | ACK, resp),
    (0.031, True, FIN | ACK, b""),
    (0.040, False, FIN | ACK, b""),
    (0.041, True, ACK, b""),
]
for i, (dt, out, flags, data) in enumerate(seq):
    seg = tcp(49152, 80, 1000 + i, 2000 + i, flags, data) if out else tcp(80, 49152, 2000 + i, 1000 + i, flags, data)
    ip = ipv4(A, B, 6, seg, 100 + i) if out else ipv4(B, A, 6, seg, 200 + i)
    add(T0 + dt, eth(MAC_A, MAC_B, 0x0800, ip) if out else eth(MAC_B, MAC_A, 0x0800, ip))

# UDP: a DNS-shaped query and answer to 192.0.2.53:53
q = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
r = bytes.fromhex("123481800001000100000000076578616d706c6503636f6d0000010001c00c000100010000012c0004c0000201")
add(T0 + 1.0, eth(MAC_A, MAC_B, 0x0800, ipv4(A, C, 17, udp(50000, 53, q), 300)))
add(T0 + 1.004, eth(MAC_B, MAC_A, 0x0800, ipv4(C, A, 17, udp(53, 50000, r), 301)))

# ICMP echo request and reply
for i in range(2):
    echo = struct.pack("!BBHHH", 8, 0, 0, 0x77, i + 1) + b"fillyfoal-ping!!"
    echo = echo[:2] + struct.pack("!H", csum(echo)) + echo[4:]
    add(T0 + 2.0 + i, eth(MAC_A, MAC_B, 0x0800, ipv4(A, B, 1, echo, 400 + i)))
    reply = b"\0" + echo[1:2] + b"\0\0" + echo[4:]
    reply = reply[:2] + struct.pack("!H", csum(reply)) + reply[4:]
    add(T0 + 2.001 + i, eth(MAC_B, MAC_A, 0x0800, ipv4(B, A, 1, reply, 500 + i)))

# UDP over IPv6
for i in range(3):
    add(T0 + 3.0 + i * 0.1, eth(MAC_A, MAC_B, 0x86DD, ipv6(A6, B6, 17, udp(40000, 4500, b"payload %d" % i))))

packets.sort(key=lambda p: p[0])
out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
for t, frame in packets:
    sec = int(t)
    usec = round((t - sec) * 1_000_000)
    out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
with open(sys.argv[1], "wb") as f:
    f.write(out)
