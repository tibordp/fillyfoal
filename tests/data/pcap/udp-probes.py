"""Sends one SSDP M-SEARCH, one mDNS query and one LLMNR query (fillyfoal capture fixtures)."""
import socket
import struct


def dns_query(qid, name, qtype, flags=0):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)


def send(data, addr, port, ttl=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    s.sendto(data, (addr, port))
    s.close()


send(
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
    "239.255.255.250",
    1900,
)
send(dns_query(0, "fillyfoal-test.local", 1), "224.0.0.251", 5353, 255)
send(dns_query(0x4242, "fillyfoal-test", 28), "224.0.0.252", 5355)
