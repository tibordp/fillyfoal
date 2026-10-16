"""Sends one NetFlow v5 packet with the flows of flows_pcap.py (IPv4 only)
to a collector on the loopback, for nfcapd 1.6 to write (see
make_nfdump16.sh).

    python3 -I netflow_v5.py [port]
"""

import socket
import struct
import sys

UNIX = 1_704_110_410  # 2024-01-01 12:00:10 UTC
UPTIME = 100_000  # ms since the exporter booted, at UNIX


def ip(s):
    return socket.inet_aton(s)


def at(seconds_before_ms):
    return UPTIME - seconds_before_ms


A, B, C = "192.0.2.10", "198.51.100.20", "192.0.2.53"
# src, dst, next hop, in, out, packets, bytes, first, last, sport, dport, flags, proto, tos, src AS, dst AS, masks
flows = [
    (A, B, "192.0.2.1", 1, 2, 4, 197, at(10_000), at(9_969), 49152, 80, 0x1B, 6, 0, 64496, 64511, 24, 24),
    (B, A, "198.51.100.1", 2, 1, 4, 203, at(9_990), at(9_960), 80, 49152, 0x1B, 6, 0, 64511, 64496, 24, 24),
    (A, C, "192.0.2.1", 1, 3, 1, 57, at(9_000), at(9_000), 50000, 53, 0, 17, 0, 64496, 64496, 24, 24),
    (C, A, "192.0.2.1", 3, 1, 1, 73, at(8_996), at(8_996), 53, 50000, 0, 17, 0, 64496, 64496, 24, 24),
    (A, B, "192.0.2.1", 1, 2, 2, 88, at(8_000), at(7_000), 0, 0x0800, 0, 1, 0, 64496, 64511, 24, 24),
    (B, A, "198.51.100.1", 2, 1, 2, 88, at(7_999), at(6_999), 0, 0x0000, 0, 1, 0, 64511, 64496, 24, 24),
]

pkt = struct.pack("!HHIIIIBBH", 5, len(flows), UPTIME, UNIX, 0, 0, 0, 1, 0)
for f in flows:
    src, dst, nh, i, o, pk, by, first, last, sp, dp, fl, pr, tos, sas, das, sm, dm = f
    pkt += struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", ip(src), ip(dst), ip(nh), i, o, pk, by, first, last,
                       sp, dp, 0, fl, pr, tos, sas, das, sm, dm, 0)

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9995
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt, ("127.0.0.1", port))
