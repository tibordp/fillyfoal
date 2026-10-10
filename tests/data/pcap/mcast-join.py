"""Joins an IPv4 and an IPv6 multicast group on eth0, so the kernel sends an
IGMPv3 report (IPv4 router-alert option) and an MLDv2 report (IPv6
hop-by-hop header) for the fillyfoal capture fixtures."""
import socket
import struct
import time

idx = socket.if_nametoindex("eth0")
s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s4.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
              socket.inet_aton("239.1.2.3") + socket.inet_aton("10.99.0.3"))
s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
              socket.inet_pton(socket.AF_INET6, "ff15::1234") + struct.pack("@I", idx))
time.sleep(1)
