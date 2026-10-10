#!/bin/bash
# Client side of the fillyfoal capture fixtures. Captures on this container's
# own interface on an isolated (--internal) Docker network; writes to /out.
set -u
S=10.99.0.2
S6=fd99::2
OUT=/out
mkdir -p $OUT

start() { # file, tcpdump args...
    local f=$1; shift
    tcpdump -U -s 0 -w "$OUT/$f" "$@" 2>/dev/null &
    TCPDUMP=$!
    sleep 1
}
stop() {
    sleep 1
    kill -INT $TCPDUMP; wait $TCPDUMP 2>/dev/null
}

# DNS over UDP and TCP against unbound.
start dns.pcap -i eth0 port 53
for q in "www.example.com A" "www.example.com AAAA" "example.com MX" "example.com TXT" \
         "example.com NS" "example.com SOA" "_http._tcp.example.com SRV" "alias.example.com A" \
         "www.example.com HTTPS" "example.com CAA" "missing.example.com A"; do
    dig +tries=1 +time=2 @$S $q > /dev/null
done
dig +tries=1 -x $S @$S > /dev/null
dig +tcp +tries=1 @$S www.example.com A > /dev/null
stop

# HTTP/1.1 with keep-alive: two requests on one connection, then a 404.
start http.pcap -i eth0 tcp port 80
curl -s -o /dev/null -o /dev/null --resolve www.example.com:80:$S \
    http://www.example.com/index.html http://www.example.com/data.json
curl -s -o /dev/null --resolve www.example.com:80:$S -H 'Accept: text/html' http://www.example.com/missing
stop

# TLS 1.3 and TLS 1.2 handshakes (key log kept for the pcapng secrets block).
tls() { # version flag
    printf 'GET / HTTP/1.0\r\n\r\n' | timeout 5 openssl s_client -connect $S:443 \
        -servername www.example.com -alpn h2,http/1.1 -groups x25519:P-256 $1 \
        -keylogfile $OUT/keylog.txt -ign_eof > /dev/null 2>&1
}
start tls13.pcap -i eth0 tcp port 443
tls -tls1_3
stop
start tls12.pcap -i eth0 tcp port 443
tls -tls1_2
stop

# ICMP and ICMPv6: echo, fragmented echo, record-route option; NDP and ARP
# appear because the neighbour caches are flushed first.
ip neigh flush all
start icmp.pcap -i eth0 icmp or icmp6 or arp or igmp or 'ip[6:2] & 0x3fff != 0' or 'ip6[6] == 44' or 'ip6[6] == 0'
ping -c 2 -i 0.2 $S > /dev/null
ping -c 1 -s 1600 $S > /dev/null
ping -c 1 -R $S > /dev/null
ping -6 -c 2 -i 0.2 $S6 > /dev/null
ping -6 -c 1 -s 1600 $S6 > /dev/null
python3 /work/mcast-join.py
stop

# Assorted UDP: DHCP, NTP, syslog, SSDP, mDNS, LLMNR, SNMP, QUIC.
ip route add 224.0.0.0/4 dev eth0 2>/dev/null
start udp.pcap -i eth0 udp or icmp
busybox udhcpc -i eth0 -n -q -f -s /bin/true > /dev/null 2>&1
chronyd -Q -t 3 "server $S iburst maxsamples 1" > /dev/null 2>&1
logger -n $S -P 514 -d -t fillyfoal "test message from the capture fixtures"
python3 /work/udp-probes.py
snmpget -v2c -c public -r 0 -t 1 $S 1.3.6.1.2.1.1.1.0 > /dev/null 2>&1
curl -s -k --http3-only --max-time 2 --resolve www.example.com:443:$S https://www.example.com/ > /dev/null 2>&1
stop

# Linux cooked captures on the "any" device.
start sll2.pcap -i any icmp
ping -c 2 -i 0.2 $S > /dev/null
stop
start sll.pcap -i any -y LINUX_SLL icmp
ping -c 2 -i 0.2 $S > /dev/null
stop

# Nanosecond timestamps.
start nano.pcap -i eth0 --time-stamp-precision=nano icmp
ping -c 2 -i 0.2 $S > /dev/null
stop

# VLAN tags: 802.1Q, and 802.1ad outer + 802.1Q inner (QinQ).
if ip link add link eth0 name eth0.10 type vlan id 10 2>/dev/null; then
    ip link add link eth0 name eth0.100 type vlan proto 802.1ad id 100
    ip link add link eth0.100 name eth0.100.20 type vlan id 20
    ip addr add 10.10.0.3/24 dev eth0.10
    ip addr add 10.20.0.3/24 dev eth0.100.20
    ip link set eth0.10 up; ip link set eth0.100 up; ip link set eth0.100.20 up
    sleep 3
    start vlan.pcap -i eth0 -n vlan or '(ether[12:2] = 0x88a8)'
    ping -c 1 -W 1 10.10.0.2 > /dev/null
    ping -c 1 -W 1 10.20.0.2 > /dev/null
    stop
fi

# pcapng from dumpcap (interface options, statistics block), then tshark
# with name resolution blocks and editcap with a decryption secrets block.
mkdir -p /root/.config/wireshark
printf '10.99.0.2\twww.example.com\nfd99::2\twww.example.com\n' > /root/.config/wireshark/hosts
dumpcap -q -i eth0 -f 'tcp port 443' -i lo -f icmp -w $OUT/dumpcap.pcapng 2>/dev/null &
D=$!
sleep 2
rm -f $OUT/keylog.txt
tls -tls1_3
ping -c 1 127.0.0.1 > /dev/null
sleep 1
kill -INT $D; wait $D 2>/dev/null
editcap --inject-secrets tls,$OUT/keylog.txt -a "4:Client Hello, keys in the secrets block" \
    $OUT/dumpcap.pcapng $OUT/tls-secrets.pcapng
# Name resolution blocks are written only for names used in printed output (-P).
tshark -r $OUT/dns.pcap -P -N dn -W n -F pcapng -w $OUT/names.pcapng > /dev/null 2>&1
tshark -r $OUT/sll2.pcap -F pcapng -w $OUT/sll2.pcapng
tshark -r $OUT/vlan.pcap -F pcapng -w $OUT/vlan.pcapng
cat $OUT/sll2.pcapng $OUT/vlan.pcapng > $OUT/sections.pcapng
# Keep only the OS name in shb_os / if_os (not the host's kernel release).
for f in dumpcap tls-secrets names sections; do
    python3 /work/scrub-pcapng.py $OUT/$f.pcapng $OUT/$f.scrubbed.pcapng
    mv $OUT/$f.scrubbed.pcapng $OUT/$f.pcapng
    capinfos -M $OUT/$f.pcapng | head -12
done
echo done
