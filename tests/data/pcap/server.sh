#!/bin/bash
# Server side of the fillyfoal capture fixtures: DNS (unbound), DHCP
# (dnsmasq), HTTP (python http.server), TLS (openssl s_server), NTP (chrony),
# on an isolated Docker network. Run in the fillyfoal-pcap-tools image.
set -eu
mkdir -p /srv/www /srv/tls
# VLAN peers for the client's tagged pings (needs NET_ADMIN and 8021q).
if ip link add link eth0 name eth0.10 type vlan id 10 2>/dev/null; then
    ip link add link eth0 name eth0.100 type vlan proto 802.1ad id 100
    ip link add link eth0.100 name eth0.100.20 type vlan id 20
    ip addr add 10.10.0.2/24 dev eth0.10
    ip addr add 10.20.0.2/24 dev eth0.100.20
    ip link set eth0.10 up; ip link set eth0.100 up; ip link set eth0.100.20 up
fi
printf '<!doctype html>\n<title>fillyfoal test</title>\n<p>Hello from the fillyfoal capture fixtures.</p>\n' > /srv/www/index.html
printf '{"name": "fillyfoal test", "ok": true}\n' > /srv/www/data.json

# Throwaway P-256 certificate (small, so the TLS 1.2 Certificate message fits one segment).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout /srv/tls/key.pem -out /srv/tls/cert.pem -days 3650 \
    -subj "/CN=www.example.com/O=fillyfoal test" \
    -addext "subjectAltName=DNS:www.example.com" 2>/dev/null

cat > /etc/unbound/unbound.conf <<'EOF'
server:
    interface: 0.0.0.0
    interface: ::0
    access-control: 0.0.0.0/0 allow
    access-control: ::/0 allow
    do-not-query-localhost: yes
    username: ""
    chroot: ""
    use-syslog: no
    local-zone: "example.com." static
    local-data: "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 2026101001 7200 3600 1209600 300"
    local-data: "example.com. 3600 IN NS ns.example.com."
    local-data: "example.com. 3600 IN MX 10 mail.example.com."
    local-data: "example.com. 3600 IN TXT \"v=spf1 -all\""
    local-data: "ns.example.com. 3600 IN A 10.99.0.2"
    local-data: "www.example.com. 300 IN A 10.99.0.2"
    local-data: "www.example.com. 300 IN AAAA fd99::2"
    local-data: "www.example.com. 300 IN HTTPS 1 . alpn=h2,http/1.1 ipv4hint=10.99.0.2"
    local-data: "alias.example.com. 300 IN CNAME www.example.com."
    local-data: "_http._tcp.example.com. 300 IN SRV 0 5 80 www.example.com."
    local-data: "example.com. 3600 IN CAA 0 issue \"ca.example.net\""
    local-zone: "99.10.in-addr.arpa." static
    local-data-ptr: "10.99.0.2 www.example.com."
    remote-control:
    control-enable: no
EOF
unbound -d &

dnsmasq --port=0 --dhcp-range=10.99.0.100,10.99.0.150,255.255.255.0,1h \
    --dhcp-option=option:router,10.99.0.1 --dhcp-option=option:dns-server,10.99.0.2 \
    --domain=example.com --no-daemon --log-dhcp &

cat > /etc/chrony/chrony.conf <<'EOF'
local stratum 8
allow all
EOF
chronyd -d -x &

python3 -m http.server 80 --directory /srv/www &
openssl s_server -accept 443 -cert /srv/tls/cert.pem -key /srv/tls/key.pem -www -alpn h2,http/1.1 -quiet &
wait
