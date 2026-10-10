FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends tshark tcpdump dnsmasq openssl python3 curl dnsutils iputils-ping busybox snmp bsdutils iproute2 ca-certificates unbound chrony && rm -rf /var/lib/apt/lists/*
