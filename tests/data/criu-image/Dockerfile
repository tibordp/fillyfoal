# CRIU 4.2 for the raw-data fixtures (make-raw.sh): CRIU 4.1.1 (Debian 13)
# cannot dump TCP sockets on Linux 6.16 and later, where getsockopt
# SO_PASSCRED fails on them.
FROM debian:sid
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        criu python3 \
    && rm -rf /var/lib/apt/lists/*
