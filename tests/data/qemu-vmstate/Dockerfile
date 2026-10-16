# Tools for the qemu-vmstate, libvirt-save and criu-image fixtures.
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        qemu-system-x86 qemu-system-arm qemu-system-sparc qemu-utils socat libvirt-daemon libvirt-daemon-driver-qemu libvirt-clients \
        criu python3-pycriu zstd xz-utils \
    && rm -rf /var/lib/apt/lists/*
