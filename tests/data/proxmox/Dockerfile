# Proxmox tools for the pxar, VMA and PBS blob fixtures: Debian bookworm
# (amd64, emulated on arm64 hosts) with Proxmox's no-subscription
# repositories. Build with
#
#   docker build --platform linux/amd64 -t fillyfoal-proxmox:bookworm tests/data/proxmox
#
# Used versions: proxmox-backup-client 3.4.9-1, proxmox-backup-server
# 3.4.9-2, pve-qemu-kvm 9.2.0-8.
FROM amd64/debian:bookworm-slim
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends wget ca-certificates zstd attr acl dosfstools mtools >/dev/null \
 && wget -q https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg \
 && echo "deb http://download.proxmox.com/debian/pbs bookworm pbs-no-subscription" > /etc/apt/sources.list.d/pbs.list \
 && echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve.list \
 && apt-get update -qq \
 && (apt-get install -y -qq --no-install-recommends proxmox-backup-client proxmox-backup-server pve-qemu-kvm >/dev/null 2>&1 || true) \
 && command -v pxar && command -v vma && command -v proxmox-backup-client
