#!/bin/sh
# Rebuilds tests/fixtures/external/proxmox-vma/{vm,config}.vma with `vma create`
# from pve-qemu-kvm 9.2.0-8 (Proxmox's bookworm repository): a VM config
# and two raw disks, a 4 MiB FAT12 volume with one text file and a 1 MiB
# disk that is zero but for one sector (vm.vma); a vzdump-style config
# with a snapshot section, a firewall config and an all-zero 1 MiB disk
# (config.vma). Build the image first (see
# tests/data/proxmox/Dockerfile), then:
#
#   sh tests/data/proxmox-vma/make-external.sh [scratch dir]
#
# The archive's UUID and backup time differ per run. The scratch directory
# also receives the source disks, to check a reassembly against.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/proxmox-vma}
mkdir -p "$work"
docker run --rm --platform linux/amd64 --hostname fillyfoal -v "$work:/out" -v "$here:/data:ro" \
  fillyfoal-proxmox:bookworm bash /data/inner.sh
mkdir -p "$repo/tests/fixtures/external/proxmox-vma"
cp "$work/vm.vma" "$repo/tests/fixtures/external/proxmox-vma/vm.vma"
cp "$work/config.vma" "$repo/tests/fixtures/external/proxmox-vma/config.vma"
