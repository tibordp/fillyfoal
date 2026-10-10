# Tools for the disk-image fixtures (qcow2, VMDK, VHD/VHDX, MBR/GPT, ISO 9660,
# UDF, LUKS). Built once and reused by make-fixtures.sh:
#   docker build -t fillyfoal-disk-tools tests/data/disk
FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    qemu-utils xorriso udftools cryptsetup-bin gdisk fdisk mtools dosfstools \
    genisoimage python3 \
 && rm -rf /var/lib/apt/lists/*
