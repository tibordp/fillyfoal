set -e
# Runs inside fillyfoal-proxmox:bookworm (tests/data/proxmox/Dockerfile)
# with host name "fillyfoal"; writes to /out. See make-external.sh.
T=/tmp/build
rm -rf $T && mkdir -p $T && cd $T
# Disk 1: a 4 MiB FAT12 volume holding one text file (more than one
# extent's 59 clusters, so the archive has two extents).
truncate -s 4M disk.raw
mkfs.fat -F 12 -n FILLYFOAL -i 12345678 disk.raw >/dev/null
printf 'A text file inside a FAT volume inside a VMA archive.\n' > inside.txt
touch -d '2026-01-02 03:04:05 UTC' inside.txt
mcopy -m -i disk.raw inside.txt ::/INSIDE.TXT
# Disk 2: 1 MiB, zero but for one sector at 320 KiB.
truncate -s 1M small.raw
printf 'second disk: sparse except for this sector\n' | dd of=small.raw bs=1 seek=327680 conv=notrunc 2>/dev/null
cat > qemu-server.conf <<'CONF'
boot: order=scsi0
cores: 1
memory: 512
name: fillyfoal
scsi0: local:100/vm-100-disk-0.raw,size=4M
scsi1: local:100/vm-100-disk-1.raw,size=1M
CONF
rm -f /out/vm.vma
vma create /out/vm.vma -c qemu-server.conf -d format=raw:drive-scsi0=disk.raw -d format=raw:drive-scsi1=small.raw 2>&1 | { grep -v progress || true; }
vma verify /out/vm.vma -v 2>&1 | { grep -v progress || true; }
# config.vma: the configuration as vzdump writes it (a %-encoded
# description, a #qmdump#map line) plus a snapshot section (vzdump drops
# those, other writers may not), a firewall configuration, and a 1 MiB
# disk of zeros (every cluster an all-zero block info, no data).
truncate -s 1M zero.raw
printf '%s\n' '#Web server%3A neutral test VM' '#second description line' \
  'boot: order=scsi0' 'cores: 1' 'memory: 512' 'name: fillyfoal' 'parent: s1' \
  'scsi0: local-lvm:vm-100-disk-0,size=1M' '#qmdump#map:scsi0:drive-scsi0:local-lvm:raw:' \
  '' '[s1]' 'boot: order=scsi0' 'cores: 1' 'memory: 256' 'name: fillyfoal' \
  'scsi0: local-lvm:vm-100-disk-0,size=1M' 'snaptime: 1767323045' > qemu-server.conf
printf '%s\n' '[OPTIONS]' 'enable: 1' '' '[RULES]' 'IN ACCEPT -p tcp -dport 22' \
  'IN SSH(ACCEPT) -i net0' > qemu-server.fw
rm -f /out/config.vma
vma create /out/config.vma -c qemu-server.conf -c qemu-server.fw -d format=raw:drive-scsi0=zero.raw 2>&1 | { grep -v progress || true; }
vma verify /out/config.vma -v 2>&1 | { grep -v progress || true; }
# For checking the dissector's reassembly (not fixtures).
cp disk.raw small.raw /out/
dpkg-query -W pve-qemu-kvm
