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
# For checking the dissector's reassembly (not fixtures).
cp disk.raw small.raw /out/
dpkg-query -W pve-qemu-kvm
