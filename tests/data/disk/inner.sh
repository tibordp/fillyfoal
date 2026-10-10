#!/bin/sh
# Runs inside the fillyfoal-disk-tools container (see make-fixtures.sh), in
# /w. Writes the raw images to /w/out; make-fixtures.sh post-processes and
# compresses them.
set -eu
export SOURCE_DATE_EPOCH=1700000000
export TZ=UTC
OUT=/w/out
rm -rf "$OUT" /tmp/src
mkdir -p "$OUT" /tmp/src
# Work on the container's own file system (device nodes, sparse files).
cd /tmp/src

# A small FAT volume used as the content of the virtual disks.
printf 'hello from fillyfoal\n' > hello.txt
seq 1 60 > numbers.txt
truncate -s 256K fat.img
mkfs.fat -n FILLYFOAL -i 12345678 fat.img > /dev/null
mcopy -i fat.img hello.txt numbers.txt ::

# ---------------------------------------------------------------- qcow2
# v3 (compat 1.1): a snapshot, a persistent bitmap, a zero cluster, a
# compressed cluster, clusters written after the snapshot (copy on write).
qemu-img convert -f raw -O qcow2 -o compat=1.1,cluster_size=4096 fat.img $OUT/qemu-v3.qcow2
qemu-io -c "write -P 0x5a 128k 4k" -c "write -z 160k 4k" \
        -c "write -c -P 0x33 192k 4k" $OUT/qemu-v3.qcow2 > /dev/null
qemu-img snapshot -c first $OUT/qemu-v3.qcow2
qemu-io -c "write -P 0x77 208k 4k" -c "write -P 0x78 128k 512" $OUT/qemu-v3.qcow2 > /dev/null
qemu-img bitmap --add $OUT/qemu-v3.qcow2 dirty0

# QCOW version 1, compressed.
# (qemu-img exits with 1 after the final empty compressed write, which the
# qcow driver refuses; the image is complete, as the comparison shows.)
qemu-img convert -f raw -O qcow -c fat.img $OUT/qemu-v1.qcow || true
qemu-img compare -q $OUT/qemu-v1.qcow fat.img

# v2 (compat 0.10) overlay on a backing file (backing format extension).
qemu-img convert -f raw -O qcow2 -o compat=0.10,cluster_size=4096 fat.img $OUT/base.qcow2
(cd $OUT && qemu-img create -q -f qcow2 -o compat=0.10,cluster_size=4096 -b base.qcow2 -F qcow2 \
        qemu-v2-backing.qcow2 &&
 qemu-io -c "write -P 0x11 4k 8k" -c "write -c -P 0x22 64k 4k" qemu-v2-backing.qcow2 > /dev/null &&
 rm base.qcow2)

# Extended L2 entries (32 subclusters per cluster) and zstd compression.
qemu-img create -q -f qcow2 -o extended_l2=on,cluster_size=16k,compression_type=zstd \
        $OUT/qemu-extl2-zstd.qcow2 256k
qemu-io -c "write -P 0x41 0 1k" -c "write -P 0x42 3k 1k" -c "write -z 8k 1k" \
        -c "write -c -P 0x43 64k 16k" -c "write -z 128k 16k" \
        $OUT/qemu-extl2-zstd.qcow2 > /dev/null

# LUKS encryption (the LUKS header lives in a qcow2 cluster).
qemu-img create -q -f qcow2 --object secret,id=sec0,data=fillyfoal \
        -o encrypt.format=luks,encrypt.key-secret=sec0,encrypt.iter-time=10,cluster_size=4096 \
        $OUT/qemu-luks.qcow2 64k

# External data file (raw).
qemu-img create -q -f qcow2 -o data_file=qemu-datafile.raw,data_file_raw=on,cluster_size=4096 \
        $OUT/qemu-datafile.qcow2 64k
rm -f $OUT/qemu-datafile.raw

# ---------------------------------------------------------------- VMDK
qemu-img convert -f raw -O vmdk -o subformat=monolithicSparse fat.img $OUT/qemu-monolithic-sparse.vmdk
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized fat.img $OUT/qemu-stream-optimized.vmdk
mkdir -p twogb
qemu-img convert -f raw -O vmdk -o subformat=twoGbMaxExtentSparse,adapter_type=lsilogic fat.img twogb/qemu-twogb.vmdk
cp twogb/qemu-twogb.vmdk $OUT/qemu-twogb.vmdk
cp twogb/qemu-twogb-s001.vmdk $OUT/qemu-twogb-s001.vmdk
mkdir -p flat
qemu-img convert -f raw -O vmdk -o subformat=monolithicFlat,hwversion=6 fat.img flat/qemu-flat.vmdk
cp flat/qemu-flat.vmdk $OUT/qemu-flat.vmdk
# VMware's stream layout (markers, tables at the end): synthetic, checked
# against its source by QEMU.
python3 /data/vmdk-stream.py fat.img $OUT/stream-markers.vmdk
qemu-img compare -q -f vmdk -F raw $OUT/stream-markers.vmdk fat.img

# ---------------------------------------------------------------- VHD, VHDX
qemu-img convert -f raw -O vpc -o subformat=dynamic fat.img $OUT/qemu-dynamic.vhd
qemu-img convert -f raw -O vpc -o subformat=fixed fat.img $OUT/qemu-fixed.vhd
python3 /data/vhd-diff.py $OUT/differencing.vhd
python3 /data/vhdx-diff.py $OUT/differencing.vhdx
qemu-img convert -f raw -O vhdx -o subformat=dynamic,block_size=1M fat.img $OUT/qemu-dynamic.vhdx
qemu-io -c "write -P 0x66 192k 4k" $OUT/qemu-dynamic.vhdx > /dev/null

# ---------------------------------------------------------------- MBR, GPT
truncate -s 2M $OUT/sfdisk-extended.img
sfdisk -q --no-reread --no-tell-kernel $OUT/sfdisk-extended.img <<'EOT'
label: dos
label-id: 0x0f11f0a1
start=64, size=1024, type=c, bootable
start=1100, size=400, type=83
start=1536, size=2400, type=5
start=1600, size=512, type=82
start=2200, size=600, type=83
start=2900, size=900, type=7
EOT
mformat -i $OUT/sfdisk-extended.img@@32768 -T 1024 -h 16 -s 32 -v PART1 -N 0x0badcafe ::
mcopy -i $OUT/sfdisk-extended.img@@32768 hello.txt ::

truncate -s 2M $OUT/sgdisk.img
sgdisk -U 11111111-2222-3333-4444-555555555555 \
       -n 1:2048:+256K -t 1:ef00 -c 1:"EFI system" -u 1:aaaaaaaa-0000-4000-8000-000000000001 \
       -n 2:0:+128K -t 2:ef02 -c 2:"BIOS boot" -u 2:aaaaaaaa-0000-4000-8000-000000000002 \
       -n 3:0:+512K -t 3:8300 -c 3:"root" -A 3:set:2 -u 3:aaaaaaaa-0000-4000-8000-000000000003 \
       -n 4:3200:+256K -t 4:0700 -c 4:"data" -A 4:set:60 -A 4:set:63 -u 4:aaaaaaaa-0000-4000-8000-000000000004 \
       -n 5:0:0 -t 5:8200 -c 5:"swap" -u 5:aaaaaaaa-0000-4000-8000-000000000005 \
       $OUT/sgdisk.img > /dev/null
mformat -i $OUT/sgdisk.img@@1048576 -T 512 -h 16 -s 32 -v ESP -N 0x0e5f0e5f ::
mcopy -i $OUT/sgdisk.img@@1048576 hello.txt ::
# A hybrid MBR on a copy.
cp $OUT/sgdisk.img $OUT/sgdisk-hybrid.img
sgdisk -h 1:3 $OUT/sgdisk-hybrid.img > /dev/null

# ---------------------------------------------------------------- ISO 9660
mkdir -p tree/docs tree/deep/a/b/c/d/e/f/g/h/i tree/dev
printf 'hello from fillyfoal\n' > tree/hello.txt
seq 1 400 > tree/docs/numbers.txt
printf 'deep\n' > tree/deep/a/b/c/d/e/f/g/h/i/leaf.txt
printf 'long\n' > "tree/docs/a rather long file name that needs a continuation area in rock ridge because it does not fit.txt"
ln -s docs/numbers.txt tree/link-to-numbers
ln -s ../../hello.txt tree/docs/up-link
mknod tree/dev/null0 c 1 3
mkdir -p boot
dd if=/dev/zero of=boot/boot.img bs=2048 count=2 2> /dev/null
printf '\353\376' | dd of=boot/boot.img conv=notrunc 2> /dev/null
truncate -s 64K boot/efi.img
mkfs.fat -n EFIBOOT -i 0e5f0e5f boot/efi.img > /dev/null
cp boot/boot.img boot/efi.img tree/
xorriso -report_about WARNING -outdev $OUT/xorriso-eltorito.iso \
  -volid FILLYFOAL -volset_id FILLYFOAL -publisher fillyfoal -preparer_id fillyfoal \
  -application_id fillyfoal -system_id LINUX \
  -joliet on -rockridge on -compliance deep_paths:long_paths \
  -map tree / \
  -set_filter_r --zisofs /docs/numbers.txt -- \
  -boot_image any bin_path=/boot.img -boot_image any cat_path=/boot.cat \
  -boot_image any platform_id=0x00 -boot_image any emul_type=no_emulation \
  -boot_image any load_size=2048 -boot_image any next \
  -boot_image any efi_path=/efi.img -boot_image any platform_id=0xef \
  -boot_image any emul_type=no_emulation
# genisoimage: ISO 9660:1999 (enhanced volume descriptor), Joliet, Rock
# Ridge with relocated deep directories (RE/CL/PL), floppy-emulation boot.
dd if=/dev/zero of=boot/floppy.img bs=1024 count=1440 2> /dev/null
mkfs.fat -n FLOPPY -i 0f10ff11 boot/floppy.img > /dev/null
mkdir -p tree2/deep/a/b/c/d/e/f/g/h/i
cp tree/hello.txt tree2/
cp tree/deep/a/b/c/d/e/f/g/h/i/leaf.txt tree2/deep/a/b/c/d/e/f/g/h/i/
cp boot/floppy.img tree2/
genisoimage -quiet -o $OUT/genisoimage-1999.iso -iso-level 4 -J -R -V FILLYFOAL \
  -A fillyfoal -p fillyfoal -publisher fillyfoal -sysid LINUX \
  -b floppy.img -c boot.cat tree2

# genisoimage at the default level: Rock Ridge relocates directories
# nested deeper than eight levels (RE/CL/PL), a name too long for its
# record continues in a continuation area (CE), a device node (PN).
mkdir -p tree3/deep/a/b/c/d/e/f/g/h/i tree3/dev
cp tree/hello.txt tree3/
cp tree/deep/a/b/c/d/e/f/g/h/i/leaf.txt tree3/deep/a/b/c/d/e/f/g/h/i/
printf 'long\n' > "tree3/$(printf 'n%.0s' $(seq 1 180)).txt"
mknod tree3/dev/zero0 c 1 5
ln -s hello.txt tree3/hello-link
genisoimage -quiet -o $OUT/genisoimage-relocated.iso -R -V RELOCATED -A fillyfoal \
  -p fillyfoal -publisher fillyfoal -sysid LINUX tree3

# ---------------------------------------------------------------- UDF
truncate -s 1M $OUT/mkudffs.udf
mkudffs -q --media-type=hd --blocksize=2048 --label=FILLYFOAL --vsid=fillyfoal \
  --uuid=0123456789abcdef $OUT/mkudffs.udf > /dev/null 2>&1 || \
  mkudffs --media-type=hd --blocksize=2048 --label=FILLYFOAL $OUT/mkudffs.udf

# ---------------------------------------------------------------- LUKS
truncate -s 4M $OUT/cryptsetup-luks1.img
printf fillyfoal | cryptsetup luksFormat --batch-mode --type luks1 --key-file - \
  --cipher aes-cbc-essiv:sha256 --key-size 256 --hash sha256 --iter-time 10 \
  --uuid 11111111-2222-4333-8444-555555555555 $OUT/cryptsetup-luks1.img
printf fillyfoal > key1
printf fillyfoal2 > key2
cryptsetup luksAddKey --batch-mode --key-file key1 --iter-time 10 \
  $OUT/cryptsetup-luks1.img key2
# Keep the header area (the payload starts at 2 MiB) and one 4 KiB block
# of (unwritten) payload.
truncate -s 2101248 $OUT/cryptsetup-luks1.img

truncate -s 4M $OUT/cryptsetup-luks2.img
printf fillyfoal | cryptsetup luksFormat --batch-mode --type luks2 --key-file - \
  --cipher aes-xts-plain64 --key-size 512 --pbkdf argon2id --pbkdf-memory 32 \
  --pbkdf-force-iterations 4 --label fillyfoal --subsystem test \
  --luks2-metadata-size 16k --luks2-keyslots-size 512k \
  --uuid 66666666-7777-4888-8999-aaaaaaaaaaaa $OUT/cryptsetup-luks2.img
cryptsetup luksAddKey --batch-mode --key-file key1 --pbkdf pbkdf2 \
  --pbkdf-force-iterations 1000 $OUT/cryptsetup-luks2.img key2
cryptsetup config --priority prefer --key-slot 1 $OUT/cryptsetup-luks2.img
printf '{"type":"fillyfoal-token","keyslots":["1"],"note":"test"}' | \
  cryptsetup token import --json-file - $OUT/cryptsetup-luks2.img
truncate -s 1052672 $OUT/cryptsetup-luks2.img

