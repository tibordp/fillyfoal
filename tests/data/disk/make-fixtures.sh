#!/bin/sh
# Rebuilds the disk-image fixtures (qcow, vmdk, vhd, vhdx, mbr, gpt,
# iso9660, udf, luks, bitlocker).
#
# Real-tool images are made in a Debian container (Dockerfile here: QEMU's
# qemu-img/qemu-io, sfdisk, sgdisk, mtools, xorriso, genisoimage, mkudffs,
# cryptsetup), with the host name "fillyfoal", in a scratch directory
# outside the home directory. Synthetic ones come from the Python scripts
# here. LUKS key material (random by design) is zeroed so the images
# compress (zero-key-material.py).
#
# Fixtures up to 64 KiB are stored as they are; larger images are stored
# whole as `<name>.raw.zst` (zstd -19). Set COMPRESS=gz to write
# `<name>.raw.gz` instead (gzip -9 -n), which the harness also reads.
#
# usage: tests/data/disk/make-fixtures.sh [scratch dir]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/disk}
compress=${COMPRESS:-zst}
mkdir -p "$work"
docker build -q -t fillyfoal-disk-tools "$here" > /dev/null
docker run --rm --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  fillyfoal-disk-tools sh /data/inner.sh
out=$work/out
python3 "$here/zero-key-material.py" "$out/cryptsetup-luks1.img" \
  "$out/cryptsetup-luks2.img" "$out/qemu-luks.qcow2"
python3 "$here/bitlocker.py" "$out/win7.img"

# put <tree> <format> <file>: copies one image into the fixture tree.
put() {
  dest="$repo/tests/fixtures/$1/$2"
  mkdir -p "$dest"
  name=$(basename "$3")
  rm -f "$dest/$name" "$dest/$name.raw.zst" "$dest/$name.raw.gz"
  if [ "$(wc -c < "$3")" -le 65536 ]; then
    cp "$3" "$dest/$name"
  elif [ "$compress" = gz ]; then
    gzip -9 -n -c "$3" > "$dest/$name.raw.gz"
  else
    zstd -19 -q -f "$3" -o "$dest/$name.raw.zst"
  fi
}

for f in qemu-v1.qcow qemu-v3.qcow2 qemu-v2-backing.qcow2 qemu-extl2-zstd.qcow2 \
         qemu-luks.qcow2 qemu-datafile.qcow2; do
  put external qcow "$out/$f"
done
for f in qemu-monolithic-sparse.vmdk qemu-stream-optimized.vmdk qemu-twogb-s001.vmdk; do
  put external vmdk "$out/$f"
done
put external vmdk-descriptor "$out/qemu-twogb.vmdk"
put external vmdk-descriptor "$out/qemu-flat.vmdk"
put synthetic vmdk "$out/stream-markers.vmdk"
put external vhd "$out/qemu-dynamic.vhd"
put external vhd "$out/qemu-fixed.vhd"
put synthetic vhd "$out/differencing.vhd"
put external vhdx "$out/qemu-dynamic.vhdx"
put synthetic vhdx "$out/differencing.vhdx"
put external mbr "$out/sfdisk-extended.img"
put external gpt "$out/sgdisk.img"
put external gpt "$out/sgdisk-hybrid.img"
put external iso9660 "$out/xorriso-eltorito.iso"
put external iso9660 "$out/genisoimage-1999.iso"
put external iso9660 "$out/genisoimage-relocated.iso"
put external udf "$out/mkudffs.udf"
put external luks "$out/cryptsetup-luks1.img"
put external luks "$out/cryptsetup-luks2.img"
put synthetic bitlocker "$out/win7.img"
