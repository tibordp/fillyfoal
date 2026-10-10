#!/bin/sh
# Runs inside the fillyfoal-disk-tools container after inner.sh: what the
# reference tools say about each image (used to check the dissectors).
cd /w/out || exit 1
mkdir -p /w/oracle
for f in *.qcow2 *.vhd *.vhdx qemu-monolithic-sparse.vmdk qemu-stream-optimized.vmdk qemu-twogb-s001.vmdk; do
  { qemu-img info --output=json "$f"; qemu-img map --output=json "$f"; } > "/w/oracle/$f.txt" 2>&1
done
qemu-img info --output=json --object secret,id=sec0,data=fillyfoal \
  --image-opts driver=qcow2,file.filename=qemu-luks.qcow2,encrypt.key-secret=sec0 \
  > /w/oracle/qemu-luks.qcow2.txt 2>&1
for f in sfdisk-extended.img sgdisk.img sgdisk-hybrid.img; do
  { sfdisk -d "$f"; sgdisk -p "$f"; sgdisk -O "$f"; for i in 1 2 3 4 5; do sgdisk -i $i "$f"; done; } > "/w/oracle/$f.txt" 2>&1
done
for f in *.iso; do
  { xorriso -indev "$f" -report_el_torito plain -report_system_area plain -lsl / -find / -exec lsdl;
    isoinfo -d -i "$f"; isoinfo -l -R -i "$f"; isoinfo -l -J -i "$f"; isoinfo -p -i "$f"; } > "/w/oracle/$f.txt" 2>&1
done
qemu-img info differencing.vhd > /w/oracle/differencing.vhd.txt 2>&1
qemu-img info stream-markers.vmdk > /w/oracle/stream-markers.vmdk.txt 2>&1
udfinfo mkudffs.udf > /w/oracle/mkudffs.udf.txt 2>&1
for f in cryptsetup-*.img; do cryptsetup luksDump --dump-json-metadata "$f" > "/w/oracle/$f.json" 2>&1; cryptsetup luksDump "$f" > "/w/oracle/$f.txt" 2>&1; done
