#!/bin/sh
# Makes the Android dynamic-partitions fixtures on a Linux host (user
# "fillyfoal", TZ=UTC) with AOSP lpmake/lpdump built by build-lptools.sh,
# avbtool.py from a shallow clone of platform/external/avb ($AOSP) and
# OpenSSL. Output: /tmp/fixtures/android-super.
#   system.img    48 KiB of "s" given an AVB hashtree footer (no FEC) in a
#                 128 KiB partition
#   vendor.img    48 KiB of "v" given an AVB hash footer in a 128 KiB partition
#   super-avb.img lpmake: a 4 MiB super device, 2 metadata slots of 8 KiB,
#                 group "main" holding both partitions (read-only), then an
#                 AVB hash footer added to the whole image by avbtool in a
#                 5 MiB partition named "super" (signed with a fresh key)
#   super-ab.img  lpmake: A/B layout (3 slots, _a/_b partitions in groups
#                 main_a/main_b; the _b ones empty), no footer
# The partition contents are plain filler so that the snapshots show the
# super image's own structure; ext4 and AVB footers inside partitions have
# fixtures of their own.
set -eu
export TZ=UTC LC_ALL=C
AOSP=${AOSP:-/tmp/aosp}
LP=$AOSP/out
AVB="python3 $AOSP/platform_external_avb/avbtool.py"
D=/tmp/fixtures/android-super
rm -rf "$D"; mkdir -p "$D"; cd "$D"

head -c 49152 /dev/zero | tr '\0' 's' > system.img
$AVB add_hashtree_footer --image system.img --partition_name system \
  --partition_size 131072 --hash_algorithm sha256 --do_not_generate_fec \
  --salt 0f1110f00f1110f00f1110f00f1110f0 --prop org.fillyfoal:system
head -c 49152 /dev/zero | tr '\0' 'v' > vendor.img
$AVB add_hash_footer --image vendor.img --partition_name vendor \
  --partition_size 131072 --salt 0f1110f00f1110f00f1110f00f1110f0

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-key.pem 2>/dev/null

"$LP/lpmake" --device-size=4194304 --metadata-size=8192 --metadata-slots=2 \
  --super-name=super --group=main:1048576 \
  --partition=system:readonly:131072:main --image=system=system.img \
  --partition=vendor:readonly:131072:main --image=vendor=vendor.img \
  --output=super-avb.img
$AVB add_hash_footer --image super-avb.img --partition_name super \
  --partition_size 5242880 --algorithm SHA256_RSA2048 --key test-key.pem \
  --salt 0f1110f00f1110f00f1110f00f1110f0 --rollback_index 1 \
  --prop org.fillyfoal:super

"$LP/lpmake" --device-size=4194304 --metadata-size=8192 --metadata-slots=3 \
  --super-name=super --group=main_a:1048576 --group=main_b:1048576 \
  --partition=system_a:readonly:131072:main_a --image=system_a=system.img \
  --partition=vendor_a:readonly:131072:main_a --image=vendor_a=vendor.img \
  --partition=system_b:readonly:0:main_b --partition=vendor_b:readonly:0:main_b \
  --output=super-ab.img

for f in super-avb.img super-ab.img; do
  "$LP/lpdump" "$f" > "$f.lpdump.txt" 2>&1 || true
  "$LP/lpdump" -s 1 "$f" > "$f.lpdump-slot1.txt" 2>&1 || true
done
for f in super-avb.img system.img vendor.img; do
  $AVB info_image --image "$f" > "$f.avbinfo.txt" 2>&1 || true
done
for f in super-avb.img super-ab.img; do zstd -q -19 -f "$f" -o "$f.raw.zst"; done
rm -f test-key.pem
ls -l
