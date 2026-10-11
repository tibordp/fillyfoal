#!/bin/sh
# Runs in a debian:trixie container (see fip.sh). Writes
#  - out/fip.bin: BL2, BL31, BL32 and BL33 with small text payloads,
#    aligned to 16 (the fixture);
#  - out/all.fip: one 4-byte image per `fiptool create` image option, the
#    source of the UUID table in platform.rs (not a fixture);
# and `fiptool info` for both.
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq arm-trusted-firmware-tools >/dev/null 2>&1
dpkg-query -W arm-trusted-firmware-tools > out/version.txt
cd /work/out
printf 'BL2 trusted boot firmware (fillyfoal test payload)\n' > bl2.bin
printf 'BL31 EL3 runtime firmware (fillyfoal test payload)\n' > bl31.bin
printf 'BL32 secure payload (fillyfoal test payload)\n' > bl32.bin
printf 'BL33 non-trusted firmware (fillyfoal test payload)\n' > bl33.bin
fiptool create --align 16 --tb-fw bl2.bin --soc-fw bl31.bin --tos-fw bl32.bin \
    --nt-fw bl33.bin fip.bin
fiptool info fip.bin > fip-info.txt

opts=$(fiptool help create 2>&1 | grep -oE '^  --[a-z0-9-]+ +FILENAME' | awk '{print $1}')
args=""
i=0
for o in $opts; do
    i=$((i + 1))
    printf '%04d' "$i" > "p$i"
    args="$args $o p$i"
done
# shellcheck disable=SC2086
fiptool create $args all.fip
fiptool info all.fip > all-info.txt
rm -f p[0-9]*
