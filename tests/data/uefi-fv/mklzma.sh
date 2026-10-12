#!/bin/sh
# Builds tests/fixtures/external/uefi-fv/lzma.fv with the EDK2 BaseTools
# (edk2-stable202405, BaseTools/Source/C built with `make -C Common` and
# `make -C GenSec GenFfs GenFv LzmaCompress` in debian:bookworm).
#
# Usage (in Docker, the tools in $TOOLS, output in the current directory):
#   docker run --rm -v /tmp/fixtures/misc-uefi:/work -w /work/out \
#     debian:bookworm sh /work/mklzma.sh
#
# One FFS file holds a GUID-defined section of the LZMA custom
# decompression GUID (LzmaCompress -e), another one of the LZMA + x86 BCJ
# GUID (LzmaCompress --f86 -e); each wraps a raw section and a user
# interface section. A third file carries a plain user interface section.
set -e
TOOLS=${TOOLS:-/work/edk2/BaseTools/Source/C/bin}
LZMA_GUID=EE4E5898-3914-4259-9D6E-DC7BD79403CF
LZMAF86_GUID=D42AE6BD-1352-4BFB-909A-CA72A6EAE889

pad4() {
    size=$(wc -c < "$1")
    rem=$(( (4 - size % 4) % 4 ))
    [ "$rem" -eq 0 ] || head -c "$rem" /dev/zero >> "$1"
}

# The payload: text with repeats (so LZMA has matches) and a few x86 CALLs
# (E8 rel32) for the BCJ filter to convert.
i=0
: > payload.bin
while [ $i -lt 24 ]; do
    printf 'fillyfoal UEFI LZMA section payload, line %02d\n' $i >> payload.bin
    i=$((i + 1))
done
printf '\350\020\000\000\000\220\220\350\040\000\000\000\303' >> payload.bin

for kind in lzma f86; do
    "$TOOLS/GenSec" -s EFI_SECTION_RAW -o raw-$kind.sec payload.bin
    pad4 raw-$kind.sec
    "$TOOLS/GenSec" -s EFI_SECTION_USER_INTERFACE -n "Inside $kind" -o ui-$kind.sec
    cat raw-$kind.sec ui-$kind.sec > inner-$kind.bin
done
"$TOOLS/LzmaCompress" -e -o inner-lzma.lz inner-lzma.bin
"$TOOLS/LzmaCompress" --f86 -e -o inner-f86.lz inner-f86.bin
"$TOOLS/GenSec" -s EFI_SECTION_GUID_DEFINED -g $LZMA_GUID -r PROCESSING_REQUIRED \
    -o guided-lzma.sec inner-lzma.lz
"$TOOLS/GenSec" -s EFI_SECTION_GUID_DEFINED -g $LZMAF86_GUID -r PROCESSING_REQUIRED \
    -o guided-f86.sec inner-f86.lz
"$TOOLS/GenSec" -s EFI_SECTION_USER_INTERFACE -n "Plain" -o ui-plain.sec

"$TOOLS/GenFfs" -t EFI_FV_FILETYPE_FREEFORM -g 3a0f4c3e-1d4b-4f6a-9a51-6c5d1e0f0a01 \
    -o lzma.ffs -i guided-lzma.sec
"$TOOLS/GenFfs" -t EFI_FV_FILETYPE_FREEFORM -g 3a0f4c3e-1d4b-4f6a-9a51-6c5d1e0f0a02 \
    -o f86.ffs -i guided-f86.sec
"$TOOLS/GenFfs" -t EFI_FV_FILETYPE_FREEFORM -g 3a0f4c3e-1d4b-4f6a-9a51-6c5d1e0f0a03 \
    -o plain.ffs -i ui-plain.sec

cat > fv.inf <<EOF
[options]
EFI_BLOCK_SIZE = 0x1000
EFI_NUM_BLOCKS = 0x2
[attributes]
EFI_ERASE_POLARITY = 1
EFI_FVB2_ALIGNMENT_16 = TRUE
[files]
EFI_FILE_NAME = lzma.ffs
EFI_FILE_NAME = f86.ffs
EFI_FILE_NAME = plain.ffs
EOF
"$TOOLS/GenFv" -i fv.inf -o lzma.fv
ls -l lzma.fv
