#!/bin/sh
# Builds tests/fixtures/external/uefi-fv/edk2-compress.fv with the EDK2
# BaseTools (edk2-stable202405, built by build-tools.sh in debian:bookworm:
# GenSec, GenFfs, GenFv, TianoCompress, BrotliCompress with the brotli
# submodule).
#
# Usage (in Docker, the tools in $TOOLS, output in the current directory):
#   docker run --rm -v /tmp/fixtures/firmware-uefi:/work -w /work/out \
#     debian:bookworm sh /work/mkcompress.sh
#
# Three FFS files, each wrapping a raw section and a user interface section:
# - a compression section of the standard (EFI) compression (GenSec
#   -c PI_STD, which calls BaseTools' EfiCompress: 4-bit position table);
# - a GUID-defined section of the Tiano compression GUID (TianoCompress -e:
#   5-bit position table, 512 KiB window);
# - a GUID-defined section of the Brotli GUID (BrotliCompress -e: a 16-byte
#   header of the decoded size and the scratch size, then a Brotli stream).
set -e
TOOLS=${TOOLS:-/work/edk2/BaseTools/Source/C/bin}
TIANO_GUID=A31280AD-481E-41B6-95E8-127F4C984779
BROTLI_GUID=3D532050-5CDA-4FD0-879E-0F7F630D5AFB

pad4() {
    size=$(wc -c < "$1")
    rem=$(( (4 - size % 4) % 4 ))
    [ "$rem" -eq 0 ] || head -c "$rem" /dev/zero >> "$1"
}

# The payload: text with near and far repeats, so the coders have matches
# at short and long distances.
i=0
: > payload.bin
while [ $i -lt 40 ]; do
    printf 'fillyfoal UEFI compressed section payload line %02d of 40\n' $i >> payload.bin
    i=$((i + 1))
done
seq 1 400 | tr '\n' ' ' >> payload.bin
head -c 600 payload.bin > payload.head
cat payload.head >> payload.bin
rm payload.head

for kind in std tiano brotli; do
    "$TOOLS/GenSec" -s EFI_SECTION_RAW -o raw-$kind.sec payload.bin
    pad4 raw-$kind.sec
    "$TOOLS/GenSec" -s EFI_SECTION_USER_INTERFACE -n "Inside $kind" -o ui-$kind.sec
    cat raw-$kind.sec ui-$kind.sec > inner-$kind.bin
done
"$TOOLS/GenSec" -s EFI_SECTION_COMPRESSION -c PI_STD -o std.sec inner-std.bin
"$TOOLS/TianoCompress" -e -o inner-tiano.tc inner-tiano.bin
"$TOOLS/BrotliCompress" -e -o inner-brotli.br inner-brotli.bin
"$TOOLS/GenSec" -s EFI_SECTION_GUID_DEFINED -g $TIANO_GUID -r PROCESSING_REQUIRED \
    -o tiano.sec inner-tiano.tc
"$TOOLS/GenSec" -s EFI_SECTION_GUID_DEFINED -g $BROTLI_GUID -r PROCESSING_REQUIRED \
    -o brotli.sec inner-brotli.br

"$TOOLS/GenFfs" -t EFI_FV_FILETYPE_FREEFORM -g 3a0f4c3e-1d4b-4f6a-9a51-6c5d1e0f0b01 \
    -o std.ffs -i std.sec
"$TOOLS/GenFfs" -t EFI_FV_FILETYPE_FREEFORM -g 3a0f4c3e-1d4b-4f6a-9a51-6c5d1e0f0b02 \
    -o tiano.ffs -i tiano.sec
"$TOOLS/GenFfs" -t EFI_FV_FILETYPE_FREEFORM -g 3a0f4c3e-1d4b-4f6a-9a51-6c5d1e0f0b03 \
    -o brotli.ffs -i brotli.sec

{
    echo '[options]'
    echo 'EFI_BLOCK_SIZE = 0x1000'
    echo 'EFI_NUM_BLOCKS = 0x2'
    echo '[attributes]'
    echo 'EFI_ERASE_POLARITY = 1'
    echo 'EFI_FVB2_ALIGNMENT_16 = TRUE'
    echo '[files]'
    echo 'EFI_FILE_NAME = std.ffs'
    echo 'EFI_FILE_NAME = tiano.ffs'
    echo 'EFI_FILE_NAME = brotli.ffs'
} > fv.inf
"$TOOLS/GenFv" -i fv.inf -o edk2-compress.fv
ls -l edk2-compress.fv
