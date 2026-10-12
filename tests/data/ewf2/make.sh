# Writes the EWF fixtures with libewf's ewfacquire (libewf-experimental
# 20260924, built from the release tarball: Debian's 20140816 lists
# encase7-v2 but writes EWF1, and 20240506 writes Ex01 files that its own
# ewfverify rejects).
#
#   mkdir -p /tmp/fixtures/forensic-ewf2 && cp tests/data/ewf2/make.sh /tmp/fixtures/forensic-ewf2/
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/forensic-ewf2:/w debian:trixie sh /w/make.sh
#
# Output in /tmp/fixtures/forensic-ewf2/out: usb.Ex01 (EWF2, deflate, MD5
# and SHA-1 sections), stored.Ex01 (EWF2, uncompressed chunks with
# checksums) and v1.E01 (EWF1, EnCase 7 format). Each image holds the same
# 96 KiB FAT12 volume with one file, in 8 KiB chunks (-b 16), so most chunks
# are empty: EWF2 stores those as pattern fills. Not byte-reproducible: the
# case data records the acquisition time.
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq build-essential curl zlib1g-dev libbz2-dev pkg-config dosfstools mtools >/dev/null 2>&1
cd /tmp
curl -sSLf -o libewf.tar.gz https://github.com/libyal/libewf/releases/download/20260924/libewf-experimental-20260924.tar.gz
echo "e2da4fdb8999b855948863d1bcb11e9427af959e789093491ed94dca397905b5  libewf.tar.gz" | sha256sum -c -
tar xzf libewf.tar.gz
cd libewf-20260924
./configure --quiet --disable-shared --enable-static >/dev/null
make -j8 >/dev/null 2>&1
T=$PWD/ewftools
rm -rf /w/out && mkdir -p /w/out && cd /w/out
dd if=/dev/zero of=src.img bs=1024 count=96 2>/dev/null
mkfs.fat -n FILLYFOAL -i 46494c4c src.img >/dev/null
printf 'hello from fillyfoal\n' > hello.txt
MTOOLS_SKIP_CHECK=1 mcopy -i src.img hello.txt ::HELLO.TXT
$T/ewfacquire -u -q -t usb -f encase7-v2 -c deflate:best -b 16 -C case-1 -D "fillyfoal test image" -e fillyfoal -E ev-1 -N "made for tests" -d sha1 src.img
$T/ewfacquire -u -q -t stored -f encase7-v2 -c none -b 16 -C case-3 -D "fillyfoal test image" -e fillyfoal -E ev-3 -N "made for tests" src.img
$T/ewfacquire -u -q -t v1 -f encase7 -c deflate:best -b 16 -C case-4 -D "fillyfoal test image" -e fillyfoal -E ev-4 -N "made for tests" src.img
for f in usb.Ex01 stored.Ex01 v1.E01; do $T/ewfverify -q $f; done
