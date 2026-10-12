# Writes the AFF4 fixtures with pyaff4 0.31 (the reference Python AFF4
# implementation) in a Debian bookworm container:
#
#   mkdir -p /tmp/fixtures/forensic-aff4 && cp tests/data/aff4/* /tmp/fixtures/forensic-aff4/
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/forensic-aff4:/w debian:bookworm sh /w/run.sh
#
# pyaff4 0.31 pins packages that no longer build on Python 3.11, so it is
# installed without its dependencies and these versions are installed
# instead; `fastchunking` (hash-based deduplication, not used here) is
# replaced by the empty module next to this script. The source is a 96 KiB
# FAT12 volume with one file (the same one tests/data/ewf2/make.sh images).
# Output in /tmp/fixtures/forensic-aff4/out; not byte-reproducible (the
# volume URNs are random).
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq python3-venv python3-dev build-essential libsnappy-dev dosfstools mtools >/dev/null 2>&1
python3 -m venv /opt/venv
/opt/venv/bin/pip install -q --upgrade "pip<24" "setuptools<70" wheel >/dev/null 2>&1
/opt/venv/bin/pip install -q --no-deps pyaff4==0.31 >/dev/null 2>&1
/opt/venv/bin/pip install -q "rdflib[sparql]==4.2.2" intervaltree==3.1.0 expiringdict==1.1.4 \
    python-dateutil==2.8.0 hexdump==3.3 tzlocal==1.5.1 PyYAML==6.0.3 python-snappy==0.7.3 \
    cramjam==2.13.0 html5lib==1.0.1 PyNaCl==1.6.2 future==1.0.0 six==1.17.0 \
    pycryptodome==3.24.1 pycryptodomex==3.24.1 pycryptoplus==0.0.1 aes-keywrap==17.12.1 \
    passlib==1.7.4 cryptography==50.0.2 >/dev/null 2>&1
rm -rf /w/out && mkdir -p /w/out /tmp/src /tmp/stub
cp /w/fastchunking.py /tmp/stub/
cd /tmp/src
dd if=/dev/zero of=src.img bs=1024 count=96 2>/dev/null
mkfs.fat -n FILLYFOAL -i 46494c4c src.img >/dev/null
printf 'hello from fillyfoal\n' > hello.txt
MTOOLS_SKIP_CHECK=1 mcopy -i src.img hello.txt ::HELLO.TXT
cp src.img /w/out/
PYTHONPATH=/tmp/stub /opt/venv/bin/python /w/gen.py /tmp/src/src.img /tmp/src/hello.txt /w/out
# Read the images back with pyaff4.
PYTHONPATH=/tmp/stub /opt/venv/bin/python /w/check.py /w/out
