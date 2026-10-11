#!/bin/sh
# Runs in a debian:trixie container (see make.sh): writes the same three
# entries (journal export format, fixed IDs and timestamps) into a compact
# and a regular journal with systemd-journal-remote, nothing from any host
# journal. MaxFileSize keeps the hash tables at their 2047/333-item minimum.
# Then a fourth entry with a 1 KiB message (above the 512-byte compression
# threshold) after the three, compressed with each of zstd, LZ4 and XZ.
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq systemd-journal-remote >/dev/null 2>&1
/usr/lib/systemd/systemd-journal-remote --version | head -1 > /work/out/version.txt
echo 5eedf111f0a15eedf111f0a15eedf111 > /etc/machine-id
mkdir -p /etc/systemd
printf '[Remote]\nSplitMode=none\nMaxFileSize=1M\nMaxUse=4M\n' > /etc/systemd/journal-remote.conf

entry() {
    # $1 realtime, $2 monotonic, $3 seqnum, $4 priority, $5 message
    printf '__CURSOR=s=00112233445566778899aabbccddeeff;i=%s\n' "$3"
    printf '__REALTIME_TIMESTAMP=%s\n__MONOTONIC_TIMESTAMP=%s\n' "$1" "$2"
    printf '_BOOT_ID=00112233445566778899aabbccddeeff\n'
    printf '_MACHINE_ID=5eedf111f0a15eedf111f0a15eedf111\n'
    printf '_HOSTNAME=fillyfoal\nSYSLOG_IDENTIFIER=fillyfoal\n'
    printf 'PRIORITY=%s\nMESSAGE=%s\n\n' "$4" "$5"
}
{
    entry 1767225600000000 1000000 1 6 'hello world'
    entry 1767225601000000 2000000 2 4 'second entry'
    entry 1767225602500000 3500000 3 3 'third entry, an error'
} > /work/in.export

SYSTEMD_JOURNAL_COMPACT=1 /usr/lib/systemd/systemd-journal-remote -o /work/out/compact.journal /work/in.export
SYSTEMD_JOURNAL_COMPACT=0 /usr/lib/systemd/systemd-journal-remote -o /work/out/regular.journal /work/in.export

{
    cat /work/in.export
    entry 1767225603000000 4000000 4 6 "a long message: $(i=0; while [ $i -lt 40 ]; do printf 'word%02d filler text ' $i; i=$((i + 1)); done)"
} > /work/long.export
for c in zstd lz4 xz; do
    SYSTEMD_JOURNAL_COMPRESS=$(echo $c | tr a-z A-Z) SYSTEMD_JOURNAL_COMPACT=1 \
        /usr/lib/systemd/systemd-journal-remote -o /work/out/$c.journal /work/long.export
done
