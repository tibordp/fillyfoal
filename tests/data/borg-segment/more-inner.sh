set -e
# Runs inside debian:bookworm-slim with --hostname fillyfoal; /work is the
# output directory. See make-more.sh.
apt-get update -qq >/dev/null && apt-get install -y -qq borgbackup attr >/dev/null 2>&1
borg --version
python3 -c 'from borg.constants import ITEMS_CHUNKER_PARAMS, MAX_OBJECT_SIZE; print("items chunker", ITEMS_CHUNKER_PARAMS, "max object", MAX_OBJECT_SIZE)'
B=/tmp/borg
rm -rf $B && mkdir -p $B/src && cd $B
export BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=yes
export BORG_BASE_DIR=$B/home
export TZ=UTC
# A file name that is not UTF-8 (Latin-1 "café.txt"), a file dated before
# 1970 (a negative nanosecond time) and a binary extended attribute.
printf 'Hello from fillyfoal.\n' > src/hello.txt
printf 'caf\351\n' > "$(printf 'src/caf\351.txt')"
touch -d '1965-06-07 08:09:10.5 UTC' src/hello.txt
setfattr -n user.fillyfoal -v 0xfffe00 src/hello.txt
borg init --encryption=none plain
borg create --compression lz4 plain::names src
# The segment holding the data and metadata (the first of the four that
# `borg create` writes), the repository index, and the client's chunks
# cache (both hash indexes).
ls plain/data/0 | sort -n
cp "plain/data/0/$(ls plain/data/0 | sort -n | tail -4 | head -1)" /work/names
cp plain/index.* /work/
cp "$(ls -d $BORG_BASE_DIR/.cache/borg/*/)chunks" /work/chunks
ls -l /work
