set -e
# Runs inside debian:bookworm-slim with --hostname fillyfoal; /work is the output directory.
apt-get update -qq >/dev/null && apt-get install -y -qq borgbackup >/dev/null 2>&1
borg --version
B=/tmp/borg
rm -rf $B && mkdir -p $B/src && cd $B
export BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=yes
export BORG_PASSPHRASE=fillyfoal
export BORG_BASE_DIR=$B/home
export TZ=UTC
printf 'Hello from fillyfoal.\nThis is a small neutral text file.\n' > src/hello.txt
seq 1 2000 > src/numbers.txt
# Each `borg create` writes four segments: the data, a DELETE of the old
# manifest, the new manifest, and a lone COMMIT. Take the first.
newest() { ls "$1"/data/0 | sort -n | tail -4 | head -1; }
take() { cp "$1/data/0/$(newest "$1")" "/work/$2"; }

borg init --encryption=none plain
borg create --compression lz4 plain::lz4 src
take plain lz4

borg init --encryption=repokey enc
borg create --compression zlib,6 enc::one src
take enc repokey

borg init --encryption=authenticated auth
borg create --compression lz4 auth::one src
take auth authenticated

for c in zstd,3 zlib,6 lzma,6 none obfuscate,1,lz4; do
  name=${c%%,*}
  seq 1 3 1200 | sed "s/^/$name line /" > src/$name.txt
  borg create --compression $c plain::$name src
  take plain $name
done
borg delete plain::lz4
take plain delete
# The segment before the lone COMMIT holds the manifest (key 0).
cp "plain/data/0/$(ls plain/data/0 | sort -n | tail -2 | head -1)" /work/manifest
# A transaction ends with a segment holding only a COMMIT.
cp "plain/data/0/$(ls plain/data/0 | sort -n | tail -1)" /work/commit

ls -l /work
