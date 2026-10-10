#!/bin/sh
# The small directory tree the filesystem fixtures are populated from:
#   sh tree.sh DIR [--no-special]
# (--no-special leaves out device nodes, FIFOs and symlinks, for
# filesystems that cannot hold them.)
set -eu
S=$1
rm -rf "$S"
mkdir -p "$S/dir/sub" "$S/many"
printf 'Hello, fillyfoal!\n' > "$S/hello.txt"
seq -s ' ' 1 3000 > "$S/numbers.txt"
python3 -c 'import sys; sys.stdout.buffer.write((bytes(range(128, 256)) + bytes(range(0, 128))) * 80)' > "$S/pattern.bin"
printf 'nested\n' > "$S/dir/sub/nested.txt"
for i in $(seq -w 1 12); do printf '%s\n' "$i" > "$S/many/entry-$i-$(printf '%030d' 0)"; done
if [ "${2:-}" != "--no-special" ]; then
  ln -s hello.txt "$S/link"
  mknod "$S/null" c 1 3
  mkfifo "$S/pipe"
fi
touch -h -d @1704067200 "$S" "$S"/* "$S"/*/* "$S"/*/*/*
