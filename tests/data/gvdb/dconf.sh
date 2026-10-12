#!/bin/sh
# dconf database from a keyfile directory (dconf compile).
set -e
out=${1:-/out}
work=$(mktemp -d)
mkdir -p "$work/keyfiles/locks"
cat > "$work/keyfiles/00-example" <<'KF'
[org/example/demo]
enabled=true
count=uint32 42
offset=-7
ratio=0.5
name='fillyfoal'
names=['a', 'b']
pair=(1, 'x')
nothing=@ms nothing
settings={'k': <1>}
byte=byte 0x41
path=objectpath '/org/example'

[org/example/other]
big=int64 -9000000000
KF
printf '/org/example/demo/enabled\n' > "$work/keyfiles/locks/00-locks"
mkdir -p "$out/dconf"
dconf compile "$out/dconf/local" "$work/keyfiles"
