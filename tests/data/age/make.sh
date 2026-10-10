#!/bin/sh
# Writes the external age/ fixtures with age 1.x (Alpine's `age` package) in
# Docker: files encrypted to an X25519 recipient, a passphrase (scrypt;
# passphrase "fillyfoal"), an ssh-ed25519 and an ssh-rsa recipient, and an
# ASCII-armored file. Keys and file
# keys are random: a re-run gives new bytes with the same structure.
#
#   sh tests/data/age/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-age
rm -rf "$work"
mkdir -p "$work"
docker run --rm -v "$work:/w" -w /w alpine:3.20 sh -euc '
apk add --no-cache age openssh-keygen expect >/dev/null
printf "fillyfoal age test message\n" >msg.txt
age-keygen -o x25519.key 2>/dev/null
age -r "$(age-keygen -y x25519.key)" -o x25519.age msg.txt
age -r "$(age-keygen -y x25519.key)" -a -o armored.age msg.txt
ssh-keygen -q -t ed25519 -N "" -C ed25519@fillyfoal -f ed
ssh-keygen -q -t rsa -b 2048 -N "" -C rsa@fillyfoal -f rsa
age -R ed.pub -R rsa.pub -o ssh.age msg.txt
cat >pass.exp <<EXP
spawn age -p -o passphrase.age msg.txt
expect "passphrase"
send "fillyfoal\r"
expect "passphrase"
send "fillyfoal\r"
expect eof
EXP
expect pass.exp >/dev/null
age --version >version.txt
'
out=$root/tests/fixtures/external/age
mkdir -p "$out"
for f in x25519 ssh passphrase; do
    cp "$work/$f.age" "$out/$f.age"
done
mkdir -p "$root/tests/fixtures/external/pem"
cp "$work/armored.age" "$root/tests/fixtures/external/pem/age-armored.age"
cat "$work/version.txt"
