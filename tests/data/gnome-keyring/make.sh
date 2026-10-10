#!/bin/sh
# Writes tests/fixtures/external/gnome-keyring/secret-tool.keyring with
# gnome-keyring-daemon (Debian trixie) in Docker, with no network: the login
# keyring unlocked with the test password "fillyfoal" and two items stored
# through libsecret's secret-tool. Salts and IVs are random: a re-run gives
# new bytes with the same structure.
#
#   sh tests/data/gnome-keyring/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-gnome-keyring
rm -rf "$work"
mkdir -p "$work/out"
cd "$work"
cat >Dockerfile <<'DOCKER'
FROM debian:trixie-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    gnome-keyring libsecret-tools dbus-daemon >/dev/null && rm -rf /var/lib/apt/lists/*
DOCKER
docker build -q -t fillyfoal-gnome-keyring . >/dev/null
cat >run.sh <<'RUN'
set -eu
export HOME=/home/test
mkdir -p "$HOME"
dbus-run-session -- sh -euc '
printf fillyfoal | gnome-keyring-daemon --unlock --components=secrets >/dev/null
sleep 1
printf "first secret" | secret-tool store --label="Fillyfoal test" service fillyfoal user alice
printf "second secret" | secret-tool store --label="Fillyfoal web" server web.example.test protocol https port 443
sleep 1
'
cp "$HOME/.local/share/keyrings/login.keyring" /out/
gnome-keyring-daemon --version >/out/version.txt
RUN
docker run --rm --network none -v "$work/out:/out" -v "$work/run.sh:/run.sh:ro" fillyfoal-gnome-keyring sh /run.sh
cat "$work/out/version.txt"
mkdir -p "$root/tests/fixtures/external/gnome-keyring"
cp "$work/out/login.keyring" "$root/tests/fixtures/external/gnome-keyring/secret-tool.keyring"
