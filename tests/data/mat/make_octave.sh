#!/bin/sh
# Writes tests/fixtures/external/mat/octave-v{6,7}.mat with GNU Octave 9.4.0
# (Debian trixie), then pins the creation time in the header text.
#
#   mkdir -p /tmp/fixtures/mat && cp make_octave.m make_octave.sh /tmp/fixtures/mat
#   cd /tmp/fixtures/mat && sh make_octave.sh
set -e
docker run --rm -v "$PWD":/work -w /work debian:trixie-slim sh -c '
  apt-get update -qq &&
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends octave >/dev/null &&
  octave-cli -q make_octave.m'
for f in octave-v6.mat octave-v7.mat; do
  # "..., written by Octave 9.4.0, YYYY-MM-DD HH:MM:SS UTC": same length.
  perl -0pi -e 's/(Octave [0-9.]+, )\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/${1}2026-01-01 00:00:00/' "$f"
done
