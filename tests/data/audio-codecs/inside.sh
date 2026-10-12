#!/bin/bash
# Runs inside fedora:42 (see make.sh): encodes short sine tones with the
# reference encoders. /data is this directory, /out the output directory.
set -euo pipefail
dnf -q -y install mac musepack-tools speex-tools python3 >/dev/null
rpm -q mac musepack-tools speex-tools
mkdir -p /work && cd /work
python3 -I /data/tone.py tone44.wav 44100 2 0.1
python3 -I /data/tone.py tone16.wav 16000 1 0.25

# Monkey's Audio: normal (2000) and extra high (4000) compression.
mac tone44.wav mac-normal.ape -c2000
mac tone44.wav mac-extra-high.ape -c4000
# Musepack SV8.
mpcenc --silent --standard tone44.wav mpcenc.mpc
# Speex, wideband, in Ogg (the Ogg serial number is random).
speexenc --wideband --quality 6 tone16.wav speexenc.spx
cp mac-normal.ape mac-extra-high.ape mpcenc.mpc speexenc.spx /out/
ls -l /out
