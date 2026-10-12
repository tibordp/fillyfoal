#!/bin/bash
# Runs inside debian:trixie-slim (see make.sh): converts song.mod (song.py)
# with real trackers, driven through their user interfaces on a virtual X
# display, since neither has a command-line save:
#   Schism Tracker 20250313 (Debian package): schism.it, schism.s3m, schism.mod
#   MilkyTracker 1.05.01 (Debian source):     milkytracker.xm
# MilkyTracker is rebuilt from the Debian source without ALSA, because the
# packaged binary aborts at start-up when there is no ALSA sequencer (as in
# a container); the module code is unchanged. /data is this directory,
# /out the output directory.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sed 's/^Types: deb$/Types: deb deb-src/' -i /etc/apt/sources.list.d/debian.sources
apt-get update -qq
apt-get install -y -qq schism libsdl2-2.0-0 libsdl3-0 xvfb xdotool python3 \
    dpkg-dev cmake g++ libsdl2-dev zlib1g-dev libzzip-dev liblhasa-dev pkg-config >/dev/null

mkdir -p /build && cd /build
apt-get source -qq milkytracker >/dev/null
cd milkytracker-*/
# Upstream only switches to C++11 on the MIDI path.
sed -i 's/set(CMAKE_CXX_STANDARD 98)/set(CMAKE_CXX_STANDARD 11)/' CMakeLists.txt
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_DISABLE_FIND_PACKAGE_ALSA=ON -DCMAKE_DISABLE_FIND_PACKAGE_JACK=ON >/dev/null
make -C build -j"$(nproc)" >/dev/null
MILKY=$PWD/build/src/tracker/milkytracker

mkdir -p /work && cd /work
python3 /data/song.py song.mod
export DISPLAY=:99 HOME=/work/home SDL_AUDIODRIVER=dummy NO_SCALE=1
mkdir -p "$HOME"
Xvfb :99 -screen 0 1600x1200x24 >/dev/null 2>&1 &
sleep 2

# Clicks are relative to the application window.
click() { xdotool mousemove --window "$WIN" "$1" "$2" click 1; sleep 0.5; }

# Schism Tracker: F10 opens "Save Module"; the format buttons are on the
# right (IT, S3M, MOD), the file name field at the bottom.
schismtracker song.mod >/dev/null 2>&1 &
sleep 4
WIN=$(xdotool search --name "Schism Tracker" | head -1)
save_schism() { # name button-y
    xdotool key F10; sleep 1
    click 588 "$2"
    click 208 371
    xdotool key End $(printf 'BackSpace %.0s' $(seq 30))
    xdotool type --delay 60 "$1"
    xdotool key Return; sleep 1.5
    xdotool key Return; sleep 0.5
}
save_schism schism.it 107
save_schism schism.s3m 131
save_schism schism.mod 155
pkill schismtracker || true
sleep 1

# MilkyTracker: Ctrl+Shift+S opens the disk operations panel; pick the
# ".xm" type and press "save" (the name defaults to song.xm).
"$MILKY" -nosplash song.mod >/dev/null 2>&1 &
sleep 4
WIN=$(xdotool search --name "MilkyTracker" | head -1)
xdotool key ctrl+shift+s; sleep 1
click 9 37
click 29 109
sleep 1
pkill -f "$MILKY" || true

cp schism.it schism.s3m schism.mod /out/
cp song.xm /out/milkytracker.xm
ls -l /out
