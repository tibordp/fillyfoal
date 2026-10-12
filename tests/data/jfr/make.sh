#!/bin/sh
# Records the JDK Flight Recorder fixture with Temurin 21 (eclipse-temurin:21-jdk):
# Hello.java starts a "worker" thread, joins it and calls System.gc(), under
# events.jfc, which enables only jdk.ThreadStart (with stack traces),
# jdk.ThreadEnd and jdk.GarbageCollection, so no host details (system
# properties, environment, CPU) are recorded. The file is mostly the metadata
# event that describes every event type (about 110 KB), so it is stored as
# jfr/events.jfr.gz (gzip -9 -n).
#
#   sh tests/data/jfr/make.sh [fixtures directory]
#
# Timestamps, thread IDs and the recording's timing differ between runs.
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/exec-jfr
rm -rf "$B"
mkdir -p "$B"
cp "$SRC/Hello.java" "$SRC/events.jfc" "$B/"
docker run --rm -v "$B:/w" -w /w eclipse-temurin:21-jdk sh -euc '
    java -version 2>&1 | head -2
    javac Hello.java
    java -XX:StartFlightRecording:filename=events.jfr,settings=/w/events.jfc Hello >/dev/null 2>&1
    jfr summary events.jfr | head -6
'
mkdir -p "$FIX/jfr"
gzip -9 -n -c "$B/events.jfr" > "$FIX/jfr/events.jfr.gz"
ls -l "$B/events.jfr" "$FIX/jfr/events.jfr.gz"
