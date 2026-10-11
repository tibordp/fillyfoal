#!/bin/sh
# Builds tests/fixtures/external/jar/hello.jar with the JDK's javac and jar
# tools (eclipse-temurin:21-jdk in Docker) from Hello.java. The jar tool
# writes deflated entries through ZipOutputStream, so they carry data
# descriptors (general purpose bit 3). --date pins the entry times, so the
# output is reproducible with the same JDK.
#
#   sh tests/data/jar/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/archive-jar
rm -rf "$B"
mkdir -p "$B/src/fillyfoal" "$B/classes"
cp "$SRC/Hello.java" "$B/src/fillyfoal/"
docker run --rm -v "$B:/work" -w /work eclipse-temurin:21-jdk sh -eu -c '
javac --release 11 -d classes src/fillyfoal/Hello.java
jar --create --file hello.jar --date=2026-01-01T00:00:00Z --main-class fillyfoal.Hello -C classes .
'
mkdir -p "$FIX/jar"
cp "$B/hello.jar" "$FIX/jar/"
