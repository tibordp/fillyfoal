#!/bin/sh
# Builds tests/fixtures/external/dex/shapes.dex: javac (the JDK bundled with
# Android Studio, --release 8) then d8 from Android SDK build-tools 36.0.0
# with debug info, in a neutral directory.
#
#   sh tests/data/dex/make.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/dex}" && pwd)
JAVA_HOME=${JAVA_HOME:-"/Applications/Android Studio.app/Contents/jbr/Contents/Home"}
D8=${D8:-"$HOME/Library/Android/sdk/build-tools/36.0.0/d8"}
export JAVA_HOME
B=/tmp/fixtures/pe-dex
rm -rf "$B"
mkdir -p "$B/classes" "$B/out"
cp -R "$SRC/src" "$B/src"
cd "$B"
"$JAVA_HOME/bin/javac" --release 8 -g -encoding UTF-8 -d classes src/org/fillyfoal/sample/*.java
"$D8" --debug --min-api 26 --output out $(find classes -name '*.class' | sort)
cp out/classes.dex "$OUT/shapes.dex"
ls -l "$OUT/shapes.dex"
