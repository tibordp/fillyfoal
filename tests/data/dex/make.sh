#!/bin/sh
# Builds tests/fixtures/external/dex/shapes.dex: javac (the JDK bundled with
# Android Studio, --release 8) then d8 from Android SDK build-tools 36.0.0
# with debug info, in a neutral directory; and shapes-v041.dex, the same
# classes as a DEX 041 container (d8 --min-api 36 with R8's
# dexContainerExperiment property).
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
mkdir out41
"$JAVA_HOME/bin/java" -Dcom.android.tools.r8.dexContainerExperiment=true \
    -cp "$(dirname "$D8")/lib/d8.jar" com.android.tools.r8.D8 \
    --debug --min-api 36 --output out41 $(find classes -name '*.class' | sort)
cp out41/classes.dex "$OUT/shapes-v041.dex"
ls -l "$OUT/shapes.dex" "$OUT/shapes-v041.dex"
