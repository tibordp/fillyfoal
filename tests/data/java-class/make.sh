#!/bin/sh
# Builds the javac 21 fixtures in tests/fixtures/external/java-class/ from
# tests/data/java-class/src with the eclipse-temurin:21-jdk Docker image, in
# a neutral directory:
#
#   javac --release 21 -g -parameters
#
# Shapes.class (pattern switches, lambdas, string concat, StackMapTable,
# exception table, generics, parameter and type annotations), Shape.class
# (sealed interface, RuntimeVisibleAnnotations with enum and array values),
# Shape-Circle.class (javac's Shape$Circle.class: record with a compact constructor and annotated
# component), Tag.class (annotation interface with AnnotationDefault) and
# module-info.class (Module). javac output carries no timestamps, so a rerun
# with the same javac is byte for byte identical. Checked against `javap -v -p`.
#
#   sh tests/data/java-class/make.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/java-class}" && pwd)
B=/tmp/fixtures/bytecode-java-class
rm -rf "$B"
mkdir -p "$B/out"
cp -R "$SRC/src" "$B/src"
docker run --rm -v "$B:/w" -w /w eclipse-temurin:21-jdk sh -c '
    javac -version &&
    javac --release 21 -g -parameters -encoding UTF-8 -d out \
        src/module-info.java src/org/fillyfoal/sample/*.java'
cp "$B/out/org/fillyfoal/sample/Shapes.class" \
   "$B/out/org/fillyfoal/sample/Shape.class" \
   "$B/out/org/fillyfoal/sample/Tag.class" \
   "$B/out/module-info.class" "$OUT/"
cp "$B/out/org/fillyfoal/sample/Shape\$Circle.class" "$OUT/Shape-Circle.class"
ls -l "$OUT"
