#!/bin/sh
# Writes the external Access fixtures (mdb/jet4.mdb, accdb/ace.accdb) with Jackcess 4.0.5 in the eclipse-temurin:21-jdk image
# (needs Docker and network access to Maven Central):
#
#   sh tests/data/mdb/make.sh OUTDIR
#
# The jars are fetched from Maven Central and checked against its .sha1
# files. Jackcess copies its bundled empty database for each file format and
# stamps the creation time into MSysObjects, so the output is not
# byte-for-byte reproducible.
set -eu
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm -v "$out:/out" -v "$here:/gen:ro" -w /tmp eclipse-temurin:21-jdk sh -euc '
    m=https://repo1.maven.org/maven2
    for u in com/healthmarketscience/jackcess/jackcess/4.0.5/jackcess-4.0.5.jar \
             org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar \
             commons-logging/commons-logging/1.2/commons-logging-1.2.jar; do
        f=$(basename "$u")
        curl -sfLO "$m/$u"
        echo "$(curl -sfL "$m/$u.sha1" | cut -c1-40)  $f" | sha1sum -c -
    done
    TZ=UTC java -Duser.timezone=UTC \
        -cp jackcess-4.0.5.jar:commons-lang3-3.12.0.jar:commons-logging-1.2.jar \
        /gen/Gen.java /out
'
