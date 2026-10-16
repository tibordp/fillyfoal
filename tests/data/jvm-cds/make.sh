#!/bin/bash
# HotSpot CDS archives for tests/fixtures/external/jvm-cds/.
# Run once per JDK (17, 21, 25); writes /tmp/fixtures/jvm-cds/out/$JDK/*.jsa:
#   mkdir -p /tmp/fixtures/jvm-cds/out
#   cp tests/data/jvm-cds/make.sh /tmp/fixtures/jvm-cds/run.sh
#   for j in 17 21 25; do
#     docker run --rm --hostname fillyfoal -e JDK=$j -v /tmp/fixtures/jvm-cds:/work -w /work \
#       eclipse-temurin:$j-jdk bash /work/run.sh
#   done
# Then (fixtures stored as zstd -19, the harness decompresses `.raw.zst`):
#   zstd -19 out/17/dynamic.jsa -o jdk17-dynamic.jsa.raw.zst   (likewise 21, 25)
#   zstd -19 out/21/dynamic-on-static.jsa -o jdk21-dynamic-on-static.jsa.raw.zst
#   head -c 73728 out/21/static.jsa | zstd -19 -o jdk21-static-prefix.jsa.raw.zst   (likewise 17)
set -e
cd /work
OUT=/work/out/${JDK:-21}; mkdir -p app $OUT
cat > app/Hello.java <<'X'
public class Hello {
  public static void main(String[] a) { System.out.println("hello " + new java.util.ArrayList<String>().size()); }
}
X
cd app
javac -d . Hello.java
jar cf hello.jar Hello.class
java -version 2>&1
# minimal static archive from a tiny class list
printf 'java/lang/Object\njava/lang/String\nHello\n' > tiny.classlist
java -Xshare:dump -XX:SharedClassListFile=tiny.classlist -XX:SharedArchiveFile=$OUT/static.jsa -cp hello.jar -Xlog:disable 2>&1 | tail -2 || true
# dynamic archive on top of the JDK's default CDS archive
java -XX:ArchiveClassesAtExit=$OUT/dynamic.jsa -cp hello.jar -Xlog:disable Hello
# dynamic archive on top of our own static archive (records the base archive name)
java -XX:SharedArchiveFile=$OUT/static.jsa -XX:ArchiveClassesAtExit=$OUT/dynamic-on-static.jsa -cp hello.jar -Xlog:disable Hello
ls -la $OUT
