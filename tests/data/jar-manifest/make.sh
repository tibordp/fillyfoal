#!/bin/sh
# Builds tests/fixtures/external/jar-manifest/MANIFEST.MF: the manifest the
# JDK's `jar` tool writes (lines wrapped at 72 bytes, CRLF), from a small
# input manifest with a long Class-Path and a per-entry section. Uses the
# eclipse-temurin:21-jdk image.
set -eu
W=/tmp/fixtures/text-jar-manifest
rm -rf "$W"
mkdir -p "$W/src/com/example" "$W/out"
cd "$W"
printf 'package com.example;\npublic class Main { public static void main(String[] a) { System.out.println("hi"); } }\n' \
    > src/com/example/Main.java
printf 'Class-Path: lib/fillyfoal-core-1.0.0.jar lib/fillyfoal-text-1.0.0.jar lib/fillyfoal-archive-1.0.0.jar lib/fillyfoal-image-1.0.0.jar\nImplementation-Title: fillyfoal demo\nImplementation-Version: 1.0\n\nName: com/example/\nSealed: true\nImplementation-Vendor: fillyfoal\n' \
    > m.txt
docker run --rm -v "$W:/w" -w /w eclipse-temurin:21-jdk sh -c \
    'javac -d classes src/com/example/Main.java &&
     jar --create --file out/demo.jar --main-class com.example.Main --manifest m.txt -C classes . &&
     cd out && jar xf demo.jar META-INF/MANIFEST.MF && java -version 2>&1 | head -1 &&
     chown -R '"$(id -u):$(id -g)"' /w'
echo "$W/out/META-INF/MANIFEST.MF"
