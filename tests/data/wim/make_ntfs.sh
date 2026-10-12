#!/bin/sh
# Builds tests/fixtures/external/wim/ntfs-acl.wim with wimlib-imagex
# (Debian bookworm's wimtools) in NTFS volume capture mode, which reads an
# NTFS image through libntfs-3g and keeps its security descriptors, short
# names and named data streams:
#
#     sh tests/data/wim/make_ntfs.sh OUTDIR
#
# The 4 MiB volume is made by mkntfs (label "fillyfoal") and filled with
# ntfscp, without mounting it. Not byte-reproducible (the WIM GUID, the XML
# times and the volume's own times differ per run).
set -e
out=$(cd "$1" && pwd)
docker run --rm -v "$out:/out" debian:bookworm-slim sh -c '
  set -e
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends wimtools ntfs-3g >/dev/null
  cd /tmp
  truncate -s 4M vol.img
  mkntfs -q -F -f -L fillyfoal -s 512 -c 4096 vol.img
  printf "hello from ntfs\n" > hello.txt
  printf "alternate stream\n" > ads.txt
  ntfscp -q vol.img hello.txt /hello.txt
  ntfscp -q -N extra vol.img ads.txt /hello.txt
  wimcapture vol.img /out/ntfs-acl.wim fillyfoal --compress=XPRESS
  wimlib-imagex --version | head -n 1
  wimlib-imagex dir /out/ntfs-acl.wim 1 --detailed
'
