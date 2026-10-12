#!/bin/sh
# Writes tests/fixtures/external/unreal-pak/repak-*.pak with repak
# (https://github.com/trumank/repak, repak_cli 0.2.3, commit 355b5f62),
# built and run in Docker:
#
#   docker run --rm -v "$PWD/tools:/out" rust:1-bookworm \
#     cargo install --git https://github.com/trumank/repak repak_cli --locked --root /out/repak
#   docker run --rm -v "$PWD/tools:/tools" -v /tmp/fixtures/games-retro-pak:/w \
#     rust:1-bookworm sh /w/make-repak.sh
#
# The input tree is made here: two small text files and one 80 KiB line that
# zlib compresses in two 64 KiB blocks.
set -e
cd /w
rm -rf content out && mkdir -p content/Game/Config content/Game/Content/Maps out
printf '[/Script/EngineSettings.GeneralProjectSettings]\nProjectName=fillyfoal\n' > content/Game/Config/DefaultGame.ini
printf 'A pak written by repak for the fillyfoal tests.\n' > content/Game/Content/readme.txt
i=0
while [ $i -lt 5120 ]; do
  printf '0123456789abcdef'
  i=$((i + 1))
done > content/Game/Content/Maps/Level.txt
for spec in V3:Zlib V8B:Zlib V11:Zlib V11:Zstd V8A:LZ4 V9:Gzip; do
  v=${spec%%:*}; c=${spec#*:}
  lower=$(echo "$v-$c" | tr 'A-Z' 'a-z')
  /tools/repak/bin/repak pack -q --version "$v" --compression "$c" content "out/repak-$lower.pak"
done
ls -l out
