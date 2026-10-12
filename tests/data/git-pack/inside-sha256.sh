#!/bin/sh
# Runs in a debian:trixie container (see sha256.sh). Prints the objects
# (`git verify-pack -v`) and the index entries (`git ls-files -s`).
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq git >/dev/null 2>&1
git --version > /work/out/version.txt
export HOME=/work/home GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"
git config --global user.name fillyfoal
git config --global user.email test@example.com
git config --global init.defaultBranch main
git init -q --object-format=sha256 /work/repo
cd /work/repo
export GIT_AUTHOR_DATE='2026-01-01T00:00:00Z' GIT_COMMITTER_DATE='2026-01-01T00:00:00Z'
seq 1 200 | sed 's/^/line /' > notes.txt
printf 'fillyfoal sha256 fixture\n' > README
git add notes.txt README
git commit -q -m 'Add notes'
export GIT_AUTHOR_DATE='2026-01-02T00:00:00Z' GIT_COMMITTER_DATE='2026-01-02T00:00:00Z'
sed -i 's/^line 100$/line one hundred/' notes.txt
git commit -q -am 'Spell out line 100'
export GIT_AUTHOR_DATE='2026-01-03T00:00:00Z' GIT_COMMITTER_DATE='2026-01-03T00:00:00Z'
echo 'line 201' >> notes.txt
git commit -q -am 'Append line 201'
git repack -q -a -d -f --depth=10 --window=10
git verify-pack -v .git/objects/pack/*.idx
git ls-files -s
cp .git/objects/pack/*.pack /work/out/sha256.pack
cp .git/objects/pack/*.idx /work/out/sha256.idx
cp .git/index /work/out/sha256.index
