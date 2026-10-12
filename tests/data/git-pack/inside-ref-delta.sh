#!/bin/sh
# Runs in a debian:trixie container (see ref-delta.sh). Prints the objects
# of each pack (`git verify-pack -v`, after `index-pack --fix-thin` for the
# thin one).
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq git >/dev/null 2>&1
git --version > /work/out/version.txt
export HOME=/work/home GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"
git config --global user.name fillyfoal
git config --global user.email test@example.com
git config --global init.defaultBranch main
git init -q /work/repo
cd /work/repo
day=1
commit() {
    export GIT_AUTHOR_DATE="2026-01-0${day}T00:00:00Z" GIT_COMMITTER_DATE="2026-01-0${day}T00:00:00Z"
    git add -A
    git commit -q -m "$1"
    day=$((day + 1))
}
seq 1 300 | sed 's/^/line /' > notes.txt
printf 'fillyfoal ref-delta fixture\n' > README
commit 'Add notes'
# Each commit rewrites a different block of 40 lines and appends some, so
# every version is closest to the next one and the deltas chain.
for n in 1 2 3; do
    sed -i "$((n * 70)),$((n * 70 + 39))s/^line /line (rewrite $n) /" notes.txt
    seq 1 10 | sed "s/^/appended in $n: /" >> notes.txt
    commit "Rewrite block $n"
done
git rev-list --objects --all | git pack-objects -q --stdout --depth=10 --window=10 > /work/out/ref-delta.pack
printf 'HEAD\n^HEAD~1\n' | git pack-objects -q --revs --thin --stdout > /work/out/thin.pack
mkdir /work/check
cp /work/out/ref-delta.pack /work/check/
git index-pack /work/check/ref-delta.pack >/dev/null
git verify-pack -v /work/check/ref-delta.idx
git index-pack --stdin --fix-thin /work/check/thin-fixed.pack < /work/out/thin.pack >/dev/null
git verify-pack -v /work/check/thin-fixed.idx
