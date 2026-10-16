#!/bin/sh
# Runs in a debian:trixie container (see make.sh).
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq git >/dev/null 2>&1
git --version > /work/out/version.txt
export HOME=/work/home GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"
git config --global user.name fillyfoal
git config --global user.email fillyfoal@example.invalid
git config --global init.defaultBranch main
git config --global gc.auto 0
git config --global maintenance.auto false

n=0
commit() {
    # commit <message> [unix date]
    n=$((n + 1))
    when=${2:-$((1767225600 + n * 86400))}
    export GIT_AUTHOR_DATE="@$when +0000" GIT_COMMITTER_DATE="@$when +0000"
    git add -A
    git commit -q --allow-empty -m "$1"
}
merge() {
    # merge <message> <branch>...
    n=$((n + 1))
    when=$((1767225600 + n * 86400))
    export GIT_AUTHOR_DATE="@$when +0000" GIT_COMMITTER_DATE="@$when +0000"
    msg=$1
    shift
    git merge -q --no-ff -m "$msg" "$@"
}

history() {
    # part 1: a line of commits, two branches and a merge
    printf 'fillyfoal commit-graph fixture\n' > README
    commit 'Initial commit'
    mkdir -p src docs
    printf 'one\n' > src/a.txt
    commit 'Add a'
    git checkout -q -b feature
    printf 'two\n' > src/b.txt
    commit 'Add b'
    git checkout -q main
    printf 'notes\n' > docs/notes.txt
    commit 'Add notes'
    merge 'Merge feature' feature
}
history2() {
    # part 2: an octopus merge of three branches, then a commit dated in
    # 2100 and its child dated 1970 (the corrected date offset overflows
    # 31 bits: GDO2)
    for b in x y z; do
        git checkout -q -b "$b" main
        printf '%s\n' "$b" > "src/$b.txt"
        commit "Add $b"
    done
    git checkout -q main
    merge 'Octopus merge' x y z
    printf 'future\n' > docs/future.txt
    commit 'From the future' 4102444800
    printf 'past\n' > docs/past.txt
    commit 'From the past' 1
}

git init -q /work/repo
cd /work/repo
history
history2
git commit-graph write --reachable --changed-paths
cp .git/objects/info/commit-graph /work/out/commit-graph
git commit-graph verify
git log --format='%H %T %P %ct %s' --all > /work/out/log.txt

git init -q /work/split
cd /work/split
n=0
history
git commit-graph write --reachable --split=no-merge
history2
git commit-graph write --reachable --split=no-merge --changed-paths
git commit-graph verify
cat .git/objects/info/commit-graphs/commit-graph-chain
base=$(sed -n 1p .git/objects/info/commit-graphs/commit-graph-chain)
top=$(sed -n 2p .git/objects/info/commit-graphs/commit-graph-chain)
cp ".git/objects/info/commit-graphs/graph-$base.graph" /work/out/split-base.graph
cp ".git/objects/info/commit-graphs/graph-$top.graph" /work/out/split-top.graph

git init -q --object-format=sha256 /work/sha256
cd /work/sha256
n=0
history
history2
git commit-graph write --reachable
cp .git/objects/info/commit-graph /work/out/sha256.graph
git commit-graph verify
