#!/bin/sh
# Runs in a debian:trixie container (see signed.sh): a four-commit repo by
# a neutral author, the last two commits signed with a throwaway SSH key
# made here, one annotated SSH-signed tag, repacked so the edited file
# becomes an ofs-delta. Prints the commits and `git verify-pack -v`.
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq git openssh-client >/dev/null 2>&1
git --version > /work/out/version.txt
export HOME=/work/home GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"
ssh-keygen -q -t ed25519 -N '' -C 'fillyfoal test key' -f "$HOME/key"
git config --global user.name fillyfoal
git config --global user.email test@example.com
git config --global init.defaultBranch main
git config --global gpg.format ssh
git config --global user.signingkey "$HOME/key.pub"
git init -q /work/repo
cd /work/repo
export GIT_AUTHOR_DATE='2026-01-01T00:00:00Z' GIT_COMMITTER_DATE='2026-01-01T00:00:00Z'
seq 1 200 | sed 's/^/line /' > notes.txt
printf 'fillyfoal git fixture\n' > README
git add notes.txt README
git commit -q -m 'Add notes'
GIT_AUTHOR_DATE='2026-01-02T00:00:00Z' GIT_COMMITTER_DATE='2026-01-02T00:00:00Z'
sed -i 's/^line 100$/line one hundred/' notes.txt
git commit -q -am 'Spell out line 100'
GIT_AUTHOR_DATE='2026-01-03T00:00:00Z' GIT_COMMITTER_DATE='2026-01-03T00:00:00Z'
echo 'line 201' >> notes.txt
git commit -q -S -am 'Append line 201 (signed)'
GIT_AUTHOR_DATE='2026-01-04T00:00:00Z' GIT_COMMITTER_DATE='2026-01-04T00:00:00Z'
sed -i 's/^line 1$/line one/' notes.txt
git commit -q -S -am 'Spell out line 1 (signed)'
git tag -s -m 'Signed release' v1.0
git repack -q -a -d -f --depth=10 --window=10
git cat-file -p HEAD
git cat-file -p v1.0
git verify-pack -v .git/objects/pack/*.idx
cp .git/objects/pack/*.pack /work/out/signed.pack
