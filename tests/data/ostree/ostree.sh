#!/bin/sh
# OSTree objects from an archive-mode repository: two commits of a small
# tree, a summary, a self-contained static delta with its part inline and
# a delta between the commits with its part in a file of its own.
# Run as root in alpine:3.22 with `apk add ostree`; writes into $1.
set -e
out=${1:-/out}
work=$(mktemp -d)
cd "$work"
mkdir -p tree/usr/share/demo tree/etc
printf 'Hello, OSTree!\n' > tree/usr/share/demo/hello.txt
printf 'key=value\n' > tree/etc/demo.conf
ln -s ../usr/share/demo/hello.txt tree/etc/hello-link
chmod 0755 tree tree/usr tree/usr/share tree/usr/share/demo tree/etc
chmod 0644 tree/usr/share/demo/hello.txt tree/etc/demo.conf
ostree init --mode=archive --repo=repo
c1=$(ostree commit --repo=repo --branch=demo/stable --owner-uid=0 --owner-gid=0 \
  --no-xattrs --timestamp='2024-01-02 03:04:05 UTC' \
  --subject='Demo commit' --body='A small tree for fillyfoal.' \
  --add-metadata-string=version=1.0 \
  --add-detached-metadata-string=note=fillyfoal tree)
ostree static-delta generate --repo=repo --empty --inline demo/stable
printf 'Hello again, OSTree!\n' > tree/usr/share/demo/hello.txt
printf 'second file\n' > tree/usr/share/demo/new.txt
chmod 0644 tree/usr/share/demo/new.txt
c2=$(ostree commit --repo=repo --branch=demo/stable --owner-uid=0 --owner-gid=0 \
  --no-xattrs --timestamp='2024-02-03 04:05:06 UTC' \
  --subject='Second commit' --add-metadata-string=version=1.1 tree)
ostree static-delta generate --repo=repo --from="$c1" --to="$c2"
ostree summary --repo=repo -u

obj() { # path of the object of type $2 with checksum $1
  echo "repo/objects/$(echo "$1" | cut -c1-2)/$(echo "$1" | cut -c3-).$2"
}
mkdir -p "$out/ostree-commit" "$out/ostree-commitmeta" "$out/ostree-dirtree" \
  "$out/ostree-dirmeta" "$out/ostree-filez" "$out/ostree-summary" \
  "$out/ostree-delta" "$out/ostree-delta-part"
cp "$(obj "$c1" commit)" "$out/ostree-commit/demo.commit"
cp "$(obj "$c2" commit)" "$out/ostree-commit/second.commit"
cp "$(obj "$c1" commitmeta)" "$out/ostree-commitmeta/demo.commitmeta"
root=$(ostree ls --repo=repo -C -d "$c1" / | awk '{print $5}')
rootmeta=$(ostree ls --repo=repo -C -d "$c1" / | awk '{print $6}')
cp "$(obj "$root" dirtree)" "$out/ostree-dirtree/root.dirtree"
cp "$(obj "$rootmeta" dirmeta)" "$out/ostree-dirmeta/root.dirmeta"
etc=$(ostree ls --repo=repo -C -d "$c1" /etc | awk '{print $5}')
cp "$(obj "$etc" dirtree)" "$out/ostree-dirtree/etc.dirtree"
hello=$(ostree ls --repo=repo -C "$c1" /usr/share/demo/hello.txt | awk '{print $5}')
link=$(ostree ls --repo=repo -C "$c1" /etc/hello-link | awk '{print $5}')
cp "$(obj "$hello" filez)" "$out/ostree-filez/hello.filez"
cp "$(obj "$link" filez)" "$out/ostree-filez/link.filez"
cp repo/summary "$out/ostree-summary/summary"
# The self-contained delta (inline part) and the delta between commits
# (part 0 in a file of its own).
for d in $(find repo/deltas -name superblock); do
  if [ -e "$(dirname "$d")/0" ]; then
    cp "$d" "$out/ostree-delta/superblock"
    cp "$(dirname "$d")/0" "$out/ostree-delta-part/0"
  else
    cp "$d" "$out/ostree-delta/inline.superblock"
  fi
done
