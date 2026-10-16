set -e
# Runs inside fillyfoal-proxmox:bookworm (tests/data/proxmox/Dockerfile)
# with host name "fillyfoal"; writes to /out. See make-external.sh.
umask 022
T=/tmp/build
rm -rf $T && mkdir -p $T/src/sub && cd $T/src
printf 'Hello from fillyfoal.\nThis file sits in a pxar archive.\n' > hello.txt
seq 1 3000 > sub/numbers.txt
printf 'second file in the subdirectory\n' > sub/notes.txt
ln -s hello.txt link-to-hello
ln sub/notes.txt hardlink-to-notes
mkfifo pipe
mknod chardev c 1 3
setfattr -n user.comment -v 'neutral attribute' hello.txt
setfacl -m u:1000:r-- sub/notes.txt
setfacl -d -m g:100:r-x sub
: > empty.txt
find $T/src -exec touch -h -d '2026-01-02 03:04:05 UTC' {} +
cd $T
rm -f /out/archive.pxar /out/split.mpxar /out/split.ppxar
pxar create /out/archive.pxar src
pxar create /out/split.mpxar src --payload-output /out/split.ppxar
pxar list /out/archive.pxar
dpkg-query -W proxmox-backup-client
