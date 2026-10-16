set -e
# Runs inside fillyfoal-proxmox:bookworm (tests/data/proxmox/Dockerfile)
# with host name "fillyfoal" and a tmpfs on /run; writes to /out. See
# make-external.sh. Starts a throwaway Proxmox Backup Server in the
# container, backs up a small tree of every entry kind and a sparse disk
# image with proxmox-backup-client, and copies out the snapshot's index
# files and its catalog (decoded from the catalog's chunks).
L=/usr/lib/x86_64-linux-gnu/proxmox-backup
mkdir -p /run/proxmox-backup && chown backup:backup /run/proxmox-backup
$L/proxmox-backup-api > /tmp/api.log 2>&1 &
sleep 8
runuser -u backup -- $L/proxmox-backup-proxy > /tmp/proxy.log 2>&1 &
sleep 8
mkdir -p /datastore && chown backup:backup /datastore
proxmox-backup-manager datastore create store1 /datastore/store1 >/dev/null
# A throwaway account on the throwaway server.
proxmox-backup-manager user create fillyfoal@pbs --password 'throwaway-fillyfoal'
proxmox-backup-manager acl update /datastore/store1 DatastoreAdmin --auth-id fillyfoal@pbs
FP=$(proxmox-backup-manager cert info | awk '/Fingerprint/ {print $NF}')
export PBS_PASSWORD='throwaway-fillyfoal' PBS_FINGERPRINT=$FP PBS_REPOSITORY='fillyfoal@pbs@localhost:store1'

# Every kind of catalog entry, and 12 MiB of random data so the archive
# is cut into several chunks.
mkdir -p /src/files/docs/notes /src/files/dev /src/image
printf 'Hello from fillyfoal.\n' > /src/files/hello.txt
seq 1 2000 > /src/files/docs/numbers.txt
printf 'a note\n' > /src/files/docs/notes/note.txt
head -c 12582912 /dev/urandom > /src/files/random.bin
ln -s docs/numbers.txt /src/files/link
ln /src/files/hello.txt /src/files/hardlink.txt
mkfifo /src/files/dev/fifo
mknod /src/files/dev/null-device c 1 3
mknod /src/files/dev/loop-device b 7 0
python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("/src/files/dev/socket")'
printf 'old\n' > /src/files/docs/old.txt
find /src -exec touch -h -d '2026-01-02 03:04:05 UTC' {} +
# A file dated before 1970: the catalog writes negative times its own way.
touch -d '1965-06-07 08:09:10 UTC' /src/files/docs/old.txt
# A sparse 9 MiB image: two all-zero 4 MiB chunks and 1 MiB of random data.
truncate -s 8M /src/image/disk.img
head -c 1048576 /dev/urandom >> /src/image/disk.img
proxmox-backup-client backup files.pxar:/src/files disk.img:/src/image/disk.img \
  --backup-id fillyfoal --backup-time 1767323045 >/dev/null 2>&1
snap=$(ls -d /datastore/store1/host/fillyfoal/*/)
cp "$snap/files.pxar.didx" "$snap/disk.img.fidx" /out/
# The raw catalog: the decoded chunks of catalog.pcat1.didx, in order.
python3 - "$snap/catalog.pcat1.didx" > /tmp/catalog.chunks <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
for i in range(4096, len(d), 40):
    print(d[i + 8:i + 40].hex())
PY
: > /out/catalog.pcat1
while read h; do
  proxmox-backup-debug inspect chunk "/datastore/store1/.chunks/$(echo "$h" | cut -c1-4)/$h" --decode /tmp/c.bin >/dev/null
  cat /tmp/c.bin >> /out/catalog.pcat1
done < /tmp/catalog.chunks
proxmox-backup-client catalog dump "host/fillyfoal/$(basename "$snap")" 2>&1 | head -40 || true
ls -l /out
dpkg-query -W proxmox-backup-client proxmox-backup-server
