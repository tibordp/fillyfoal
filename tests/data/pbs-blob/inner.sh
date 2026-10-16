set -e
# Runs inside fillyfoal-proxmox:bookworm (tests/data/proxmox/Dockerfile)
# with host name "fillyfoal" and a tmpfs on /run; writes to /out. See
# make-external.sh. Starts a throwaway Proxmox Backup Server in the
# container, backs up a few neutral files with proxmox-backup-client
# (plain and encrypted) and copies blobs out of the datastore.
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

mkdir -p /src/files /src/image
printf 'Hello from fillyfoal.\nThis file sits in a pxar archive in a PBS chunk.\n' > /src/files/hello.txt
seq 1 2000 > /src/files/numbers.txt
find /src -exec touch -h -d '2026-01-02 03:04:05 UTC' {} +
# A 4 KiB image of random bytes: zstd cannot shrink it, so its chunk is
# stored uncompressed.
head -c 4096 /dev/urandom > /src/image/random.img
proxmox-backup-client key create /tmp/key.json --kdf none
S=/datastore/store1
proxmox-backup-client backup files.pxar:/src/files random.img:/src/image/random.img \
  --backup-id plain --backup-time 1767323045 >/dev/null 2>&1
proxmox-backup-client backup files.pxar:/src/files random.img:/src/image/random.img \
  --backup-id encrypted --backup-time 1767323046 --keyfile /tmp/key.json >/dev/null 2>&1

magic() { head -c 8 "$1" | od -An -tu1 | tr -s ' ' | sed 's/^ //'; }
pick() { # pick <magic> <name>: the smallest chunk with that magic
  best=""
  for f in $(find $S/.chunks -type f | sort); do
    if [ "$(magic "$f")" = "$1" ]; then
      if [ -z "$best" ] || [ "$(stat -c %s "$f")" -lt "$(stat -c %s "$best")" ]; then best=$f; fi
    fi
  done
  echo "$2 <- ${best#$S/}"
  cp "$best" "/out/$2"
}
pick "66 171 56 7 190 131 112 161" uncompressed-chunk.blob
pick "49 185 88 66 111 182 163 127" compressed-chunk.blob
pick "123 103 133 190 34 45 76 240" encrypted-chunk.blob
pick "230 89 27 191 11 191 216 11" encrypted-compressed-chunk.blob
cp $S/host/plain/*/index.json.blob /out/index.json.blob
# The chunk holding the plain files.pxar (the largest compressed one).
for f in $(find $S/.chunks -type f | sort); do
  if [ "$(magic "$f")" = "49 185 88 66 111 182 163 127" ] && [ "$(stat -c %s "$f")" -gt 1000 ]; then
    echo "pxar-chunk.blob <- ${f#$S/}"; cp "$f" /out/pxar-chunk.blob
  fi
done
ls -l /out
dpkg-query -W proxmox-backup-client proxmox-backup-server
