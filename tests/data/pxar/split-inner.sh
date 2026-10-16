set -e
# Runs inside fillyfoal-proxmox:bookworm (tests/data/proxmox/Dockerfile)
# with host name "fillyfoal" and a tmpfs on /run; writes to /out. See
# make-split.sh. Starts a throwaway Proxmox Backup Server in the container,
# backs up a 100-file directory twice as a split archive
# (--change-detection-mode=metadata), changing one file and adding one in
# between, and rebuilds each snapshot's .mpxar and .ppxar streams from
# their chunks.
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

umask 022
mkdir -p /src/d/sub
# FILE_COUNT files of FILE_SIZE bytes: a line naming the file, then one
# shared 4 KiB pseudo-random block repeated (so the payload stream
# compresses well for storage); a text file in a subdirectory; a file with
# a capability. With 4 MiB of payloads in all the client reused nothing
# (it re-encodes when little would be reused); with 10 MiB it reuses whole
# chunks of the first payload stream, old start and tail markers included.
python3 - "${FILE_COUNT:-100}" "${FILE_SIZE:-100000}" <<'PY'
import random, sys
count, size = int(sys.argv[1]), int(sys.argv[2])
rng = random.Random(1)
block = bytes(rng.getrandbits(8) for _ in range(4096))
for i in range(100, 100 + count):
    head = f"file {i} of a neutral test tree\n".encode()
    body = (block * (size // 4096 + 2))[: size - len(head)]
    open(f"/src/d/f{i}.bin", "wb").write(head + body)
PY
seq 1 50000 > /src/d/sub/numbers.txt
printf 'a file with a capability\n' > /src/d/capable
setcap cap_net_raw+ep /src/d/capable
find /src -exec touch -h -d '2026-01-02 03:04:05 UTC' {} +
proxmox-backup-client backup x.pxar:/src/d --backup-id split \
  --change-detection-mode=metadata 2>&1 | grep -v '^$' | tail -6
# Files changed within a second of the previous run are not reused.
sleep 2
echo changed > /src/d/f105.bin
echo new > /src/d/new.txt
touch -h -d '2026-01-03 03:04:05 UTC' /src/d/f105.bin /src/d/new.txt /src/d
sleep 2
proxmox-backup-client backup x.pxar:/src/d --backup-id split \
  --change-detection-mode=metadata 2>&1 | grep -v '^$' | tail -12
S=/datastore/store1
n=0
for snap in $S/host/split/*/; do
  snap=${snap%/}
  n=$((n+1))
  t=/out/snap$n
  mkdir -p $t
  for idx in $snap/*.didx; do
    b=$(basename $idx .didx)
    : > $t/$b
    # A dynamic index: a 4096-byte header, then (end offset, SHA-256) records.
    python3 - "$idx" > /tmp/chunks <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
for i in range(4096, len(d), 40):
    print(d[i + 8:i + 40].hex())
PY
    while read h; do
      proxmox-backup-debug inspect chunk $S/.chunks/$(echo $h | cut -c1-4)/$h --decode /tmp/c.bin >/dev/null
      cat /tmp/c.bin >> $t/$b
    done < /tmp/chunks
    echo "$t/$b: $(wc -l < /tmp/chunks) chunks"
  done
done
ls -l /out/snap*
dpkg-query -W proxmox-backup-client proxmox-backup-server
