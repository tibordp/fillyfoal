#!/bin/sh
# Writes the external pg-relation/, pg-control/ and pg-wal/ fixtures with
# the official PostgreSQL 17.9 Docker image: a cluster with data checksums
# and 1 MiB WAL segments (initdb --data-checksums --wal-segsize=1), a
# database made by shop.sql, then a clean shutdown.
#
# pg-relation: the table's heap, its free space map and visibility map
# (after VACUUM), and its primary key B-tree; pg-control: global/pg_control;
# pg-wal: the segment holding the changes to `crate` (wal_recycle=off and wal_keep_size, so
# the segment is new and zero after its last record, the log switch).
#
# OIDs, LSNs, XIDs, the system identifier and times differ between runs.
#
#   sh tests/data/postgres/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/data-postgres
rm -rf "$work"
mkdir -p "$work"
name=fillyfoal-postgres
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --hostname fillyfoal -e POSTGRES_PASSWORD=fillyfoal \
	-e POSTGRES_INITDB_ARGS="--wal-segsize=1 --data-checksums" \
	postgres:17.9 -c wal_level=replica -c wal_recycle=off -c wal_keep_size=64MB -c shared_buffers=16MB >/dev/null
i=0
until docker exec "$name" pg_isready -U postgres -q 2>/dev/null && \
	docker logs "$name" 2>&1 | grep -q "PostgreSQL init process complete"; do
	i=$((i + 1))
	[ "$i" -lt 120 ] || { echo "server did not start" >&2; exit 1; }
	sleep 2
done
sleep 2
docker exec -i "$name" psql -U postgres -q <"$root/tests/data/postgres/shop.sql" >/dev/null
docker exec "$name" cat /tmp/names >"$work/names"
docker stop -t 120 "$name" >/dev/null
heap=$(sed -n 1p "$work/names")
pkey=$(sed -n 2p "$work/names")
wal=$(sed -n 3p "$work/names")
data=/var/lib/postgresql/data
for f in "$heap" "${heap}_fsm" "${heap}_vm" "$pkey" global/pg_control "pg_wal/$wal"; do
	docker cp "$name:$data/$f" "$work/$(basename "$f")"
done
docker rm "$name" >/dev/null

out="$root/tests/fixtures/external"
mkdir -p "$out/pg-relation" "$out/pg-control" "$out/pg-wal"
cp "$work/$(basename "$heap")" "$out/pg-relation/fruit-heap"
cp "$work/$(basename "$heap")_fsm" "$out/pg-relation/fruit-heap_fsm"
cp "$work/$(basename "$heap")_vm" "$out/pg-relation/fruit-heap_vm"
cp "$work/$(basename "$pkey")" "$out/pg-relation/fruit-pkey"
cp "$work/pg_control" "$out/pg-control/pg_control"
gzip -9 -n <"$work/$wal" >"$out/pg-wal/$wal.gz"
chmod 644 "$out"/pg-relation/* "$out/pg-control/pg_control"
