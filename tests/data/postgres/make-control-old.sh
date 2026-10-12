#!/bin/sh
# Writes the external pg-control/pg_control-{10,11,12} fixtures: the
# control files (versions 1002, 1100 and 1201) of fresh clusters of the
# official PostgreSQL 10.21, 11.16 and 12.22 Docker images, after a clean
# shutdown, and next to them (in the work directory) what each version's
# pg_controldata prints, to check the dissector against.
#
# The system identifier and times differ between runs.
#
#   sh tests/data/postgres/make-control-old.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/data-pg-control-old
rm -rf "$work"
mkdir -p "$work"
out="$root/tests/fixtures/external/pg-control"
mkdir -p "$out"
for v in 10.21 11.16 12.22; do
	major=${v%%.*}
	name="fillyfoal-pgcontrol-$major"
	docker rm -f "$name" >/dev/null 2>&1 || true
	docker run -d --name "$name" --hostname fillyfoal -e POSTGRES_PASSWORD=fillyfoal \
		"postgres:$v" >/dev/null
	i=0
	until docker logs "$name" 2>&1 | grep -q "PostgreSQL init process complete" &&
		docker exec "$name" pg_isready -U postgres -q 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -lt 120 ] || { echo "server did not start" >&2; exit 1; }
		sleep 2
	done
	docker stop -t 120 "$name" >/dev/null
	mkdir -p "$work/$major/global"
	docker cp "$name:/var/lib/postgresql/data/global/pg_control" "$work/$major/global/pg_control"
	docker rm "$name" >/dev/null
	docker run --rm -v "$work/$major:/d" --entrypoint pg_controldata "postgres:$v" -D /d \
		>"$work/$major/pg_controldata.txt"
	cp "$work/$major/global/pg_control" "$out/pg_control-$major"
	chmod 644 "$out/pg_control-$major"
done
