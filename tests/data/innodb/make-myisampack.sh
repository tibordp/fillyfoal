#!/bin/sh
# Writes the external myisam-packed/ fixtures: two MyISAM tables made by
# tests/data/innodb/myisampack.sql on MariaDB 11.4.13 (official Docker
# image), copied out after a clean shutdown and compressed with that
# image's myisampack: crate.MYD (CHAR, VARCHAR, ENUM, a constant column,
# NULLs, a DATE) and memo.MYD (a TEXT column, so records carry a blob
# length).
#
#   sh tests/data/innodb/make-myisampack.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/data-myisampack
rm -rf "$work"
mkdir -p "$work"
name=fillyfoal-myisampack
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --hostname fillyfoal -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 \
	mariadb:11.4.13 --innodb-buffer-pool-size=32M --skip-log-bin >/dev/null
i=0
until docker logs "$name" 2>&1 | grep -q "Version: .*port: 3306 "; do
	i=$((i + 1))
	[ "$i" -lt 120 ] || { echo "server did not start" >&2; exit 1; }
	sleep 2
done
docker exec -i "$name" mariadb -uroot <"$root/tests/data/innodb/myisampack.sql"
docker stop -t 120 "$name" >/dev/null
for t in crate memo; do
	for ext in MYD MYI frm; do
		docker cp "$name:/var/lib/mysql/shop/$t.$ext" "$work/$t.$ext"
	done
done
docker rm "$name" >/dev/null
chmod 666 "$work"/*
for t in crate memo; do
	# -f: the tables are small enough for myisampack to decline them otherwise.
	docker run --rm -v "$work:/w" --entrypoint myisampack mariadb:11.4.13 -f -s "/w/$t"
done
out="$root/tests/fixtures/external/myisam-packed"
mkdir -p "$out"
cp "$work/crate.MYD" "$out/crate.MYD"
cp "$work/memo.MYD" "$out/memo.MYD"
chmod 644 "$out"/*.MYD
