#!/bin/sh
# Writes the external innodb/, innodb-redo/ and myisam-data/ fixtures with
# the official MySQL 9.7.1 and MariaDB 10.5.29 Docker images: a small
# database `shop` (mysql.sql, mariadb.sql) is created, the server is shut
# down cleanly, and its files are copied out.
#
# MySQL: fruit.ibd (dynamic rows, SDI dictionary, a secondary index, a
# deleted row), notes.ibd (redundant rows, an off-page LOB), the first 16
# pages of ibdata1 and the first 8 of undo_001 (the full files are 12 and
# 16 MiB), the redo file in use (#innodb_redo/#ib_redoN, 256 KiB with
# --innodb-redo-log-capacity=8M) and two MyISAM data files.
# MariaDB: fruit.ibd (full_crc32), packed.ibd (ROW_FORMAT=COMPRESSED,
# 4 KiB pages), ib_logfile0 (10.5 format, 2 MiB) and a MyISAM data file
# with a split row.
#
# LSNs, transaction IDs and times differ between runs.
#
#   sh tests/data/innodb/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
here="$root/tests/data/innodb"
work=/tmp/fixtures/data-innodb
rm -rf "$work"
mkdir -p "$work/mysql" "$work/mariadb"

wait_ready() {
	i=0
	until docker logs "$1" 2>&1 | grep -q "Version: .*port: 3306 "; do
		i=$((i + 1))
		[ "$i" -lt 120 ] || { echo "server did not start" >&2; exit 1; }
		sleep 2
	done
}

# MySQL
docker rm -f fillyfoal-mysql >/dev/null 2>&1 || true
docker run -d --name fillyfoal-mysql --hostname fillyfoal -e MYSQL_ALLOW_EMPTY_PASSWORD=1 \
	mysql:9.7.1 --innodb-redo-log-capacity=8M --innodb-buffer-pool-size=32M --skip-log-bin >/dev/null
wait_ready fillyfoal-mysql
docker exec -i fillyfoal-mysql mysql -uroot <"$here/mysql.sql"
# SIGTERM shuts the server down cleanly (all pages flushed).
docker stop -t 120 fillyfoal-mysql >/dev/null
docker cp fillyfoal-mysql:/var/lib/mysql/shop "$work/mysql/shop"
docker cp fillyfoal-mysql:/var/lib/mysql/ibdata1 "$work/mysql/ibdata1"
docker cp fillyfoal-mysql:/var/lib/mysql/undo_001 "$work/mysql/undo_001"
docker cp "fillyfoal-mysql:/var/lib/mysql/#innodb_redo" "$work/mysql/redo"
docker rm fillyfoal-mysql >/dev/null

# MariaDB
docker rm -f fillyfoal-mariadb >/dev/null 2>&1 || true
docker run -d --name fillyfoal-mariadb --hostname fillyfoal -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 \
	mariadb:10.5.29 --innodb-log-file-size=2M --innodb-buffer-pool-size=32M --skip-log-bin >/dev/null
wait_ready fillyfoal-mariadb
docker exec -i fillyfoal-mariadb mysql -uroot <"$here/mariadb.sql"
docker stop -t 120 fillyfoal-mariadb >/dev/null
docker cp fillyfoal-mariadb:/var/lib/mysql/shop "$work/mariadb/shop"
docker cp fillyfoal-mariadb:/var/lib/mysql/ib_logfile0 "$work/mariadb/ib_logfile0"
docker rm fillyfoal-mariadb >/dev/null

out="$root/tests/fixtures/external"
mkdir -p "$out/innodb" "$out/innodb-redo" "$out/myisam-data"
gzip -9 -n <"$work/mysql/shop/fruit.ibd" >"$out/innodb/mysql-fruit.ibd.gz"
gzip -9 -n <"$work/mysql/shop/notes.ibd" >"$out/innodb/mysql-notes.ibd.gz"
head -c 262144 "$work/mysql/ibdata1" | gzip -9 -n >"$out/innodb/mysql-ibdata1-head.gz"
head -c 131072 "$work/mysql/undo_001" | gzip -9 -n >"$out/innodb/mysql-undo_001-head.gz"
gzip -9 -n <"$work/mariadb/shop/fruit.ibd" >"$out/innodb/mariadb-fruit.ibd.gz"
gzip -9 -n <"$work/mariadb/shop/packed.ibd" >"$out/innodb/mariadb-packed.ibd.gz"
# The redo file in use is the one without the _tmp suffix.
redo=$(ls "$work/mysql/redo" | grep -v _tmp | head -n 1)
gzip -9 -n <"$work/mysql/redo/$redo" >"$out/innodb-redo/mysql-ib_redo.gz"
gzip -9 -n <"$work/mariadb/ib_logfile0" >"$out/innodb-redo/mariadb-ib_logfile0.gz"
cp "$work/mysql/shop/legacy.MYD" "$out/myisam-data/mysql-dynamic.MYD"
cp "$work/mysql/shop/fixed.MYD" "$out/myisam-data/mysql-fixed.MYD"
cp "$work/mariadb/shop/legacy.MYD" "$out/myisam-data/mariadb-split.MYD"
chmod 644 "$out"/myisam-data/*.MYD
