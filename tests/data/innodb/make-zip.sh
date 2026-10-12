#!/bin/sh
# Writes the external innodb/ fixtures of compressed and instantly altered
# tables with the official MySQL 9.7.1 and MariaDB 10.5.29 Docker images
# (as make.sh does for the others):
#
# - zip.sql on both servers: a ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=1
#   table of 40 rows, so its B-trees have node pointer pages, with a
#   secondary index, deleted and updated rows, NULLs and a few values
#   long enough to be stored off-page. Bulk inserts recompress pages, so
#   some records are in the compressed stream and some in the
#   modification log.
# - instant.sql on MySQL: a table altered with ALGORITHM=INSTANT
#   ADD COLUMN (at the end and in the middle) and DROP COLUMN, with rows
#   inserted between the changes, so records carry row versions.
#
# LSNs, transaction IDs and times differ between runs.
#
#   sh tests/data/innodb/make-zip.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
here="$root/tests/data/innodb"
work=/tmp/fixtures/data-innodb-zip
rm -rf "$work"
mkdir -p "$work"

wait_ready() {
	i=0
	until docker logs "$1" 2>&1 | grep -q "Version: .*port: 3306 "; do
		i=$((i + 1))
		[ "$i" -lt 120 ] || { echo "server did not start" >&2; exit 1; }
		sleep 2
	done
}

docker rm -f fillyfoal-zip-mysql >/dev/null 2>&1 || true
docker run -d --name fillyfoal-zip-mysql --hostname fillyfoal -e MYSQL_ALLOW_EMPTY_PASSWORD=1 \
	mysql:9.7.1 --innodb-redo-log-capacity=8M --innodb-buffer-pool-size=32M --skip-log-bin >/dev/null
wait_ready fillyfoal-zip-mysql
docker exec -i fillyfoal-zip-mysql mysql -uroot <"$here/zip.sql"
docker exec -i fillyfoal-zip-mysql mysql -uroot <"$here/instant.sql"
docker stop -t 120 fillyfoal-zip-mysql >/dev/null
docker cp fillyfoal-zip-mysql:/var/lib/mysql/shop/stock.ibd "$work/mysql-stock.ibd"
docker cp fillyfoal-zip-mysql:/var/lib/mysql/shop/inst.ibd "$work/mysql-inst.ibd"
docker rm fillyfoal-zip-mysql >/dev/null

docker rm -f fillyfoal-zip-mariadb >/dev/null 2>&1 || true
docker run -d --name fillyfoal-zip-mariadb --hostname fillyfoal -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 \
	mariadb:10.5.29 --innodb-log-file-size=2M --innodb-buffer-pool-size=32M --skip-log-bin >/dev/null
wait_ready fillyfoal-zip-mariadb
docker exec -i fillyfoal-zip-mariadb mysql -uroot <"$here/zip.sql"
docker stop -t 120 fillyfoal-zip-mariadb >/dev/null
docker cp fillyfoal-zip-mariadb:/var/lib/mysql/shop/stock.ibd "$work/mariadb-stock.ibd"
docker rm fillyfoal-zip-mariadb >/dev/null

out="$root/tests/fixtures/external/innodb"
mkdir -p "$out"
for f in mysql-stock mysql-inst mariadb-stock; do
	gzip -9 -n <"$work/$f.ibd" >"$out/$f.ibd.gz"
done
