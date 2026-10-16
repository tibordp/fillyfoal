#!/bin/sh
# Builds the mysql-binlog fixtures with real servers in throwaway
# containers (host name "fillyfoal"): the official mysql:9.7.1 and
# mariadb:10.5 images. Each server runs workload.sql (row-based events with
# full table-map metadata, then a few statement-based ones), and the binary
# log file holding it is copied out:
#
#   mysql-rows.bin           MySQL 9.7.1: GTIDs, CRC32 checksums, row and
#                            statement events
#   mysql-compressed.bin     MySQL, binlog_transaction_compression=ON: a
#                            transaction in a zstd Transaction_payload event
#   mysql-nochecksum.bin     MySQL, binlog_checksum=NONE
#   mariadb-rows.bin         MariaDB 10.5.29: MariaDB GTIDs, annotate-rows,
#                            CRC32 checksums
#   mariadb-compressed.bin   MariaDB, log_bin_compress=ON: zlib-compressed
#                            query and rows events
#
# The servers' UUIDs, the format description events' timestamps (the
# server's start) and the XIDs vary between runs; the workload's events
# carry the fixed times workload.sql sets.
#
#   sh tests/data/mysql-binlog/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/mysql-binlog
rm -rf "$B"
mkdir -p "$B"
mkdir -p "$FIX/mysql-binlog"

# run <container> <client> <sql>
run() {
  docker exec -i "$1" "$2" -uroot -h127.0.0.1 -N -B -e "$3"
}
current() {
  run "$1" "$2" "SHOW BINARY LOGS" | tail -1 | cut -f1
}
wait_up() {
  i=0
  until run "$1" "$2" "SELECT 1" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 120 ] || { docker logs "$1" | tail -20; exit 1; }
    sleep 1
  done
}
take() {
  # take <container> <client> <name>: rotate, copy the previous file
  file=$(current "$1" "$2")
  run "$1" "$2" "FLUSH BINARY LOGS"
  docker cp "$1:/var/lib/mysql/$file" "$B/$3"
  cp "$B/$3" "$FIX/mysql-binlog/$3"
  chmod 644 "$FIX/mysql-binlog/$3"
}

C=fillyfoal-binlog-mysql
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" --hostname fillyfoal -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  mysql:9.7.1 --server-id=1 --log-bin=mysql-bin --binlog-row-metadata=FULL >/dev/null
wait_up "$C" mysql
run "$C" mysql "SELECT VERSION()" > "$B/mysql-version.txt"
run "$C" mysql "FLUSH BINARY LOGS"
docker exec -i "$C" mysql -uroot -h127.0.0.1 < "$SRC/workload.sql"
take "$C" mysql mysql-rows.bin
run "$C" mysql "SET SESSION binlog_transaction_compression = ON; SET TIMESTAMP = 1767226080;
  INSERT INTO shop.notes (body) VALUES ('compressed'), ('compressed'), ('compressed');"
take "$C" mysql mysql-compressed.bin
run "$C" mysql "SET GLOBAL binlog_checksum = 'NONE'"
run "$C" mysql "FLUSH BINARY LOGS"
run "$C" mysql "SET TIMESTAMP = 1767226140; INSERT INTO shop.notes (body) VALUES ('no checksum');"
take "$C" mysql mysql-nochecksum.bin
docker rm -f "$C" >/dev/null

C=fillyfoal-binlog-mariadb
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" --hostname fillyfoal -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=yes \
  mariadb:10.5 --server-id=1 --log-bin=mysql-bin --binlog-format=ROW \
  --binlog-row-metadata=FULL --binlog-annotate-row-events=ON >/dev/null
wait_up "$C" mysql
run "$C" mysql "SELECT VERSION()" > "$B/mariadb-version.txt"
run "$C" mysql "FLUSH BINARY LOGS"
docker exec -i "$C" mysql -uroot -h127.0.0.1 < "$SRC/workload.sql"
take "$C" mysql mariadb-rows.bin
run "$C" mysql "SET GLOBAL log_bin_compress = ON; SET GLOBAL log_bin_compress_min_len = 10"
run "$C" mysql "SET TIMESTAMP = 1767226080; INSERT INTO shop.notes (body) VALUES ('compressed'), ('compressed'), ('compressed');
  SET SESSION binlog_format = 'STATEMENT'; UPDATE shop.notes SET body = 'compressed statement' WHERE body = 'compressed';"
take "$C" mysql mariadb-compressed.bin
docker rm -f "$C" >/dev/null
cat "$B/mysql-version.txt" "$B/mariadb-version.txt"
