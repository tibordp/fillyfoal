#!/bin/sh
# MySQL 8.0 binary logs, from throwaway containers of the official
# mysql:8.0 image (host name "fillyfoal"), with the server's defaults
# (binlog_row_metadata=MINIMAL, GTIDs off: anonymous GTID events):
#
#   mysql80-rows.bin       workload.sql, then statement-based events with a
#                          user variable (User var event) and RAND() (Rand
#                          event), an XA transaction (XA prepare event) and
#                          a one-phase XA commit
#   mysql80-partial.bin    binlog_row_value_options=PARTIAL_JSON and
#                          binlog_row_image=MINIMAL: JSON_SET / JSON_REMOVE
#                          updates in a Partial update rows event
#   mysql80-relay.bin      a replica's relay log: the replica (a second
#                          container on a private network) replicates a few
#                          statements, then its relay log is rotated and
#                          copied
#
# The server UUIDs, start times, XIDs and RAND() seeds vary between runs.
#
#   sh tests/data/mysql-binlog/make_mysql80.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/mysql-binlog-mysql80
rm -rf "$B"
mkdir -p "$B" "$FIX/mysql-binlog"

# run <container> <sql>
run() {
  docker exec -i "$1" mysql -uroot -h127.0.0.1 -N -B -e "$2"
}
current() {
  run "$1" "SHOW BINARY LOGS" | tail -1 | cut -f1
}
wait_up() {
  i=0
  until run "$1" "SELECT 1" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 120 ] || { docker logs "$1" | tail -20; exit 1; }
    sleep 1
  done
}
take() {
  # take <container> <name>: rotate, copy the previous file
  file=$(current "$1")
  run "$1" "FLUSH BINARY LOGS"
  docker cp "$1:/var/lib/mysql/$file" "$B/$2"
  cp "$B/$2" "$FIX/mysql-binlog/$2"
  chmod 644 "$FIX/mysql-binlog/$2"
}

N=fillyfoal-binlog-net
S=fillyfoal-binlog-mysql80
R=fillyfoal-binlog-replica
cleanup() {
  docker rm -f "$S" "$R" >/dev/null 2>&1 || true
  docker network rm "$N" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT
docker network create "$N" >/dev/null

docker run -d --name "$S" --network "$N" --hostname fillyfoal \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes mysql:8.0 --server-id=1 --log-bin=mysql-bin >/dev/null
wait_up "$S"
run "$S" "SELECT VERSION()" > "$B/version.txt"
run "$S" "FLUSH BINARY LOGS"
docker exec -i "$S" mysql -uroot -h127.0.0.1 < "$SRC/workload.sql"
run "$S" "SET SESSION binlog_format = 'STATEMENT';
  SET TIMESTAMP = 1767226080; SET @who = 'a user variable';
  INSERT INTO shop.notes (body) VALUES (@who);
  SET TIMESTAMP = 1767226140;
  INSERT INTO shop.notes (body) VALUES (CONCAT('random ', FLOOR(RAND() * 1000)));"
run "$S" "SET TIMESTAMP = 1767226200; XA START 'x1';
  INSERT INTO shop.notes (body) VALUES ('in an XA transaction');
  XA END 'x1'; XA PREPARE 'x1'; XA COMMIT 'x1';
  SET TIMESTAMP = 1767226260; XA START 'x2';
  INSERT INTO shop.notes (body) VALUES ('one phase');
  XA END 'x2'; XA COMMIT 'x2' ONE PHASE;"
take "$S" mysql80-rows.bin
run "$S" "SET SESSION binlog_row_image = 'MINIMAL';
  SET SESSION binlog_row_value_options = 'PARTIAL_JSON';
  SET TIMESTAMP = 1767226320;
  UPDATE shop.items SET extra = JSON_SET(extra, '\$.colour', 'black') WHERE id = 1;
  SET TIMESTAMP = 1767226380;
  UPDATE shop.items SET extra = JSON_REMOVE(extra, '\$.sizes[0]'), name = 'teapot' WHERE id = 1;"
take "$S" mysql80-partial.bin

# A replica of the source from a fresh binary log: its relay log holds
# the replica's own format description, the source's rotate and format
# description, then the source's events.
run "$S" "CREATE USER 'repl'@'%' IDENTIFIED WITH mysql_native_password BY 'fillyfoal';
  GRANT REPLICATION SLAVE ON *.* TO 'repl'@'%'; FLUSH BINARY LOGS"
file=$(current "$S")
docker run -d --name "$R" --network "$N" --hostname fillyfoal \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes mysql:8.0 --server-id=2 --log-bin=mysql-bin \
  --relay-log=relay-bin >/dev/null
wait_up "$R"
run "$R" "CREATE DATABASE shop; CREATE TABLE shop.notes (id INT PRIMARY KEY AUTO_INCREMENT, body VARCHAR(100));
  CHANGE REPLICATION SOURCE TO SOURCE_HOST='$S', SOURCE_USER='repl', SOURCE_PASSWORD='fillyfoal',
  SOURCE_LOG_FILE='$file', SOURCE_LOG_POS=4; START REPLICA;"
run "$S" "SET TIMESTAMP = 1767226440; INSERT INTO shop.notes (body) VALUES ('replicated');
  SET TIMESTAMP = 1767226500; UPDATE shop.notes SET body = 'replicated twice' WHERE body = 'replicated';"
i=0
until [ "$(run "$R" "SELECT COUNT(*) FROM shop.notes WHERE body = 'replicated twice'")" = 1 ]; do
  i=$((i + 1))
  [ "$i" -lt 60 ] || { docker exec "$R" mysql -uroot -h127.0.0.1 -e "SHOW REPLICA STATUS\G"; exit 1; }
  sleep 1
done
relay=$(docker exec "$R" sh -c 'ls /var/lib/mysql/relay-bin.0*' | tail -1 | xargs basename)
run "$R" "FLUSH RELAY LOGS"
docker cp "$R:/var/lib/mysql/$relay" "$B/mysql80-relay.bin"
cp "$B/mysql80-relay.bin" "$FIX/mysql-binlog/mysql80-relay.bin"
chmod 644 "$FIX/mysql-binlog/mysql80-relay.bin"
cat "$B/version.txt"
