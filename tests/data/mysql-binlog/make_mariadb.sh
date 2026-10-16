#!/bin/sh
# More MariaDB binary logs, from throwaway containers (host name
# "fillyfoal") of the official images:
#
#   mariadb-encrypted.bin    MariaDB 10.5: encrypt_binlog=ON with the
#                            file_key_management plugin and the fixed test
#                            key below: a start encryption event, then
#                            encrypted events
#   mariadb114-rows.bin      MariaDB 11.4: workload.sql, a CREATE TABLE
#                            with a character set (11.4 writes the
#                            Q_CHARACTER_SET_COLLATIONS status variable),
#                            then an XA transaction
#
#   sh tests/data/mysql-binlog/make_mariadb.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/mysql-binlog-mariadb
rm -rf "$B"
mkdir -p "$B" "$FIX/mysql-binlog"

# run <container> <sql>
run() {
  docker exec -i "$1" mariadb -uroot -h127.0.0.1 -N -B -e "$2"
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

# A test key (id 1, AES-256), not a secret.
mkdir -p "$B/keys"
echo '1;0f0e0d0c0b0a09080706050403020100f0e0d0c0b0a090807060504030201000' > "$B/keys/keys.txt"
chmod 644 "$B/keys/keys.txt"

C=fillyfoal-binlog-encrypted
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" --hostname fillyfoal -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=yes \
  -v "$B/keys":/keys:ro mariadb:10.5 --server-id=1 --log-bin=mysql-bin --binlog-format=ROW \
  --plugin-load-add=file_key_management --file-key-management-filename=/keys/keys.txt \
  --encrypt-binlog=ON >/dev/null
wait_up "$C"
run "$C" "SELECT VERSION()" > "$B/encrypted-version.txt"
run "$C" "FLUSH BINARY LOGS"
run "$C" "SET TIMESTAMP = 1767225600; CREATE DATABASE shop;
  CREATE TABLE shop.notes (id INT PRIMARY KEY, body VARCHAR(100));
  SET TIMESTAMP = 1767225660; INSERT INTO shop.notes VALUES (1, 'an encrypted row');"
take "$C" mariadb-encrypted.bin
docker rm -f "$C" >/dev/null

C=fillyfoal-binlog-mariadb114
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" --hostname fillyfoal -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=yes \
  mariadb:11.4 --server-id=1 --log-bin=mysql-bin --binlog-format=ROW \
  --binlog-row-metadata=FULL --binlog-annotate-row-events=ON >/dev/null
wait_up "$C"
run "$C" "SELECT VERSION()" > "$B/mariadb114-version.txt"
run "$C" "FLUSH BINARY LOGS"
docker exec -i "$C" mariadb -uroot -h127.0.0.1 < "$SRC/workload.sql"
run "$C" "SET TIMESTAMP = 1767226140; CREATE TABLE shop.tags (name VARCHAR(20)) DEFAULT CHARSET=utf8mb4;"
run "$C" "SET TIMESTAMP = 1767226200; XA START 'x1';
  INSERT INTO shop.notes (body) VALUES ('in an XA transaction');
  XA END 'x1'; XA PREPARE 'x1'; XA COMMIT 'x1';"
take "$C" mariadb114-rows.bin
docker exec "$C" mariadb-binlog -vv --base64-output=decode-rows \
  "/var/lib/mysql/$(run "$C" "SHOW BINARY LOGS" | tail -2 | head -1 | cut -f1)" \
  > "$B/mariadb114-rows.txt" 2>&1 || true
docker rm -f "$C" >/dev/null
cat "$B/encrypted-version.txt" "$B/mariadb114-version.txt"
