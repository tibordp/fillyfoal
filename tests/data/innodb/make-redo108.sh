#!/bin/sh
# Writes the external innodb-redo/mariadb11-ib_logfile0.gz fixture: the
# redo log of a fresh MariaDB 11.4.13 server (official Docker image,
# --innodb-log-file-size=4M, the 10.8+ unframed "Phys" format) after
# tests/data/innodb/redo.sql and a clean shutdown. The log has not
# wrapped around, so it holds every mini-transaction since the server
# was initialised.
#
# LSNs and the records differ between runs.
#
#   sh tests/data/innodb/make-redo108.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/data-innodb-redo108
rm -rf "$work"
mkdir -p "$work"
name=fillyfoal-redo-mariadb
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --hostname fillyfoal -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 \
	mariadb:11.4.13 --innodb-log-file-size=4M --innodb-buffer-pool-size=32M --skip-log-bin >/dev/null
i=0
until docker logs "$name" 2>&1 | grep -q "Version: .*port: 3306 "; do
	i=$((i + 1))
	[ "$i" -lt 120 ] || { echo "server did not start" >&2; exit 1; }
	sleep 2
done
docker exec -i "$name" mariadb -uroot <"$root/tests/data/innodb/redo.sql"
docker stop -t 120 "$name" >/dev/null
docker cp "$name:/var/lib/mysql/ib_logfile0" "$work/ib_logfile0"
docker rm "$name" >/dev/null
out="$root/tests/fixtures/external/innodb-redo"
mkdir -p "$out"
gzip -9 -n <"$work/ib_logfile0" >"$out/mariadb11-ib_logfile0.gz"
