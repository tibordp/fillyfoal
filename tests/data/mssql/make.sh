#!/bin/sh
# Writes the external mssql-data/ and mssql-log/ fixtures with Microsoft
# SQL Server 2022 (mcr.microsoft.com/mssql/server:2022-latest, 16.0.4295.3
# Developer Edition, linux/amd64; it runs under emulation on arm64 hosts).
# shop.sql shrinks the model database, creates `shop` with a primary data
# file, a secondary file in its own file group and a 1 MiB log, adds two
# small tables (one in the secondary file group), shrinks the log and
# detaches the database so its files are consistent.
#
# Stored: the whole secondary file (shop_extra.ndf, 1 MiB: file header,
# PFS, GAM, SGAM, change maps, a data page and its IAM page), the first 16
# pages of the primary file (shop.mdf is 5 MiB: file header, allocation
# pages, the boot page and system table pages) and the first 64 KiB of the
# log (file header page and the start of the first virtual log file).
#
# GUIDs, LSNs and times differ between runs. The SA password is a
# throwaway one for the container.
#
#   sh tests/data/mssql/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/data-mssql
rm -rf "$work"
mkdir -p "$work"
name=fillyfoal-mssql
pass='Fillyfoal!2026'
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --platform linux/amd64 --name "$name" --hostname fillyfoal \
	-e ACCEPT_EULA=Y -e MSSQL_PID=Developer -e "MSSQL_SA_PASSWORD=$pass" \
	mcr.microsoft.com/mssql/server:2022-latest >/dev/null
i=0
until docker logs "$name" 2>&1 | grep -q "Recovery is complete"; do
	i=$((i + 1))
	[ "$i" -lt 150 ] || { echo "server did not start" >&2; exit 1; }
	sleep 2
done
sleep 5
docker exec -i "$name" /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$pass" -b \
	-i /dev/stdin <"$root/tests/data/mssql/shop.sql" >/dev/null
for f in shop.mdf shop_extra.ndf shop_log.ldf; do
	docker cp "$name:/var/opt/mssql/data/$f" "$work/$f"
done
docker rm -f "$name" >/dev/null

out="$root/tests/fixtures/external"
mkdir -p "$out/mssql-data" "$out/mssql-log"
gzip -9 -n <"$work/shop_extra.ndf" >"$out/mssql-data/shop_extra.ndf.gz"
head -c 131072 "$work/shop.mdf" | gzip -9 -n >"$out/mssql-data/shop-head.mdf.gz"
head -c 65536 "$work/shop_log.ldf" | gzip -9 -n >"$out/mssql-log/shop_log-head.ldf.gz"
