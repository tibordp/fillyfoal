#!/bin/sh
# Writes the external krb5-ccache/ and krb5-keytab/ fixtures with MIT
# Kerberos (Debian's krb5-kdc and krb5-user) in Docker: a throwaway KDC for
# the realm FILLYFOAL.TEST, run with no network (loopback only), and kinit
# and kvno against it. Keys are random: a re-run gives new bytes with the
# same structure.
#
#   sh tests/data/krb5-ccache/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-krb5
rm -rf "$work"
mkdir -p "$work/out"
cd "$work"
cat >Dockerfile <<'DOCKER'
FROM debian:trixie-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    krb5-kdc krb5-admin-server krb5-user >/dev/null && rm -rf /var/lib/apt/lists/*
DOCKER
docker build -q -t fillyfoal-krb5 . >/dev/null
cat >run.sh <<'RUN'
set -eu
cat >/etc/krb5.conf <<CONF
[libdefaults]
    default_realm = FILLYFOAL.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    noaddresses = false
    forwardable = true
    renew_lifetime = 7d
[realms]
    FILLYFOAL.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
CONF
mkdir -p /etc/krb5kdc
cat >/etc/krb5kdc/kdc.conf <<CONF
[realms]
    FILLYFOAL.TEST = {
        max_renewable_life = 7d
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha384-192:normal
    }
CONF
kdb5_util -r FILLYFOAL.TEST -P masterpassword create -s >/dev/null
kadmin.local -q "addprinc -pw fillyfoal alice" >/dev/null
kadmin.local -q "addprinc -randkey host/server.fillyfoal.test" >/dev/null
kadmin.local -q "addprinc -randkey HTTP/web.fillyfoal.test" >/dev/null
kadmin.local -q "ktadd -k /out/server.keytab host/server.fillyfoal.test HTTP/web.fillyfoal.test" >/dev/null
krb5kdc
sleep 1
# A version 4 cache (the default) with a TGT (forwardable, renewable, with
# the loopback address) and two service tickets.
echo fillyfoal | kinit -f -r 2d -a -c FILE:/out/krb5cc_v4 alice >/dev/null
KRB5CCNAME=FILE:/out/krb5cc_v4 kvno host/server.fillyfoal.test HTTP/web.fillyfoal.test >/dev/null
# A version 3 cache (ccache_type = 3).
{ echo "[libdefaults]"; echo "    ccache_type = 3"; sed 1d /etc/krb5.conf; } >/etc/krb5-v3.conf
echo fillyfoal | KRB5_CONFIG=/etc/krb5-v3.conf kinit -c FILE:/out/krb5cc_v3 alice >/dev/null
klist -e -f -a -c FILE:/out/krb5cc_v4 >/out/klist.txt
klist -V >>/out/klist.txt
RUN
docker run --rm --network none -v "$work/out:/out" -v "$work/run.sh:/run.sh:ro" fillyfoal-krb5 sh /run.sh
cat "$work/out/klist.txt"
mkdir -p "$root/tests/fixtures/external/krb5-ccache" "$root/tests/fixtures/external/krb5-keytab"
cp "$work/out/krb5cc_v4" "$root/tests/fixtures/external/krb5-ccache/krb5cc_v4"
cp "$work/out/krb5cc_v3" "$root/tests/fixtures/external/krb5-ccache/krb5cc_v3"
cp "$work/out/server.keytab" "$root/tests/fixtures/external/krb5-keytab/server.keytab"
