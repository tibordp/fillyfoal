#!/bin/sh
# Writes tests/fixtures/external/keychain/items.keychain with macOS
# `security` (a new, separate keychain file; the user's keychains and search
# list are not touched): a generic password, an internet password, a
# self-signed certificate and its EC private key. Password "fillyfoal".
# Item passwords: hunter2, s3cret. Random salts, keys and dates make every
# run differ.
#
#   sh tests/data/keychain/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
kc=$work/items.keychain
security create-keychain -p fillyfoal "$kc"
security add-generic-password -a alice -s fillyfoal-service -l "Fillyfoal generic" \
    -j "a comment" -w hunter2 "$kc"
security add-internet-password -a bob -s example.com -r htps -P 443 -p /login \
    -l "example.com (bob)" -w s3cret "$kc"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj /CN=fillyfoal -days 365 -keyout "$work/k.pem" -out "$work/c.pem" 2>/dev/null
openssl ec -in "$work/k.pem" -out "$work/k2.pem" 2>/dev/null
security import "$work/c.pem" -k "$kc"
security import "$work/k2.pem" -k "$kc" -t priv -f openssl
mkdir -p "$root/tests/fixtures/external/keychain"
cp "$kc" "$root/tests/fixtures/external/keychain/items.keychain"
security delete-keychain "$kc" 2>/dev/null || true
