#!/bin/sh
# Writes the external x509/ and crl/revoked.crl fixtures with the openssl CLI
# (OpenSSL 3.6). Keys are random: a re-run gives new bytes with the same
# structure. Subjects are neutral test names.
#
#   sh tests/data/x509/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-x509
rm -rf "$work"
mkdir -p "$work"
cd "$work"
out=$root/tests/fixtures/external
mkdir -p "$out/x509" "$out/crl"

# A fabricated RFC 6962 SignedCertificateTimestampList (two SCTs, one with an
# ECDSA and one with an RSA signature algorithm; the signatures are filler),
# handed to openssl as the extension's DER.
sct() { # log id hex digit, timestamp (ms, 16 hex digits), hash, signature, length (4 hex digits)
    printf '00'
    printf '%064d' 0 | tr 0 "$1"
    printf '%s' "$2"
    printf '0000'
    printf '%s%s%s' "$3" "$4" "$5"
    n=$(printf '%d' "0x$5")
    printf '%0*d' $((n * 2)) 0 | tr 0 a
}
s1=$(sct 1 0000019a2b3c4d5e 04 03 0010)
s2=$(sct 2 0000019a2b3c4f00 04 01 0020)
l1=$(printf '%04x' $((${#s1} / 2)))
l2=$(printf '%04x' $((${#s2} / 2)))
body="$l1$s1$l2$s2"
list=$(printf '%04x' $((${#body} / 2)))$body
n=$((${#list} / 2))
sctder=$(printf '0481%02x%s' "$n" "$list" | sed 's/../&:/g;s/:$//')

cat >ca.cnf <<CNF
[req]
distinguished_name = dn
[dn]
[ca]
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectAltName = email:ca@example.test
subjectKeyIdentifier = hash
nameConstraints = critical, permitted;DNS:.example.test, permitted;email:example.test, permitted;IP:192.0.2.0/255.255.255.0, permitted;IP:2001:db8::/ffff:ffff::, excluded;DNS:bad.example.test, permitted;dirName:dir_nc
certificatePolicies = 2.5.29.32.0, @pol
policyConstraints = requireExplicitPolicy:0, inhibitPolicyMapping:1
inhibitAnyPolicy = 2
1.3.6.1.4.1.311.21.1 = ASN1:INTEGER:0
[dir_nc]
O = Fillyfoal Test
[pol]
policyIdentifier = 1.3.6.1.4.1.55555.1.1
CPS.1 = "https://pki.example.test/cps"
userNotice.1 = @notice
[notice]
explicitText = "Test certificates only"
organization = "Fillyfoal Test"
noticeNumbers = 1, 2
CNF

cat >leaf.cnf <<CNF
[leaf]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, 1.3.6.1.4.1.311.10.3.12
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer:always
subjectAltName = @san
issuerAltName = issuer:copy
crlDistributionPoints = crldp
authorityInfoAccess = OCSP;URI:http://ocsp.example.test/, caIssuers;URI:http://pki.example.test/ca.cer
1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05
1.3.6.1.4.1.11129.2.4.2 = DER:$sctder
1.3.6.1.4.1.311.20.2 = ASN1:BMPSTRING:WebServer
1.3.6.1.4.1.311.21.7 = ASN1:SEQUENCE:template
2.16.840.1.113730.1.1 = ASN1:FORMAT:BITLIST,BITSTRING:0,1,6
2.16.840.1.113730.1.13 = ASN1:IA5STRING:fillyfoal test certificate
[template]
id = OID:1.3.6.1.4.1.311.21.8.1.2.3
major = INTEGER:100
minor = INTEGER:3
[san]
DNS.1 = leaf.example.test
DNS.2 = *.leaf.example.test
email.1 = test@example.test
URI.1 = https://leaf.example.test/
IP.1 = 192.0.2.10
IP.2 = 2001:db8::10
dirName.1 = dir_san
RID.1 = 1.3.6.1.4.1.55555.2
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:test@example.test
[dir_san]
CN = leaf directory name
O = Fillyfoal Test
[crldp]
fullname = URI:http://pki.example.test/ca.crl
reasons = keyCompromise, CACompromise
CRLissuer = dirName:dir_crl
[dir_crl]
CN = Fillyfoal Test CRL issuer
CNF

# Root CA: RSA 2048, SHA-256.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key 2>/dev/null
openssl req -new -x509 -key ca.key -days 3650 -sha256 -subj "/C=SI/O=Fillyfoal Test/CN=Fillyfoal Test Root CA" \
    -config ca.cnf -extensions ca -set_serial 0x1001 -out ca.pem
openssl x509 -in ca.pem -outform DER -out "$out/x509/ca-rsa.cer"

# Leaf: EC P-256 key, signed by the RSA CA, every extension above.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
openssl req -new -key leaf.key -subj "/C=SI/O=Fillyfoal Test/OU=Testing/CN=leaf.example.test/emailAddress=test@example.test" -out leaf.csr
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 0x2002 -days 365 -sha256 \
    -extfile leaf.cnf -extensions leaf -out leaf.pem 2>/dev/null
openssl x509 -in leaf.pem -outform DER -out "$out/x509/leaf-p256.cer"

# EC P-384 self-signed (ECDSA with SHA-384).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout p384.key -sha384 -days 365 \
    -subj "/CN=p384.example.test" -addext "subjectAltName=DNS:p384.example.test" -set_serial 3 -out p384.pem 2>/dev/null
openssl x509 -in p384.pem -outform DER -out "$out/x509/p384.cer"

# Ed25519 self-signed.
openssl req -x509 -newkey ed25519 -nodes -keyout ed25519.key -days 365 -subj "/CN=ed25519.example.test" \
    -set_serial 4 -out ed25519.pem 2>/dev/null
openssl x509 -in ed25519.pem -outform DER -out "$out/x509/ed25519.cer"

# X25519 key certified by the CA (a key-agreement key cannot sign itself).
openssl genpkey -algorithm X25519 -out x25519.key
openssl pkey -in x25519.key -pubout -out x25519.pub
openssl x509 -new -force_pubkey x25519.pub -subj "/CN=x25519.example.test" -CA ca.pem -CAkey ca.key \
    -set_serial 5 -days 365 -out x25519.pem 2>/dev/null
openssl x509 -in x25519.pem -outform DER -out "$out/x509/x25519.cer"

# RSA-PSS key and signature (SHA-384, salt 48).
openssl req -x509 -newkey rsa-pss -pkeyopt rsa_keygen_bits:2048 -nodes -keyout pss.key -days 365 \
    -subj "/CN=rsa-pss.example.test" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:48 -sha384 \
    -set_serial 6 -out pss.pem 2>/dev/null
openssl x509 -in pss.pem -outform DER -out "$out/x509/rsa-pss.cer"

# A CRL with revoked entries and entry extensions, from `openssl ca`.
mkdir -p db
: >db/index.txt
echo 1000 >db/crlnumber
cat >crl.cnf <<CNF
[ca]
default_ca = test
[test]
database = db/index.txt
crlnumber = db/crlnumber
default_md = sha256
default_crl_days = 30
crl_extensions = crlext
[crlext]
authorityKeyIdentifier = keyid:always
issuingDistributionPoint = @idp
[idp]
fullname = URI:http://pki.example.test/ca.crl
onlysomereasons = keyCompromise, superseded
CNF
openssl ca -config crl.cnf -cert ca.pem -keyfile ca.key -revoke leaf.pem -crl_reason keyCompromise 2>/dev/null
openssl ca -config crl.cnf -cert ca.pem -keyfile ca.key -revoke p384.pem -crl_compromise 20260101120000Z 2>/dev/null
openssl ca -config crl.cnf -cert ca.pem -keyfile ca.key -revoke ed25519.pem -crl_hold 1.2.840.10040.2.2 2>/dev/null
openssl ca -config crl.cnf -cert ca.pem -keyfile ca.key -gencrl -out ca.crl.pem 2>/dev/null
openssl crl -in ca.crl.pem -outform DER -out "$out/crl/revoked.crl"

# --- OCSP: a signed request with a nonce for three certificates, and the
# response of `openssl ocsp` acting as responder over the CA's index (one
# revoked, one good, one unknown).
mkdir -p "$out/ocsp-request" "$out/ocsp-response"
openssl ca -config crl.cnf -cert ca.pem -keyfile ca.key -valid x25519.pem 2>/dev/null
openssl ocsp -issuer ca.pem -cert leaf.pem -cert pss.pem -cert x25519.pem -signer leaf.pem -signkey leaf.key \
    -reqout ocsp.req 2>/dev/null
openssl ocsp -index db/index.txt -rsigner ca.pem -rkey ca.key -CA ca.pem -reqin ocsp.req -ndays 7 \
    -respout ocsp.resp 2>/dev/null
openssl ocsp -issuer ca.pem -cert leaf.pem -no_nonce -reqout ocsp-plain.req 2>/dev/null
openssl ocsp -index db/index.txt -rsigner ca.pem -rkey ca.key -CA ca.pem -reqin ocsp-plain.req -resp_key_id \
    -resp_no_certs -respout ocsp-bykey.resp 2>/dev/null
cp ocsp.req "$out/ocsp-request/signed-nonce.ocsp"
cp ocsp-plain.req "$out/ocsp-request/plain.ocsp"
cp ocsp.resp "$out/ocsp-response/by-name.ocsp"
cp ocsp-bykey.resp "$out/ocsp-response/by-key.ocsp"

# --- RFC 3161 time stamps: a request and a reply from `openssl ts`.
mkdir -p "$out/tsq" "$out/tsr"
cat >tsa-ext.cnf <<CNF
[tsa]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
CNF
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tsa.key -subj "/O=Fillyfoal Test/CN=Fillyfoal Test TSA" -out tsa.csr 2>/dev/null
openssl x509 -req -in tsa.csr -CA ca.pem -CAkey ca.key -set_serial 7 -days 365 -extfile tsa-ext.cnf -extensions tsa -out tsa.pem 2>/dev/null
echo 0100 >tsaserial
cat >tsa.cnf <<CNF
[tsa]
default_tsa = tsa_config
[tsa_config]
serial = tsaserial
signer_cert = tsa.pem
certs = ca.pem
signer_key = tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.55555.3.1
other_policies = 1.3.6.1.4.1.55555.3.2
digests = sha256, sha384, sha512
accuracy = secs:1, millisecs:500, microsecs:100
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
CNF
printf 'fillyfoal time-stamped data\n' >data.txt
openssl ts -query -data data.txt -sha256 -cert -out query.tsq
openssl ts -reply -queryfile query.tsq -config tsa.cnf -section tsa_config -out reply.tsr 2>/dev/null
cp query.tsq "$out/tsq/sha256-nonce.tsq"
cp reply.tsr "$out/tsr/granted.tsr"

# --- PKCS#7 / CMS.
mkdir -p "$out/pkcs7"
cat ca.pem leaf.pem >chain.pem
openssl crl2pkcs7 -nocrl -certfile chain.pem -outform DER -out "$out/pkcs7/bundle.p7b"
openssl crl2pkcs7 -in ca.crl.pem -certfile ca.pem -outform DER -out "$out/pkcs7/bundle-crl.p7c"
printf 'fillyfoal test message\n' >msg.txt
openssl cms -encrypt -in msg.txt -binary -aes256 -recip ca.pem -recip leaf.pem -outform DER -out "$out/pkcs7/enveloped.p7m"
openssl cms -encrypt -in msg.txt -binary -aes-256-gcm -recip leaf.pem -outform DER -out "$out/pkcs7/auth-enveloped.p7m"
openssl cms -encrypt -in msg.txt -binary -aes128 -pwri_password fillyfoal -outform DER -out "$out/pkcs7/password.p7m"
openssl cms -encrypt -in msg.txt -binary -aes128 -secretkey 000102030405060708090a0b0c0d0e0f \
    -secretkeyid 66696c6c79666f616c -outform DER -out "$out/pkcs7/kek.p7m"
openssl cms -EncryptedData_encrypt -in msg.txt -binary -aes-128-cbc -secretkey 000102030405060708090a0b0c0d0e0f \
    -outform DER -out "$out/pkcs7/encrypted-data.p7m"
openssl cms -digest_create -in msg.txt -binary -md sha256 -outform DER -out "$out/pkcs7/digested.p7m"

# --- Keys and parameters.
mkdir -p "$out/rsa-private-key" "$out/rsa-public-key" "$out/ec-private-key" "$out/pkcs8" "$out/spki" \
    "$out/dh-params" "$out/dsa-params" "$out/dsa-private-key"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa1024.key 2>/dev/null
openssl rsa -in rsa1024.key -traditional -outform DER -out "$out/rsa-private-key/rsa1024.der" 2>/dev/null
openssl rsa -in rsa1024.key -RSAPublicKey_out -outform DER -out "$out/rsa-public-key/rsa1024.der" 2>/dev/null
openssl ec -in leaf.key -outform DER -out "$out/ec-private-key/p256.der" 2>/dev/null
openssl ec -in p384.key -no_public -outform DER -out "$out/ec-private-key/p384-no-public.der" 2>/dev/null
openssl pkey -in rsa1024.key -outform DER -out "$out/pkcs8/rsa1024.p8"
openssl pkey -in leaf.key -outform DER -out "$out/pkcs8/p256.p8"
openssl pkey -in ed25519.key -outform DER -out "$out/pkcs8/ed25519.p8"
openssl pkey -in x25519.key -outform DER -out "$out/pkcs8/x25519.p8"
openssl pkey -in rsa1024.key -pubout -outform DER -out "$out/spki/rsa1024.der"
openssl pkey -in p384.key -pubout -outform DER -out "$out/spki/p384.der"
openssl pkey -in ed25519.key -pubout -outform DER -out "$out/spki/ed25519.der"
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out dh.pem
openssl dhparam -in dh.pem -outform DER -out "$out/dh-params/ffdhe2048.der" 2>/dev/null
openssl dsaparam -outform DER -out "$out/dsa-params/dsa1024.der" 1024 2>/dev/null
openssl gendsa -out dsa.key "$out/dsa-params/dsa1024.der" 2>/dev/null || {
    openssl dsaparam -out dsaparam.pem 1024 2>/dev/null
    openssl gendsa -out dsa.key dsaparam.pem 2>/dev/null
}
openssl dsa -in dsa.key -outform DER -out "$out/dsa-private-key/dsa1024.der" 2>/dev/null

# --- Generic DER: assorted universal types from `openssl asn1parse -genconf`.
mkdir -p "$out/der"
cat >generic.cnf <<CNF
asn1 = SEQUENCE:top
[top]
flag = BOOLEAN:true
small = INTEGER:-129
big = INTEGER:0x0123456789abcdef0123456789abcdef
none = NULL
oid = OID:1.3.6.1.4.1.55555.9
utf8 = FORMAT:UTF8,UTF8String:fillyfoal ünïcödé
printable = PRINTABLESTRING:Fillyfoal Test
ia5 = IA5STRING:test@example.test
bmp = BMPSTRING:wide
utc = UTCTIME:260101120000Z
gen = GENTIME:20260101120000Z
bits = FORMAT:BITLIST,BITSTRING:1,3,5
octets = FORMAT:HEX,OCTETSTRING:00112233
enum = ENUMERATED:3
set = SET:inner
tagged = IMPLICIT:0,INTEGER:42
explicit = EXPLICIT:1,UTF8:explicit
[inner]
a = INTEGER:1
b = INTEGER:2
CNF
openssl asn1parse -genconf generic.cnf -out "$out/der/generic.der" -noout
