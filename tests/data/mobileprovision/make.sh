#!/bin/sh
# Writes tests/fixtures/synthetic/mobileprovision/test.mobileprovision: a
# made-up iOS provisioning profile property list (neutral names, a fresh
# throwaway certificate), signed by `openssl cms -sign -nodetach -stream` as
# CMS SignedData in BER with indefinite lengths and a chunked eContent, the
# way Apple's profiles are encoded. Synthetic: Apple signs real profiles.
#
#   sh tests/data/mobileprovision/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-mobileprovision
rm -rf "$work"
mkdir -p "$work"
cd "$work"
out=$root/tests/fixtures/synthetic/mobileprovision
mkdir -p "$out"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout signer.key -days 365 \
    -subj "/O=Fillyfoal Test/CN=Fillyfoal Test Profile Signing" -set_serial 9 -out signer.pem 2>/dev/null
openssl x509 -in signer.pem -outform DER -out signer.der
cert=$(base64 <signer.der | tr -d '\n')

cat >profile.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AppIDName</key>
	<string>Fillyfoal Test App</string>
	<key>ApplicationIdentifierPrefix</key>
	<array>
	<string>TEST000000</string>
	</array>
	<key>CreationDate</key>
	<date>2026-01-01T12:00:00Z</date>
	<key>Platform</key>
	<array>
		<string>iOS</string>
	</array>
	<key>IsXcodeManaged</key>
	<false/>
	<key>DeveloperCertificates</key>
	<array>
		<data>$cert</data>
	</array>
	<key>Entitlements</key>
	<dict>
		<key>application-identifier</key>
		<string>TEST000000.test.example.fillyfoal</string>
		<key>get-task-allow</key>
		<true/>
	</dict>
	<key>ExpirationDate</key>
	<date>2027-01-01T12:00:00Z</date>
	<key>Name</key>
	<string>Fillyfoal Test Development</string>
	<key>ProvisionedDevices</key>
	<array>
		<string>00000000-0000000000000001</string>
	</array>
	<key>TeamIdentifier</key>
	<array>
		<string>TEST000000</string>
	</array>
	<key>TeamName</key>
	<string>Fillyfoal Test Team</string>
	<key>TimeToLive</key>
	<integer>365</integer>
	<key>UUID</key>
	<string>00000000-1111-2222-3333-444444444444</string>
	<key>Version</key>
	<integer>1</integer>
</dict>
</plist>
PLIST

openssl cms -sign -in profile.plist -binary -nodetach -stream -signer signer.pem -inkey signer.key \
    -md sha256 -outform DER -out "$out/test.mobileprovision"
