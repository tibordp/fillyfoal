#!/bin/sh
# Builds tests/fixtures/external/deb822/hello_1.0-1.dsc: the source control
# file `dpkg-source -b` writes for a throwaway native-format source package
# with neutral maintainer fields (unsigned). Uses the debian:bookworm image.
set -eu
W=/tmp/fixtures/text-deb822
rm -rf "$W"
mkdir -p "$W/hello-1.0/debian/source"
cd "$W/hello-1.0"
printf 'int main(void) { return 0; }\n' > hello.c
printf '3.0 (native)\n' > debian/source/format
cat > debian/control <<'EOF'
Source: hello
Section: devel
Priority: optional
Maintainer: fillyfoal <fillyfoal@example.com>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://example.com/hello

Package: hello
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: sample program for fixtures
 A long description of the sample program,
 spanning two lines.
 .
 And a second paragraph.

Package: hello-doc
Architecture: all
Section: doc
Description: documentation for the sample program
 Documentation.
EOF
cat > debian/changelog <<'EOF'
hello (1.0) unstable; urgency=medium

  * Initial release.

 -- fillyfoal <fillyfoal@example.com>  Mon, 01 Jan 2024 00:00:00 +0000
EOF
printf '#!/usr/bin/make -f\n%%:\n\tdh $@\n' > debian/rules
chmod +x debian/rules
docker run --rm -v "$W:/w" -w /w debian:bookworm sh -c \
    'apt-get update -qq >/dev/null && apt-get install -y -qq dpkg-dev >/dev/null &&
     dpkg-source --version | head -1 &&
     SOURCE_DATE_EPOCH=1704067200 dpkg-source -b hello-1.0 &&
     chown -R '"$(id -u):$(id -g)"' /w'
echo "$W/hello_1.0.dsc"
