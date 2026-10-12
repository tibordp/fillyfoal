"""Writes hand-made negative-probe fixtures: everyday text files that weak
text probes used to claim (Markdown for `#` comments, JSON for a leading
`[...]`, LRC for bracketed log stamps, YAML for header stanzas, nothing at
all for legacy code pages, colours, overstrike or a few NULs). Each goes
under the directory of the format it must be identified as, so
`fixtures_are_identified_correctly` pins it.

Usage: python3 -I negatives.py <repo>/tests/fixtures/synthetic
"""

import os
import sys

OUT = sys.argv[1]


def write(fmt, name, data):
    path = os.path.join(OUT, fmt, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    with open(path, "wb") as f:
        f.write(data)


# `#` comments are not Markdown headings.
write("text", "hosts", """##
# Host Database
#
# localhost is used to configure the loopback interface
# when the system is booting.  Do not change this entry.
##
127.0.0.1\tlocalhost
255.255.255.255\tbroadcasthost
::1             localhost
""")
write("text", ".gitignore", """# Byte-compiled files
__pycache__/
*.py[cod]
# Dependencies
**/node_modules/
# Distribution
build/
dist/
""")
write("text", "requirements.txt", """# Core dependencies
requests==2.31.0
# Testing
pytest>=7
""")
write("text", ".bashrc", """# ~/.bashrc
# aliases
alias ll="ls -l"
export PATH=$HOME/bin:$PATH
# prompt
PS1="\\u@\\h "
""")
write("text", "rules.mk", """# Makefile fragment
# build rules
CC = cc
all: main

main: main.o
\t$(CC) -o $@ $^
# clean
""")
write("text", "analysis.R", """# R script
# load data
x <- read.csv("a.csv")
summary(x)
# plot
plot(x)
""")

# A leading `[...]` is not a JSON array when text follows it.
write("text", "dmesg.txt", """[    0.000000] Linux version 6.1.0 (gcc 12) #1 SMP
[    0.000000] Command line: BOOT_IMAGE=/vmlinuz root=/dev/sda1
[    0.000123] x86/fpu: Supporting XSAVE feature 0x001
""")
write("text", "references.txt", """[1] Smith, J. Some paper. 2001.
[2] Doe, A. Another paper. 2003.
""")

# Bracketed log stamps are not LRC tags.
write("text", "apache_error.log", "".join(
    f"[Mon Jan 01 12:00:{s:02}.123456 2024] [core:error] [pid 123] AH00126: Invalid URI in request\n"
    for s in range(1, 9)))
write("text", "php_error.log", "".join(
    f"[01-Jan-2024 12:00:{s:02} UTC] PHP Warning:  Undefined variable $x in /var/www/a.php on line {s}\n"
    for s in range(1, 9)))
write("text", "laravel.log", "".join(
    f'[2024-01-01 12:00:{s:02}] app.INFO: request handled {{"id":{s}}} []\n'
    for s in range(1, 9)))
write("text", "irc.log", "".join(
    f"[12:{m:02}] <nick> hello there\n" for m in range(1, 9)))

# Legacy 8-bit code pages.
write("text", "cp1251.txt", "Привет, мир. Это проверка текста на русском языке.\nВторая строка.\n"
      .encode("cp1251"))
write("text", "koi8r.txt", "Привет, мир. Это проверка текста на русском языке.\nВторая строка.\n"
      .encode("koi8_r"))
write("text", "cp1253.txt", "Γειά σου κόσμε, αυτό είναι ένα δοκιμαστικό κείμενο.\n"
      .encode("cp1253"))

# Terminal colours, overstrike and a few NULs are still text.
write("text", "colour.log", "".join(
    f"\x1b[32mINFO\x1b[0m  compiling crate number {n} of the build\n" for n in range(1, 13)))
write("text", "cargo.log", "".join(
    f"\x1b[1;32m   Compiling\x1b[0m foo v0.1.{n} (/src/foo)\n" for n in range(1, 13)))
write("text", "ls.man", "".join(
    "".join(c + "\b" + c for c in word) if bold else word
    for word, bold in [("NAME", True), ("\n     ", False), ("ls", True),
                       (" - list directory contents\n\n", False), ("SYNOPSIS", True),
                       ("\n     ", False), ("ls", True), (" [OPTION]... [FILE]...\n", False)]))
write("text", "nul-bytes.log", "".join(
    f"log line {n} before the crash\n" for n in range(1, 21)).encode() + b"\0" * 4 + "".join(
    f"log line {n} after the crash\n" for n in range(21, 181)).encode())

# Newline-delimited GeoJSON features are JSON Lines, not one Feature.
write("ndjson", "features.geojsons", "".join(
    '{"type":"Feature","geometry":{"type":"Point","coordinates":[%d,2]},"properties":{"n":%d}}\n'
    % (n, n) for n in range(1, 5)))

# An HTML fragment, not an XML document.
write("html", "fragment.html", """<div class="x">
<p>Para one<br>
line &nbsp; two</p>
<img src="a.png">
<p>Para two</p>
</div>
""")

# Header stanzas are not YAML.
write("deb822", "control", """Source: hello
Section: devel
Priority: optional
Maintainer: Example Person <a@example.com>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.0

Package: hello
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: example package
 This is a long description
 spanning lines.
 .
 Another paragraph.
""")
write("jar-manifest", "wrapped.MF", (
    "Manifest-Version: 1.0\r\n"
    "Main-Class: com.example.Main\r\n"
    "Class-Path: lib/aaaaaaaaaaaaaaaaaaaaaaaa.jar lib/bbbbbbbbbbbbbbbbbbbbbbb\r\n"
    " bbbbbbb.jar lib/cccccccccccccccc.jar\r\n"
    "\r\n"))

# Apple Mail: a byte count, the message, a property list.
message = (
    "From: a@example.com\n"
    "To: b@example.com\n"
    "Subject: Hi\n"
    "Date: Mon, 1 Jan 2024 12:00:00 +0000\n"
    "Message-ID: <1@example.com>\n"
    "\n"
    "Hello.\n")
plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>date-received</key>
\t<integer>1704110400</integer>
\t<key>flags</key>
\t<integer>8590195713</integer>
</dict>
</plist>
"""
write("emlx", "1.emlx", f"{len(message.encode())}\n{message}{plist}")

# Section-less key=value files are INI-style configuration, not plain text.
write("ini", "app.properties", """# Application settings
! written by hand for fillyfoal
app.name=fillyfoal demo
app.version = 1.2.0
server.port=8080
server.url=http://localhost:8080/
greeting=Hello, \\
    world
log-level=info
""")
write("ini", "os-release", """PRETTY_NAME="Fillyfoal Linux 1.0"
NAME="Fillyfoal Linux"
VERSION_ID="1.0"
ID=fillyfoal
HOME_URL="https://example.com/"
""")
write("ini", "demo.env", """# local development
export DATABASE_URL=postgres://localhost/demo
DEBUG=true
SECRET_KEY='not-a-secret'
PORT=3000
""")
# Pinned requirements are not key=value entries.
write("text", "requirements-lock.txt", """requests==2.31.0
urllib3==2.2.1
idna==3.6
certifi==2024.2.2
""")

# A text/html part is HTML even when it starts like plain text.
write("eml", "html-part.eml", """From: a@example.com
To: b@example.com
Subject: Notes
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <2@example.com>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

Hello Bob,<br>
see you <b>soon</b>.<br>
-- <i>Ana</i>
""")

# A VBA PROJECT stream (MS-OVBA 2.3.1) as Access keeps it in
# MSysAccessStorage, where no VBA storage context names it: `key="value"`
# lines start like TOML, but `[Host Extender Info]` is no TOML table.
write("text", "vba-PROJECT", "".join(line + "\r\n" for line in [
    'ID="{4C1E1D2A-6F5B-4E3C-9A8D-1B2C3D4E5F60}"',
    'Name="Database1"',
    'HelpContextID="0"',
    'VersionCompatible32="393222000"',
    'CMG="0A08B8E2BCE2BCE2BCE2BC"',
    'DPB="1E1CAEF6AFF6AFF6"',
    'GC="2C2E9CC49DC59DC562"',
    "",
    "[Host Extender Info]",
    "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000",
    "",
    "[Workspace]",
]))
