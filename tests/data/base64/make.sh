#!/bin/sh
# Makes the base64 fixtures from other fixtures (run from the repository
# root): wrapped at 76 with LF (`base64 -b 76` / GNU `base64`), at 64 with
# CRLF (as mail software wraps), a single line, and URL-safe unpadded.
set -eu
F=tests/fixtures
O=$F/synthetic/base64
python3 -I - "$F" "$O" <<'PY'
import base64, sys
src, out = sys.argv[1], sys.argv[2]
def read(p):
    with open(f"{src}/{p}", "rb") as f:
        return f.read()
def wrap(s, n, nl):
    return nl.join(s[i:i + n] for i in range(0, len(s), n)) + nl
def write(name, data):
    with open(f"{out}/{name}", "wb") as f:
        f.write(data)
write("mixed.zip.b64", wrap(base64.b64encode(read("external/zip/mixed.zip")), 76, b"\n"))
write("gray-crlf.png.b64", wrap(base64.b64encode(read("external/png/gray2-trns.png")), 64, b"\r\n"))
write("hello.b64", base64.b64encode(b"hello, world\n") + b"\n")
write("two-members.gz.b64", base64.urlsafe_b64encode(read("external/gzip/two-members.gz")).rstrip(b"="))
PY
