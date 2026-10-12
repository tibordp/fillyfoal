#!/bin/sh
# Writes a password-protected document with LibreOffice:
#   encrypt.sh <profile> <factory> <filter> <out>
# e.g. encrypt.sh <profile> swriter "MS Word 97" encrypted.doc
# <profile> is a throwaway profile prepared as in tests/data/cfb/lo-profile.py
# (user name "fillyfoal"); encrypt.bas becomes its Standard.Module1.
set -e
here=$(cd "$(dirname "$0")" && pwd)
profile=$(cd "$1" && pwd)
out="$(cd "$(dirname "$4")" && pwd)/$(basename "$4")"
python3 - "$here/encrypt.bas" "$profile/user/basic/Standard/Module1.xba" <<'EOF'
import sys
from xml.sax.saxutils import escape
code = open(sys.argv[1]).read()
open(sys.argv[2], "w").write(
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE script:module PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "module.dtd">\n'
    '<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" '
    'script:language="StarBasic">' + escape(code) + "</script:module>\n")
EOF
FACTORY="$2" FILTER="$3" OUT="file://$out" soffice -env:UserInstallation="file://$profile" \
    --headless --norestore "macro:///Standard.Module1.Main"
