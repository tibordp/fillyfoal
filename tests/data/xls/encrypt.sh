#!/bin/sh
# Writes a password-protected .xls with LibreOffice: encrypt.sh <profile> <out.xls>
# <profile> is a throwaway profile prepared as in tests/data/cfb/lo-profile.py
# (user name "fillyfoal"); encrypt.bas becomes its Standard.Module1.
set -e
here=$(cd "$(dirname "$0")" && pwd)
profile=$(cd "$1" && pwd)
out="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
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
XLS_OUT="file://$out" soffice -env:UserInstallation="file://$profile" --headless --norestore \
    "macro:///Standard.Module1.Main"
