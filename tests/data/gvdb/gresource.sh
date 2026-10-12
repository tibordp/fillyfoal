#!/bin/sh
# A GResource bundle with a plain, an aliased and a zlib-compressed file
# (glib-compile-resources).
set -e
out=${1:-/out}
work=$(mktemp -d)
cd "$work"
printf 'Hello, GResource!\n' > hello.txt
printf '<interface>\n  <object class="GtkWindow" id="win"/>\n</interface>\n' > window.ui
i=0
while [ $i -lt 40 ]; do printf 'line of text\n'; i=$((i + 1)); done > big.txt
cat > demo.gresource.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<gresources>
  <gresource prefix="/org/example/demo">
    <file>hello.txt</file>
    <file alias="ui/window.ui">window.ui</file>
    <file compressed="true">big.txt</file>
  </gresource>
</gresources>
XML
mkdir -p "$out/gresource"
glib-compile-resources --target="$out/gresource/demo.gresource" demo.gresource.xml
