#!/bin/sh
# A GSettings schema cache (glib-compile-schemas) for one small schema.
set -e
out=${1:-/out}
work=$(mktemp -d)
cat > "$work/org.example.demo.gschema.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<schemalist>
  <enum id="org.example.demo.Mode">
    <value nick="off" value="0"/>
    <value nick="on" value="1"/>
  </enum>
  <schema id="org.example.demo" path="/org/example/demo/">
    <key name="enabled" type="b">
      <default>true</default>
      <summary>Whether the demo is enabled</summary>
    </key>
    <key name="count" type="u">
      <default>3</default>
      <range min="0" max="10"/>
    </key>
    <key name="mode" enum="org.example.demo.Mode">
      <default>'off'</default>
    </key>
  </schema>
</schemalist>
XML
mkdir -p "$out/gvdb"
glib-compile-schemas --targetdir="$out/gvdb" "$work"
