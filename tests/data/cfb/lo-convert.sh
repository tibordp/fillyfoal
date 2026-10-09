#!/bin/sh
# Converts a flat ODF source with LibreOffice in a throwaway profile whose
# user name is "fillyfoal": lo-convert.sh <format> <source> <outdir>
# The profile is created on first use; set its user data before converting:
# see tests/fixtures/external/SOURCES.md (CFB section).
set -e
fmt="$1"
src="$2"
out="$3"
exec soffice -env:UserInstallation=file:///tmp/fixtures/office-cfb/lo-profile --headless \
    --convert-to "$fmt" --outdir "$out" "$src"
