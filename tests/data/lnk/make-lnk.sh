#!/bin/sh
# Rebuilds tests/fixtures/external/lnk/console-propstore.lnk with the
# securifybv.ShellLink and securifybv.PropertyStore 0.1.0 .NET libraries
# (Program.cs), in the mcr.microsoft.com/dotnet/sdk:8.0 image, in a scratch
# directory outside the home directory:
#
#   sh tests/data/lnk/make-lnk.sh [scratch dir]
#
# The output is byte-reproducible (the library leaves the header times zero).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/forensics-lnk}
mkdir -p "$work"
docker run --rm -v "$work:/w" -v "$here:/data:ro" mcr.microsoft.com/dotnet/sdk:8.0 sh /data/inner.sh
mkdir -p "$repo/tests/fixtures/external/lnk"
cp "$work/out/console-propstore.lnk" "$repo/tests/fixtures/external/lnk/"
