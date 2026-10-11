#!/bin/sh
# Runs inside the container started by make-lnk.sh.
set -eu
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
rm -rf /tmp/app
dotnet new console -o /tmp/app > /dev/null
cd /tmp/app
dotnet add package securifybv.ShellLink --version 0.1.0 > /dev/null
dotnet add package securifybv.PropertyStore --version 0.1.0 > /dev/null
cp /data/Program.cs Program.cs
dotnet --version
mkdir -p /w/out
dotnet run -- /w/out/console-propstore.lnk
