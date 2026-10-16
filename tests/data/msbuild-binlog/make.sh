#!/bin/bash
# MSBuild binary logs for tests/fixtures/external/msbuild-binlog/ (and gzip/tiny.binlog).
# Run (writes /tmp/fixtures/dotnet/out/{tiny,build-noimports}.binlog):
#   mkdir -p /tmp/fixtures/dotnet/out
#   cp tests/data/msbuild-binlog/make.sh /tmp/fixtures/dotnet/binlog.sh
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/dotnet:/work -w /work \
#     mcr.microsoft.com/dotnet/sdk:8.0 bash /work/binlog.sh
# The environment is cleared (`env -i`): MSBuild logs environment variables.
# The fixtures keep the files byte for byte; `*.binlog.gz` is only the name the
# test harness needs to dissect the record stream inside (it is already gzip).
set -e
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
CLEAN="env -i PATH=/usr/share/dotnet:/usr/bin:/bin HOME=/tmp/home HOSTNAME=fillyfoal DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1"

# A project without the SDK: a few targets, a property, items and a warning;
# the log embeds the project file (ProjectImportArchive).
cd /work
rm -rf tiny && mkdir tiny && cd tiny
cat > tiny.proj <<'X'
<Project DefaultTargets="Build">
  <PropertyGroup>
    <Greeting>hello from fillyfoal</Greeting>
  </PropertyGroup>
  <ItemGroup>
    <Thing Include="alpha;beta" Kind="letter" />
  </ItemGroup>
  <Target Name="Prepare">
    <Message Importance="high" Text="Preparing @(Thing)" />
  </Target>
  <Target Name="Build" DependsOnTargets="Prepare">
    <Message Importance="high" Text="$(Greeting)" />
    <Warning Text="a neutral warning" Code="FF0001" />
  </Target>
</Project>
X
$CLEAN dotnet msbuild tiny.proj -nologo -bl:/work/out/tiny.binlog -v:m

# A console app built with the SDK, without the project import archive
# (which would embed every SDK .props/.targets file).
cd /work
rm -rf hello && mkdir hello && cd hello
cat > hello.csproj <<'X'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
  </PropertyGroup>
</Project>
X
cat > Program.cs <<'X'
class Program { static void Main() { System.Console.WriteLine("hello"); } }
X
$CLEAN dotnet build "-bl:/work/out/build-noimports.binlog;ProjectImports=None" -v:q 2>&1 | tail -3
dotnet --version

# Local time and global properties (tokyo-globalprops.binlog.gz, written as
# gp.binlog): TZ=Asia/Tokyo, so the events' timestamps (DateTimeKind
# Local) are nine hours ahead of UTC, and `-p:Foo=bar`, so ProjectStarted
# and ProjectEvaluationFinished carry a global property list.
mkdir -p /tmp/t && cd /tmp/t
cat > tiny.proj <<'X'
<Project DefaultTargets="Build">
  <Target Name="Prepare"><Message Importance="high" Text="prep $(Foo)" /></Target>
  <Target Name="Build" DependsOnTargets="Prepare"><Message Importance="high" Text="hi" /></Target>
</Project>
X
date -u
$CLEAN TZ=Asia/Tokyo dotnet msbuild tiny.proj -nologo -p:Foo=bar -bl:/work/out/gp.binlog -v:m
