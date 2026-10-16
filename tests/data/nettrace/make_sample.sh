#!/bin/bash
# A runtime-written EventPipe trace with sample profiler and rundown
# events, for tests/fixtures/external/nettrace/sample.nettrace.
# Run (writes /tmp/fixtures/dotnet/out/sample.nettrace):
#   mkdir -p /tmp/fixtures/dotnet/out
#   cp tests/data/nettrace/make_sample.sh /tmp/fixtures/dotnet/sample.sh
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/dotnet:/work -w /work \
#     mcr.microsoft.com/dotnet/sdk:8.0 bash /work/sample.sh
# A program that spins for 30 ms, sampled by the runtime's sample profiler
# (Microsoft-DotNETCore-SampleProfiler); the rundown at the end of the
# session lists the loaded modules, assemblies and JIT-compiled methods
# (Microsoft-Windows-DotNETRuntimeRundown).
set -e
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
cd /work
rm -rf app2 && mkdir app2 && cd app2
cat > app.csproj <<'Y'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
    <AssemblyName>app</AssemblyName>
  </PropertyGroup>
</Project>
Y
cat > Program.cs <<'Y'
class Program {
  static void Main() {
    var sw = System.Diagnostics.Stopwatch.StartNew();
    long n = 0;
    while (sw.ElapsedMilliseconds < 30) { n++; }
    System.Console.WriteLine(n > 0 ? "done" : "none");
  }
}
Y
dotnet build -c Release -o /work/app2/bin -v:q 2>&1 | tail -2
cd /work/app2/bin
DOTNET_EnableEventPipe=1 \
DOTNET_EventPipeOutputPath=/work/out/sample.nettrace \
DOTNET_EventPipeConfig='Microsoft-DotNETCore-SampleProfiler:0:5' \
DOTNET_EventPipeOutputStreaming=0 DOTNET_EventPipeRundown=1 \
  dotnet app.dll
ls -la /work/out
