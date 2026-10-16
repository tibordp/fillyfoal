#!/bin/bash
# A runtime-written EventPipe trace for tests/fixtures/external/nettrace/demo.nettrace.
# Run (writes /tmp/fixtures/dotnet/out/demo.nettrace):
#   mkdir -p /tmp/fixtures/dotnet/out
#   cp tests/data/nettrace/make.sh /tmp/fixtures/dotnet/trace.sh
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/dotnet:/work -w /work \
#     mcr.microsoft.com/dotnet/sdk:8.0 bash /work/trace.sh
# No dotnet-trace needed: the runtime writes the file itself (DOTNET_EnableEventPipe).
# Rundown is off: it would list every JIT-compiled method of the framework.
# (Only `Hello` events appear in the trace; no `Tick` event was written,
# for reasons not investigated.)
set -e
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
cd /work
rm -rf app && mkdir app && cd app
cat > app.csproj <<'X'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
    <AssemblyName>app</AssemblyName>
  </PropertyGroup>
</Project>
X
cat > Program.cs <<'X'
using System.Diagnostics.Tracing;
[EventSource(Name = "Fillyfoal-Demo")]
sealed class Demo : EventSource {
  public static readonly Demo Log = new Demo();
  [Event(1, Level = EventLevel.Informational)] public void Hello(string name, int count) { WriteEvent(1, name, count); }
  [Event(2, Level = EventLevel.Informational)] public void Tick(long n, double ratio) { WriteEvent(2, n, ratio); }
}
class Program {
  static void Main() {
    for (int i = 0; i < 3; i++) { Demo.Log.Hello("fillyfoal", i); Demo.Log.Tick(i * 1000L, i / 4.0); }
    System.GC.Collect();
    System.Console.WriteLine("done");
  }
}
X
dotnet build -c Release -o /work/app/bin -v:q 2>&1 | tail -2
cd /work/app/bin
# Our EventSource with stacks, plus the runtime's GC keyword at informational level
DOTNET_EnableEventPipe=1 \
DOTNET_EventPipeOutputPath=/work/out/demo.nettrace \
DOTNET_EventPipeConfig='Fillyfoal-Demo:0xFFFFFFFF:5,Microsoft-Windows-DotNETRuntime:0x1:4' \
DOTNET_EventPipeOutputStreaming=0 DOTNET_EventPipeRundown=0 \
  dotnet app.dll
ls -la /work/out
