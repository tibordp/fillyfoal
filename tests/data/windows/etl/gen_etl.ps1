# Regenerates the etl/ fixtures. Must run elevated:
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\fillyfoal\winfix\scripts\common\elevate.ps1 -Script C:\fillyfoal\winfix\scripts\etl\gen_etl.ps1
# Prereq: fillyfoal_tlg.exe built with build_tlg.cmd (into C:\fillyfoal\winfix\work\etl).
param([string[]] $Only = @('kproc', 'tlg', 'comp', 'kernel'))
$ErrorActionPreference = 'Continue'
$out  = 'C:\fillyfoal\winfix\out\etl'
$work = 'C:\fillyfoal\winfix\work\etl'
$xperf = 'C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe'
$tlgGuid = '{a946bbbd-88e8-5895-7beb-4d343c1d945f}'   # fillyfoal-test (EventSource name hash)
New-Item -ItemType Directory -Force $out, $work | Out-Null
Set-Location $work

function Stop-Quiet($name) { logman stop $name -ets 2>&1 | Out-Null }

# 1. Manifest-based provider: Microsoft-Windows-Kernel-Process, keyword 0x10 (WINEVENT_KEYWORD_PROCESS), level 4
if ($Only -contains 'kproc') {
    $f = "$out\kernel-process-manifest.etl"; Remove-Item $f -ErrorAction SilentlyContinue
    Stop-Quiet ff-kproc
    logman start ff-kproc -p Microsoft-Windows-Kernel-Process 0x10 0x4 -o $f -bs 16 -nb 2 8 -ets
    cmd /c echo fillyfoal test 1 | Out-Null
    cmd /c echo fillyfoal test 2 | Out-Null
    Start-Sleep -Milliseconds 700
    logman stop ff-kproc -ets
}

# 2. TraceLogging provider "fillyfoal-test" (self-describing events) from fillyfoal_tlg.exe
if ($Only -contains 'tlg') {
    $f = "$out\tracelogging-fillyfoal.etl"; Remove-Item $f -ErrorAction SilentlyContinue
    Stop-Quiet ff-tlg
    logman start ff-tlg -p $tlgGuid 0xFFFFFFFFFFFFFFFF 0x5 -o $f -bs 16 -nb 2 8 -ets
    & "$work\fillyfoal_tlg.exe"
    Start-Sleep -Milliseconds 300
    logman stop ff-tlg -ets
}

# 3. Compressed ETL
if ($Only -contains 'comp') {
    # 3a. xperf -merge -mergeonly -compress of the TraceLogging trace
    $f = "$out\tracelogging-fillyfoal-xperf-compressed.etl"; Remove-Item $f -ErrorAction SilentlyContinue
    & $xperf -merge "$out\tracelogging-fillyfoal.etl" $f -mergeonly -compress
    # 3b. Session that writes compressed buffers itself: ff_comp.exe = StartTrace with
    #     EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_COMPRESSED_MODE (0x04000000)
    #     (logman -mode 0x4000000 is silently ignored, so a small controller program is used).
    $f = "$out\compressed-session-kproc-tlg.etl"; Remove-Item $f -ErrorAction SilentlyContinue
    & "$work\ff_comp.exe" $f "$work\fillyfoal_tlg.exe"
}

# 4. NT Kernel Logger via ff_klog.exe (StartTrace/ControlTrace), thread events only, with
#    EVENT_TRACE_FLAG_NO_SYSCONFIG (0x10000000) so no SystemConfig rundown (it holds the NIC IP
#    addresses). The process flag is not used: its rundown carries the command lines of every
#    running process on the box, which is not publishable. Raw and xperf-merged (-suppresspii).
if ($Only -contains 'kernel') {
    $raw = "$out\kernel-logger-thread-raw.etl"
    $mrg = "$out\kernel-logger-thread-merged.etl"
    Remove-Item $raw, $mrg -ErrorAction SilentlyContinue
    & "$work\ff_klog.exe" kernel $raw 10000002 500
    & $xperf -merge $raw $mrg -suppresspii
}

foreach ($e in Get-ChildItem "$out\*.etl") {
    tracerpt $e.FullName -o "$work\$($e.BaseName).csv" -of CSV -summary "$work\$($e.BaseName).summary.txt" -report "$work\$($e.BaseName).report.xml" -y | Out-Null
}
Get-ChildItem $out | Format-Table Name, Length
