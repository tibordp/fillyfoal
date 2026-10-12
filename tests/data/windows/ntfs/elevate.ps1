# Run a PowerShell script elevated (UAC set to never prompt), wait, and print its transcript.
param(
    [Parameter(Mandatory)] [string] $Script,
    [string] $Log
)
$Script = (Resolve-Path $Script).Path
if (-not $Log) { $Log = "$Script.log" }
$wrapper = "Start-Transcript -Path '$Log' -Force | Out-Null; try { & '$Script' } catch { `$_ | Out-String | Write-Output; exit 1 } finally { Stop-Transcript | Out-Null }"
$p = Start-Process powershell -Verb RunAs -Wait -PassThru -WindowStyle Hidden `
    -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $wrapper
if (Test-Path $Log) { Get-Content $Log }
"elevated exit code: $($p.ExitCode)"
