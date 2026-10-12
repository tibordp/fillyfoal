# Unattended crash-dump state machine. Runs as SYSTEM at every startup (scheduled task
# "fillyfoal-crashloop", created by setup.ps1). For each dump type in $plan:
#   boot A ("armed"):   CrashDumpEnabled already set at the previous boot -> crash with NotMyFault
#   boot B ("crashed"): collect the dump written by that crash, set the next type, reboot
# After the last type it restores CrashDumpEnabled=7, removes the task and stops.
$ErrorActionPreference = 'Continue'
$root  = 'C:\fillyfoal\winfix\work\kernel-dump'
$state = "$root\state.json"
$log   = "$root\crashloop.log"
$cc    = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$nmf   = 'C:\fillyfoal\winfix\tools\notmyfault\x\notmyfaultc64a.exe'   # ARM64 console build
$plan  = @(
    @{ name = 'small';     value = 3 },   # small memory dump (256 KB-class minidump)
    @{ name = 'kernel';    value = 2 },   # kernel memory dump
    @{ name = 'automatic'; value = 7 },   # automatic memory dump
    @{ name = 'complete';  value = 1 }    # complete memory dump
)
function Log($m) { "$((Get-Date).ToUniversalTime().ToString('s'))Z $m" | Add-Content $log }
function Save($s) { $s | ConvertTo-Json | Set-Content $state }

$s = Get-Content $state -Raw | ConvertFrom-Json
Log "boot: index=$($s.index) phase=$($s.phase)"
Start-Sleep -Seconds 90   # let the boot settle and the dump be moved out of the dedicated dump file

if ($s.phase -eq 'crashed') {
    $p = $plan[$s.index]
    $dest = Join-Path $root $p.name
    New-Item -ItemType Directory -Force $dest | Out-Null
    $since = [datetime]::Parse($s.crashedAt).ToUniversalTime()
    # Wait (up to 30 min) for the dump file(s) to appear and stop growing.
    function Found {
        $script:mem  = Get-Item 'C:\Windows\MEMORY.DMP' -EA SilentlyContinue | ? { $_.LastWriteTimeUtc -gt $since }
        $script:mini = @(Get-ChildItem 'C:\Windows\Minidump\*.dmp' -EA SilentlyContinue | ? { $_.LastWriteTimeUtc -gt $since })
        (@($script:mem) + $script:mini | ? { $_ } | % { "$($_.Name):$($_.Length)" }) -join ','
    }
    $prev = ''
    for ($t = 0; $t -lt 180; $t++) {
        $cur = Found
        $ready = if ($p.value -eq 3) { $mini.Count -gt 0 } else { [bool]$mem }
        if ($ready -and $cur -eq $prev) { break }   # present and unchanged for 10 s
        $prev = $cur
        Start-Sleep 10
    }
    Log "found: $(Found)"
    if ($mem)  { Move-Item $mem.FullName (Join-Path $dest 'MEMORY.DMP') -Force; Log "moved MEMORY.DMP ($($mem.Length)) to $dest" }
    foreach ($m in $mini) { Move-Item $m.FullName (Join-Path $dest $m.Name) -Force; Log "moved $($m.Name) ($($m.Length)) to $dest" }
    if (-not $mem -and -not $mini) { Log "WARNING: no dump found for $($p.name)" }
    Get-ItemProperty $cc | Out-String | Set-Content (Join-Path $dest 'CrashControl.txt')

    $s.index++
    if ($s.index -ge $plan.Count) {
        Set-ItemProperty $cc CrashDumpEnabled 7
        $s.phase = 'done'; Save $s
        Log 'all dump types done; CrashDumpEnabled restored to 7; removing task'
        schtasks /Delete /TN fillyfoal-crashloop /F | Out-Null
        return
    }
    $n = $plan[$s.index]
    Set-ItemProperty $cc CrashDumpEnabled $n.value
    $s.phase = 'armed'; Save $s
    Log "armed $($n.name) (CrashDumpEnabled=$($n.value)); rebooting"
    shutdown /r /t 5 /c "fillyfoal crashloop: arming $($n.name) dump"
    return
}

if ($s.phase -eq 'armed') {
    $p = $plan[$s.index]
    Log "crashing for $($p.name) dump; CrashDumpEnabled=$((Get-ItemProperty $cc).CrashDumpEnabled)"
    $s.phase = 'crashed'; $s.crashedAt = (Get-Date).ToUniversalTime().ToString('o'); Save $s
    Start-Sleep 5
    & $nmf /accepteula /crash 0x01   # High IRQL fault (kernel mode) -> bugcheck 0xD1
    Start-Sleep 60
    Log 'ERROR: still running after crash request'
}
