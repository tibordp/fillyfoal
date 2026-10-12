# One-time setup for crashloop.ps1 (run elevated). Afterwards reboot once; the rest is unattended
# (about 8 reboots). Progress: C:\fillyfoal\winfix\work\kernel-dump\crashloop.log
$root = 'C:\fillyfoal\winfix\work\kernel-dump'
New-Item -ItemType Directory -Force $root | Out-Null
$cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
# The pagefile is a fixed 1 GiB, too small for kernel/complete dumps of a 16 GiB VM, so give the
# crash dump stack a dedicated dump file big enough for a complete dump (RAM + headroom).
Set-ItemProperty $cc DedicatedDumpFile 'C:\fillyfoal-dedicated-dump.sys'
Set-ItemProperty $cc DumpFileSize 17500 -Type DWord        # MiB
Set-ItemProperty $cc AutoReboot 1 -Type DWord
Set-ItemProperty $cc Overwrite 1 -Type DWord
Set-ItemProperty $cc AlwaysKeepMemoryDump 1 -Type DWord   # don't let WER delete it on low disk
Set-ItemProperty $cc CrashDumpEnabled 3 -Type DWord        # first type: small memory dump
@{ index = 0; phase = 'armed'; crashedAt = '' } | ConvertTo-Json | Set-Content "$root\state.json"
$task = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\fillyfoal\winfix\scripts\kernel-dump\crashloop.ps1'
schtasks /Create /TN fillyfoal-crashloop /SC ONSTART /RU SYSTEM /RL HIGHEST /TR $task /F
Get-ItemProperty $cc | Out-String
