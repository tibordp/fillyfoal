# Elevated: extract ODT and install Office LTSC 2024 (volume, unactivated) + Visio
$odt = 'C:\fillyfoal\winfix\tools\odt'
$exe = Get-ChildItem $odt -Filter '*.exe' | Select-Object -First 1
New-Item -ItemType Directory -Force "$odt\x" | Out-Null
& $exe.FullName /extract:"$odt\x" /quiet | Out-Null
Start-Sleep 3
Get-ChildItem "$odt\x"
$p = Start-Process "$odt\x\setup.exe" -ArgumentList '/configure','C:\fillyfoal\winfix\scripts\office\configuration.xml' -Wait -PassThru
"setup exit: $($p.ExitCode)"
