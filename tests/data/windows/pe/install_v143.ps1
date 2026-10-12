# fillyfoal pe/: add the VS 2022 (v143, MSVC 14.44) x64 toolset to the Build Tools 2026 instance.
# Run elevated (via scripts\common\elevate.ps1). Needed for /DEBUG:FASTLINK (dropped in link 14.5x).
$setup = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe'
$cmdline = 'modify --installPath "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools" ' +
           '--add Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64 --quiet --norestart'
for ($i = 0; $i -lt 20; $i++) {
    $p = Start-Process -FilePath $setup -ArgumentList $cmdline -Wait -PassThru
    Write-Host "setup.exe exit code: $($p.ExitCode)"
    if ($p.ExitCode -ne 1618) { break }   # 1618 = another install in progress
    Start-Sleep -Seconds 30
}
Get-ChildItem 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC' -Name
