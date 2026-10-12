# fillyfoal pe/: run after build_x64.cmd and build_arm64.cmd (and before sign.ps1).
# Moves the shipped images/PDBs from C:\fillyfoal\src to winfix\out\pe, moves all other
# src\fixture* intermediates (sources, .obj, compiler _cc.pdb, .lib, .exp) to winfix\work\pe,
# and checks that no src\fixture* file is left. Only files named fixture* are touched.
# (build_fastlink.cmd does its own move/cleanup.)
# Full regeneration order:
#   cmd /c build_x64.cmd ; cmd /c build_arm64.cmd ; powershell -File collect.ps1 ; powershell -File sign.ps1
#   (install_v143.ps1 once, elevated) ; cmd /c build_fastlink.cmd
$ErrorActionPreference = 'Stop'
$src = 'C:\fillyfoal\src'
$out = 'C:\fillyfoal\winfix\out\pe'
$work = 'C:\fillyfoal\winfix\work\pe'
New-Item -ItemType Directory -Force $out, $work | Out-Null
$ship = 'fixture_hello_x64.exe','fixture_hello_x64.pdb',
        'fixture_lib.dll','fixture_lib.pdb','fixture_use.exe','fixture_use.pdb',
        'fixture_hello_arm64.exe','fixture_hello_arm64.pdb',
        'fixture_hello_arm64ec.exe','fixture_hello_arm64ec.pdb',
        'fixture_lib_arm64x.dll','fixture_lib_arm64x.pdb'
foreach ($f in $ship) { Move-Item -LiteralPath (Join-Path $src $f) -Destination $out -Force }
Get-ChildItem -LiteralPath $src -Filter 'fixture*' -File | Move-Item -Destination $work -Force
$left = Get-ChildItem -LiteralPath $src -Filter 'fixture*'
if ($left) { throw "leftover fixture files in ${src}: $($left.Name -join ', ')" }
Write-Host "collected into $out; $src has no fixture* files left"
