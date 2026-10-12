# Regenerates the ESE fixtures into C:\fillyfoal\winfix\out\ese (no elevation needed).
$ErrorActionPreference = 'Stop'
$src  = $PSScriptRoot
$work = 'C:\fillyfoal\winfix\work\ese'
$out  = 'C:\fillyfoal\winfix\out\ese'
New-Item -ItemType Directory -Force $work, $out | Out-Null
# build from a copy so no bin/obj ends up in the scripts folder
New-Item -ItemType Directory -Force "$work\src" | Out-Null
Copy-Item "$src\EseFixtures.csproj", "$src\Program.cs" "$work\src\" -Force
dotnet build "$work\src\EseFixtures.csproj" -c Release -o "$work\bin" | Out-Host
if ($LASTEXITCODE) { throw 'build failed' }
$exe = "$work\bin\EseFixtures.exe"
& $exe plain 32768 "$work\db32k" "$out\ese_32k_pages_lv.edb" 16;        if ($LASTEXITCODE) { throw 'db32k' }
& $exe plain 8192  "$work\db8k"  "$out\ese_8k_pages_lv.edb" 1;         if ($LASTEXITCODE) { throw 'db8k' }
& $exe compressed 8192 "$work\dbcomp" "$out\ese_8k_compressed_columns.edb" 16; if ($LASTEXITCODE) { throw 'dbcomp' }
foreach ($f in Get-ChildItem "$out\*.edb") { esentutl /mh $f.FullName | Out-File -Encoding utf8 "$work\$($f.BaseName).mh.txt"; Get-Content "$work\$($f.BaseName).mh.txt" }
