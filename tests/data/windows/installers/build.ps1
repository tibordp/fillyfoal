# Compiles fillyfoal-test.iss with each installed Inno Setup version -> out\installers\setup-<ver>.exe
$ErrorActionPreference = 'Stop'
$work = 'C:\fillyfoal\winfix\work\installers\src'
$out  = 'C:\fillyfoal\winfix\out\installers'
New-Item -ItemType Directory -Force $work, $out | Out-Null
Copy-Item "$PSScriptRoot\fillyfoal-test.iss" $work -Force
$nl = "`r`n"
[IO.File]::WriteAllText("$work\readme.txt", "fillyfoal test$($nl)Lorem ipsum dolor sit amet.$nl")
[IO.File]::WriteAllText("$work\data.txt", "0 1 2 3 4 5 6 7 8 9$nl")
Push-Location $work
try {
  foreach ($v in '6.3.3', '6.4.3', '6.5.4', '6.6.1', '6.7.3', '7.0.2', '7.1.0') {
    $iscc = "C:\fillyfoal\winfix\tools\innosetup-$v\ISCC.exe"
    & $iscc "/O$out" "/Fsetup-$v" "$work\fillyfoal-test.iss" | Tee-Object -FilePath "C:\fillyfoal\winfix\work\installers\iscc-$v.log"
    if ($LASTEXITCODE) { throw "ISCC $v failed" }
  }
} finally { Pop-Location }


