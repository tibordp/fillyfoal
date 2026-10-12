# Builds out\msi\*: two MSIs (WiX 6), a transform (MsiTran -g) and a patch (wix build patch.wxs).
$ErrorActionPreference = 'Stop'
$src  = $PSScriptRoot
$work = 'C:\fillyfoal\winfix\work\msi'
$out  = 'C:\fillyfoal\winfix\out\msi'
$wix  = 'C:\fillyfoal\winfix\tools\wix\wix.exe'
$sdk  = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86'
New-Item -ItemType Directory -Force $work, $out | Out-Null
Push-Location $work
try {
  foreach ($v in '1.0.0', '1.0.1') {
    & $wix build -arch x86 -d Version=$v -b "$src\files\$v" "$src\product.wxs" `
      -intermediatefolder "$work\obj-$v" -o "$work\$v\fillyfoal-test-$v.msi"
    if ($LASTEXITCODE) { throw "wix build $v failed" }
  }
  & $wix build -arch x86 -d Target="$work\1.0.0\fillyfoal-test-1.0.0.wixpdb" -d Update="$work\1.0.1\fillyfoal-test-1.0.1.wixpdb" `
    -bt "$src\files\1.0.0" -bu "$src\files\1.0.1" "$src\patch.wxs" -intermediatefolder "$work\obj-patch" -o "$work\patch\fillyfoal-test-1.0.1.msp"
  if ($LASTEXITCODE) { throw 'wix build patch failed' }

  Copy-Item "$work\1.0.0\fillyfoal-test-1.0.0.msi", "$work\1.0.1\fillyfoal-test-1.0.1.msi", "$work\patch\fillyfoal-test-1.0.1.msp" $out -Force
  # Transform: base 1.0.0 -> reference 1.0.1, with default error-suppression/validation flags
  Remove-Item "$out\fillyfoal-test-1.0.0-to-1.0.1.mst" -ErrorAction SilentlyContinue
  & "$sdk\MsiTran.exe" -g "$out\fillyfoal-test-1.0.0.msi" "$out\fillyfoal-test-1.0.1.msi" "$out\fillyfoal-test-1.0.0-to-1.0.1.mst"
  if ($LASTEXITCODE) { throw "MsiTran failed $LASTEXITCODE" }
} finally { Pop-Location }
