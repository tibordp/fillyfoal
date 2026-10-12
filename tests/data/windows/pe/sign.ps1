# fillyfoal pe/: Authenticode-sign a copy of fixture_hello_x64.exe with a fresh self-signed cert.
# Exports only the public .cer; removes the cert (and its private key) from the store afterwards.
param([string]$Src = 'C:\fillyfoal\winfix\out\pe\fixture_hello_x64.exe',
      [string]$OutDir = 'C:\fillyfoal\winfix\out\pe')
$ErrorActionPreference = 'Stop'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\arm64\signtool.exe'
$dst = Join-Path $OutDir 'fixture_hello_x64_signed.exe'
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=fillyfoal test, O=fillyfoal' `
    -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(5)
try {
    Export-Certificate -Cert $cert -FilePath (Join-Path $OutDir 'fixture_codesign.cer') -Type CERT | Out-Null
    $tsa = $null
    foreach ($u in 'http://timestamp.digicert.com','http://timestamp.sectigo.com','http://timestamp.acs.microsoft.com') {
        Copy-Item $Src $dst -Force
        & $signtool sign /v /fd sha256 /sha1 $cert.Thumbprint /s My /tr $u /td sha256 /d 'fillyfoal test' $dst
        if ($LASTEXITCODE -eq 0) { $tsa = $u; break }
        Write-Host "timestamp via $u failed"
    }
    if (-not $tsa) {
        Copy-Item $Src $dst -Force
        & $signtool sign /v /fd sha256 /sha1 $cert.Thumbprint /s My /d 'fillyfoal test' $dst
        if ($LASTEXITCODE -ne 0) { throw 'signing failed' }
        Write-Host 'signed WITHOUT timestamp'
    } else { Write-Host "timestamped via $tsa" }
    & $signtool verify /pa /v $dst   # expected to fail chain validation (untrusted self-signed root)
} finally {
    $cp = 'Cert:\CurrentUser\My\' + $cert.Thumbprint
    Remove-Item -Path $cp -DeleteKey
}
