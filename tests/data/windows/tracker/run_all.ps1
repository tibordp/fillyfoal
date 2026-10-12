# Regenerate out\tracker\ with OpenMPT 1.32.11.00 portable ARM64 (in tools\openmpt\app).
# Requires: python + pywinauto (pip install --user pywinauto). Not elevated.
# Pass 1 (Misc.ITCompressionMono=0): IT + compat-export IT with uncompressed samples.
# Pass 2 (Misc.ITCompressionMono=7): IT + compat-export IT with IT-compressed samples, then
#        Song Properties > Type = "OpenMPT MPTM" and Save As .mptm.
# First-run dialogs (Welcome / update check / statistics) must have been answered once
# (welcome.py); any that reappear are declined by hand or auto-dismiss.
$ErrorActionPreference = 'Stop'
$app  = 'C:\fillyfoal\winfix\tools\openmpt\app'
$ini  = "$app\mptrack.ini"
$work = 'C:\fillyfoal\winfix\work\tracker'
$s    = 'C:\fillyfoal\winfix\scripts\tracker'
python -I "$s\make_seed_it.py" "$work\seed.it"

function Set-Compression([int]$v) {
    $t = [IO.File]::ReadAllText($ini).TrimStart([char]0xFEFF)
    if ($t -notmatch '\[Misc\]') { $t += "`r`n[Misc]`r`n" }
    if ($t -match 'ITCompressionMono=\d+') { $t = $t -replace 'ITCompressionMono=\d+', "ITCompressionMono=$v" }
    else { $t = $t -replace '\[Misc\]\r?\n', "[Misc]`r`nITCompressionMono=$v`r`nITCompressionStereo=0`r`nDefaultArtist=fillyfoal`r`n" }
    [IO.File]::WriteAllText($ini, $t)
}
function Start-Mpt {
    $p = Start-Process "$app\OpenMPT.exe" -ArgumentList "`"$work\seed.it`"" -PassThru
    Start-Sleep 6
    python "$s\omp.py" $p.Id windows
    python "$s\omp.py" $p.Id artist fillyfoal
    return $p.Id
}

Set-Compression 0
$id = Start-Mpt
python "$s\omp.py" $id save "Save As..." "$work\fillyfoal-uncompressed.it"
python "$s\omp.py" $id save "Compatibility Export..." "$work\fillyfoal-compat-uncompressed.it"
python "$s\omp.py" $id exit

Set-Compression 7
$id = Start-Mpt
python "$s\omp.py" $id save "Save As..." "$work\fillyfoal-compressed.it"
python "$s\omp.py" $id save "Compatibility Export..." "$work\fillyfoal-compat-compressed.it"
python "$s\omp.py" $id mptm
python "$s\omp.py" $id save "Save As..." "$work\fillyfoal.mptm"
python "$s\omp.py" $id exit

python -I "$s\check_it.py" "$work\fillyfoal-uncompressed.it" "$work\fillyfoal-compat-uncompressed.it" `
    "$work\fillyfoal-compressed.it" "$work\fillyfoal-compat-compressed.it" "$work\fillyfoal.mptm"
