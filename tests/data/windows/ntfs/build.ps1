# Builds ntfs-attrlist.vhd, ntfs-wof.vhd and ntfs-lznt1.vhd (16 MiB fixed VHD, MBR, one NTFS partition).
# Must run elevated:
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\fillyfoal\winfix\scripts\common\elevate.ps1 -Script C:\fillyfoal\winfix\scripts\ntfs\build.ps1
param([string[]] $Only = @('attrlist', 'wof', 'lznt1'))
$ErrorActionPreference = 'Continue'
$scripts = 'C:\fillyfoal\winfix\scripts\ntfs'
$work = 'C:\fillyfoal\winfix\work\ntfs'
$out = 'C:\fillyfoal\winfix\out\ntfs'
New-Item -ItemType Directory -Force $work, $out | Out-Null
Set-Location C:\

function Get-FreeLetter {
    $used = [System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name[0] }
    'QRSTUVWXYZ'.ToCharArray() | Where-Object { $used -notcontains $_ } | Select-Object -Last 1
}

function Invoke-DiskpartTemplate($template, $vhd, $letter) {
    $txt = (Get-Content -Raw "$scripts\$template").Replace('__VHD__', $vhd).Replace('__LETTER__', "$letter")
    $tmp = "$work\$template"
    Set-Content -Encoding ascii -Path $tmp -Value $txt
    diskpart /s $tmp
}

# Deterministic, compressible synthetic text.
function New-SyntheticText($path, $tag, $kib) {
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    while ($sb.Length -lt $kib * 1024) {
        [void]$sb.AppendFormat("fillyfoal test {0} line {1:D6}: lorem ipsum dolor sit amet, consectetur adipiscing elit, value {2}`r`n", $tag, $i, ($i * 7919) % 1000)
        $i++
    }
    [System.IO.File]::WriteAllText($path, $sb.ToString(0, $kib * 1024), [System.Text.Encoding]::ASCII)
}

function Build-Volume($name, [scriptblock] $populate) {
    $vhd = "$out\$name.vhd"
    $verify = "$work\$name-verify.txt"
    if (Test-Path $vhd) { Remove-Item $vhd -Force }
    $L = Get-FreeLetter
    "=== $name on ${L}:"
    Invoke-DiskpartTemplate 'diskpart-create.txt' $vhd $L
    Start-Sleep -Seconds 2
    & $populate "${L}:" *>&1 | Tee-Object -FilePath $verify
    "--- fsutil fsinfo ntfsinfo ${L}:" | Tee-Object -Append -FilePath $verify
    fsutil fsinfo ntfsinfo "${L}:" | Tee-Object -Append -FilePath $verify
    "--- cmd dir /a /r ${L}:\" | Tee-Object -Append -FilePath $verify
    cmd /c dir /a /r /s "${L}:\" 2>&1 | Tee-Object -Append -FilePath $verify
    Set-Location C:\
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    Invoke-DiskpartTemplate 'diskpart-detach.txt' $vhd $L
    # Offline check of the detached image (WOF hides its reparse point from fsutil reparsepoint query).
    python -I "$scripts\mftdump.py" $vhd | Out-File -Encoding utf8 "$work\$name-mftdump.txt"
}

# 1. $ATTRIBUTE_LIST. Counts were found by experiment (see manifest): with 6 named 100-byte streams
#    the list stays resident (384 bytes). It goes non-resident once the base record (whose size
#    depends on the $FILE_NAME length) has no room left; 7 streams + a 29-char name already did that.
#    Hard links (120+ char names, own directory each): 6 links -> resident list, 10 -> non-resident.
if ($Only -contains 'attrlist') {
    Build-Volume 'ntfs-attrlist' {
        param($d)
        function Add-Streams($f, $count, $size) {
            Set-Content -Path $f -Value 'fillyfoal test' -Encoding ascii
            for ($i = 1; $i -le $count; $i++) {
                $n = 'stream{0:D3}' -f $i
                $v = ("fillyfoal test stream $n ").PadRight($size, 'x')
                Set-Content -LiteralPath "${f}:$n" -Value $v -Encoding ascii -NoNewline
            }
        }
        function Add-Links($dir, $count) {
            New-Item -ItemType Directory $dir | Out-Null
            $t = "$dir\target.txt"
            Set-Content -Path $t -Value 'fillyfoal test hard link target' -Encoding ascii
            for ($i = 1; $i -le $count; $i++) {
                $n = ('hardlink-{0:D2}-fillyfoal-test-' -f $i).PadRight(120, 'x') + '.txt'
                fsutil hardlink create "$dir\$n" $t | Out-Null
            }
        }
        Add-Streams "$d\attrlist-resident.txt" 6 100
        Add-Streams "$d\attrlist-nonresident.txt" 60 72
        Add-Links "$d\attrlist-resident-hardlinks" 6
        Add-Links "$d\attrlist-nonresident-hardlinks" 10
        foreach ($f in 'attrlist-resident.txt', 'attrlist-nonresident.txt',
                       'attrlist-resident-hardlinks\target.txt', 'attrlist-nonresident-hardlinks\target.txt') {
            "--- fsutil file layout $d\$f"
            fsutil file layout "$d\$f"
        }
    }
}
# 2. WOF (Windows Overlay Filter) compressed files.
if ($Only -contains 'wof') {
    Build-Volume 'ntfs-wof' {
        param($d)
        $algos = 'xpress4k', 'xpress8k', 'xpress16k', 'lzx'
        foreach ($a in $algos) {
            New-SyntheticText "$d\wof-$a.txt" "wof-$a" 320
            compact /c /exe:$a "$d\wof-$a.txt"
        }
        New-SyntheticText "$d\uncompressed-control.txt" 'uncompressed' 320
        "--- compact /q /a $d\"
        compact /q /a "$d\*.txt"
        foreach ($f in (Get-ChildItem "$d\*.txt" | Sort-Object Name)) {

            "--- fsutil file layout $($f.FullName)"
            fsutil file layout $f.FullName
        }
    }
}

# 3. Classic NTFS (LZNT1) compression: compressed file + compressed directory with a file inside.
if ($Only -contains 'lznt1') {
    Build-Volume 'ntfs-lznt1' {
        param($d)
        New-SyntheticText "$d\lznt1-file.txt" 'lznt1-file' 320
        compact /c "$d\lznt1-file.txt"
        New-Item -ItemType Directory "$d\lznt1-dir" | Out-Null
        compact /c "$d\lznt1-dir"
        New-SyntheticText "$d\lznt1-dir\inside-compressed-dir.txt" 'lznt1-dir' 320
        New-SyntheticText "$d\uncompressed-control.txt" 'uncompressed' 320
        "--- compact /q /s:$d\"
        compact /q /a /s:"$d\" *
        foreach ($f in "$d\lznt1-file.txt", "$d\lznt1-dir", "$d\lznt1-dir\inside-compressed-dir.txt", "$d\uncompressed-control.txt") {
            "--- fsutil file layout $f"
            fsutil file layout $f
        }
    }
}


