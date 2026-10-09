<#
.SYNOPSIS
  Makes fillyfoal's Windows fixtures with Windows' own components: an EVTX
  event log, registry hives (latest and standard format), an ESE database,
  minidumps and, if Outlook is installed, a PST.

.DESCRIPTION
  Run in an elevated Windows PowerShell 5.1 (or 7) session on a throwaway or
  temporarily renamed VM:

      Rename-Computer -NewName FILLYFOAL -Restart     # once, before running
      Set-ExecutionPolicy -Scope Process Bypass
      .\make-fixtures.ps1                            # writes C:\fillyfoal-fixtures

  Event records and ESE database headers contain the computer name, and
  registry keys carry their owner's SID, so the script refuses to run unless
  the computer is named FILLYFOAL, sets registry ownership to
  BUILTIN\Administrators, and finally scans every output for the user name,
  computer name, full name and user SID (ASCII and UTF-16, text and binary
  SID), deleting any file that fails. Everything it registers (event log,
  registry key) is removed again.

  Copy the output folder to the Mac; fixtures are listed in
  tests/fixtures/external/SOURCES.md with this script as their source.
#>
param(
    [string]$OutDir = 'C:\fillyfoal-fixtures',
    [switch]$SkipPst
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

if ($env:COMPUTERNAME -ne 'FILLYFOAL') {
    throw "Rename the computer to FILLYFOAL first (Rename-Computer -NewName FILLYFOAL -Restart): event logs and ESE headers record the computer name."
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated (Administrator) PowerShell.'
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Set-Location $OutDir

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class FillyNative {
    // --- registry ---
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegOpenKeyExW(IntPtr hKey, string subKey, uint options, int sam, out IntPtr result);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegSaveKeyExW(IntPtr hKey, string file, IntPtr security, uint flags);
    [DllImport("advapi32.dll")]
    public static extern int RegCloseKey(IntPtr hKey);

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValueW(string system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, uint len, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    public static void EnablePrivilege(string name) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Exception("OpenProcessToken failed");
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.Count = 1; tp.Attributes = 2;
        if (!LookupPrivilegeValueW(null, name, out tp.Luid)) throw new Exception("LookupPrivilegeValue failed");
        if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) throw new Exception("AdjustTokenPrivileges failed");
    }

    public static void SaveKey(string subKey, string file, uint flags) {
        // HKEY_CURRENT_USER, sign-extended as Windows defines it.
        IntPtr hkcu = new IntPtr(unchecked((int)0x80000001));
        IntPtr key;
        int rc = RegOpenKeyExW(hkcu, subKey, 0, 0x20019, out key);
        if (rc != 0) throw new Exception("RegOpenKeyEx failed: " + rc);
        try {
            rc = RegSaveKeyExW(key, file, IntPtr.Zero, flags);
            if (rc != 0) throw new Exception("RegSaveKeyEx failed: " + rc);
        } finally { RegCloseKey(key); }
    }

    // --- minidump ---
    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr process, uint pid, Microsoft.Win32.SafeHandles.SafeFileHandle file,
        uint type, IntPtr exception, IntPtr user, IntPtr callback);
    public static void Dump(System.Diagnostics.Process p, string file, uint type) {
        using (System.IO.FileStream fs = new System.IO.FileStream(file, System.IO.FileMode.Create)) {
            if (!MiniDumpWriteDump(p.Handle, (uint)p.Id, fs.SafeFileHandle, type, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                throw new Exception("MiniDumpWriteDump failed: " + Marshal.GetLastWin32Error());
        }
    }

    // --- ESE (esent.dll) ---
    [StructLayout(LayoutKind.Sequential)]
    public struct JET_COLUMNDEF {
        public uint cbStruct, columnid, coltyp;
        public ushort wCountry, langid, cp, wCollate;
        public uint cbMax, grbit;
    }
    [DllImport("esent.dll", CharSet = CharSet.Ansi)] static extern int JetCreateInstanceA(out IntPtr instance, string name);
    [DllImport("esent.dll", CharSet = CharSet.Ansi)] static extern int JetSetSystemParameterA(ref IntPtr instance, IntPtr sesid, uint param, IntPtr lParam, string sz);
    [DllImport("esent.dll")] static extern int JetInit(ref IntPtr instance);
    [DllImport("esent.dll", CharSet = CharSet.Ansi)] static extern int JetBeginSessionA(IntPtr instance, out IntPtr sesid, string user, string pwd);
    [DllImport("esent.dll", CharSet = CharSet.Ansi)] static extern int JetCreateDatabaseA(IntPtr sesid, string file, string connect, out uint dbid, uint grbit);
    [DllImport("esent.dll", CharSet = CharSet.Ansi)] static extern int JetCreateTableA(IntPtr sesid, uint dbid, string name, uint pages, uint density, out IntPtr tableid);
    [DllImport("esent.dll", CharSet = CharSet.Ansi)] static extern int JetAddColumnA(IntPtr sesid, IntPtr tableid, string name, ref JET_COLUMNDEF def, IntPtr deflt, uint cbDefault, out uint columnid);
    [DllImport("esent.dll", CharSet = CharSet.Ansi)] static extern int JetCreateIndexA(IntPtr sesid, IntPtr tableid, string name, uint grbit, string keyDesc, uint cbKey, uint density);
    [DllImport("esent.dll")] static extern int JetBeginTransaction(IntPtr sesid);
    [DllImport("esent.dll")] static extern int JetCommitTransaction(IntPtr sesid, uint grbit);
    [DllImport("esent.dll")] static extern int JetPrepareUpdate(IntPtr sesid, IntPtr tableid, uint prep);
    [StructLayout(LayoutKind.Sequential)]
    public struct JET_SETINFO { public uint cbStruct, ibLongValue, itagSequence; }
    [DllImport("esent.dll")] static extern int JetSetColumn(IntPtr sesid, IntPtr tableid, uint columnid, byte[] data, uint cb, uint grbit, IntPtr setinfo);
    [DllImport("esent.dll", EntryPoint = "JetSetColumn")] static extern int JetSetColumnInfo(IntPtr sesid, IntPtr tableid, uint columnid, byte[] data, uint cb, uint grbit, ref JET_SETINFO setinfo);
    [DllImport("esent.dll")] static extern int JetUpdate(IntPtr sesid, IntPtr tableid, IntPtr bookmark, uint cb, IntPtr actual);
    [DllImport("esent.dll")] static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);
    [DllImport("esent.dll")] static extern int JetCloseDatabase(IntPtr sesid, uint dbid, uint grbit);
    [DllImport("esent.dll", CharSet = CharSet.Ansi)] static extern int JetDetachDatabaseA(IntPtr sesid, string file);
    [DllImport("esent.dll")] static extern int JetEndSession(IntPtr sesid, uint grbit);
    [DllImport("esent.dll")] static extern int JetTerm(IntPtr instance);

    static void Check(int rc, string what) { if (rc < 0) throw new Exception(what + " failed: " + rc); }

    static uint Col(IntPtr s, IntPtr t, string name, uint coltyp, uint cbMax, ushort cp, uint grbit) {
        JET_COLUMNDEF d = new JET_COLUMNDEF();
        d.cbStruct = (uint)Marshal.SizeOf(typeof(JET_COLUMNDEF));
        d.coltyp = coltyp; d.cbMax = cbMax; d.cp = cp; d.grbit = grbit;
        uint id;
        Check(JetAddColumnA(s, t, name, ref d, IntPtr.Zero, 0, out id), "JetAddColumn " + name);
        return id;
    }
    static void Set(IntPtr s, IntPtr t, uint col, byte[] v) {
        Check(JetSetColumn(s, t, col, v, (uint)v.Length, 0, IntPtr.Zero), "JetSetColumn");
    }
    // Appends another value to a multi-valued column (itagSequence 0).
    static void Append(IntPtr s, IntPtr t, uint col, byte[] v) {
        JET_SETINFO info = new JET_SETINFO();
        info.cbStruct = (uint)Marshal.SizeOf(typeof(JET_SETINFO));
        info.itagSequence = 0;
        Check(JetSetColumnInfo(s, t, col, v, (uint)v.Length, 0, ref info), "JetSetColumn (append)");
    }
    static int Index(IntPtr s, IntPtr t, string name, uint grbit, string keyDesc, uint density) {
        // keyDesc ends with the double NUL; cbKey counts it.
        return JetCreateIndexA(s, t, name, grbit, keyDesc, (uint)keyDesc.Length, density);
    }

    // Byte search for the privacy scan (PowerShell loops are too slow).
    public static bool Contains(byte[] hay, byte[] needle) {
        if (needle.Length == 0 || hay.Length < needle.Length) return false;
        for (int i = 0; i <= hay.Length - needle.Length; i++) {
            int j = 0;
            while (j < needle.Length && hay[i + j] == needle[j]) j++;
            if (j == needle.Length) return true;
        }
        return false;
    }

    public static void MakeEse(string dir, string file) {
        IntPtr inst;
        Check(JetCreateInstanceA(out inst, "fillyfoal"), "JetCreateInstance");
        Check(JetSetSystemParameterA(ref inst, IntPtr.Zero, 0, IntPtr.Zero, dir + "\\"), "SystemPath");
        Check(JetSetSystemParameterA(ref inst, IntPtr.Zero, 1, IntPtr.Zero, dir + "\\"), "TempPath");
        Check(JetSetSystemParameterA(ref inst, IntPtr.Zero, 2, IntPtr.Zero, dir + "\\"), "LogFilePath");
        Check(JetSetSystemParameterA(ref inst, IntPtr.Zero, 3, IntPtr.Zero, "fly"), "BaseName");
        Check(JetSetSystemParameterA(ref inst, IntPtr.Zero, 34, IntPtr.Zero, "Off"), "Recovery");
        Check(JetInit(ref inst), "JetInit");
        IntPtr s; uint db;
        Check(JetBeginSessionA(inst, out s, "", ""), "JetBeginSession");
        Check(JetCreateDatabaseA(s, file, null, out db, 0), "JetCreateDatabase");

        Check(JetBeginTransaction(s), "JetBeginTransaction");
        IntPtr t;
        Check(JetCreateTableA(s, db, "Fixtures", 16, 80, out t), "JetCreateTable");
        uint cId = Col(s, t, "Id", 4, 0, 0, 0x10);            // Long, autoincrement
        uint cFlag = Col(s, t, "Flag", 1, 0, 0, 0);            // Bit
        uint cByte = Col(s, t, "Small", 2, 0, 0, 0);           // UnsignedByte
        uint cShort = Col(s, t, "Short", 3, 0, 0, 0);          // Short
        uint cMoney = Col(s, t, "Money", 5, 0, 0, 0);          // Currency
        uint cSingle = Col(s, t, "Single", 6, 0, 0, 0);        // IEEESingle
        uint cDouble = Col(s, t, "Double", 7, 0, 0, 0);        // IEEEDouble
        uint cDate = Col(s, t, "When", 8, 0, 0, 0);            // DateTime
        uint cBin = Col(s, t, "Bytes", 9, 255, 0, 0);          // Binary
        uint cText = Col(s, t, "Name", 10, 255, 1200, 0);      // Text, UTF-16
        uint cAscii = Col(s, t, "Ascii", 10, 255, 1252, 0);    // Text, ANSI
        uint cLongBin = Col(s, t, "Blob", 11, 0, 0, 0);        // LongBinary
        uint cLongText = Col(s, t, "Notes", 12, 0, 1200, 0);   // LongText
        uint cU32 = Col(s, t, "U32", 14, 0, 0, 0);             // UnsignedLong
        uint cI64 = Col(s, t, "I64", 15, 0, 0, 0);             // LongLong
        uint cGuid = Col(s, t, "Guid", 16, 0, 0, 0);           // GUID
        uint cU16 = Col(s, t, "U16", 17, 0, 0, 0);             // UnsignedShort
        uint cTags = Col(s, t, "Tags", 10, 64, 1200, 0x2 | 0x400); // JET_bitColumnTagged | JET_bitColumnMultiValued
        Check(Index(s, t, "PrimaryKey", 0x1 | 0x2, "+Id\0\0", 90), "JetCreateIndex primary");
        Check(Index(s, t, "ByName", 0, "+Name\0-When\0\0", 80), "JetCreateIndex ByName");

        Random rnd = new Random(1234);
        for (int i = 0; i < 400; i++) {
            Check(JetPrepareUpdate(s, t, 0), "JetPrepareUpdate");
            Set(s, t, cFlag, new byte[] { (byte)(i % 2) });
            Set(s, t, cByte, new byte[] { (byte)i });
            Set(s, t, cShort, BitConverter.GetBytes((short)(i - 200)));
            Set(s, t, cMoney, BitConverter.GetBytes((long)i * 12345));
            Set(s, t, cSingle, BitConverter.GetBytes(i / 3.0f));
            Set(s, t, cDouble, BitConverter.GetBytes(Math.PI * i));
            Set(s, t, cDate, BitConverter.GetBytes(new DateTime(2024, 1, 2, 3, 4, 5).AddHours(i).ToOADate()));
            byte[] b = new byte[16 + i % 32]; rnd.NextBytes(b); Set(s, t, cBin, b);
            Set(s, t, cText, Encoding.Unicode.GetBytes("fixture row " + i));
            Set(s, t, cAscii, Encoding.ASCII.GetBytes("ascii " + i));
            if (i % 50 == 0) {
                byte[] blob = new byte[20000]; rnd.NextBytes(blob); Set(s, t, cLongBin, blob);
                Set(s, t, cLongText, Encoding.Unicode.GetBytes(new string('x', 3000) + " long text " + i));
            }
            Set(s, t, cU32, BitConverter.GetBytes((uint)(i * 1000)));
            Set(s, t, cI64, BitConverter.GetBytes((long)i << 40));
            Set(s, t, cGuid, new Guid(i, 1, 2, new byte[] { 3, 4, 5, 6, 7, 8, 9, 10 }).ToByteArray());
            Set(s, t, cU16, BitConverter.GetBytes((ushort)(i * 7)));
            if (i % 10 == 0) {
                Append(s, t, cTags, Encoding.Unicode.GetBytes("alpha"));
                Append(s, t, cTags, Encoding.Unicode.GetBytes("beta"));
            }
            Check(JetUpdate(s, t, IntPtr.Zero, 0, IntPtr.Zero), "JetUpdate");
        }
        Check(JetCloseTable(s, t), "JetCloseTable");

        IntPtr t2;
        Check(JetCreateTableA(s, db, "Small", 1, 100, out t2), "JetCreateTable Small");
        uint k = Col(s, t2, "Key", 10, 64, 1200, 0);
        uint v = Col(s, t2, "Value", 4, 0, 0, 0);
        Check(Index(s, t2, "PK", 0x1 | 0x2, "+Key\0\0", 100), "JetCreateIndex PK");
        foreach (string name in new string[] { "one", "two", "three" }) {
            Check(JetPrepareUpdate(s, t2, 0), "JetPrepareUpdate");
            Set(s, t2, k, Encoding.Unicode.GetBytes(name));
            Set(s, t2, v, BitConverter.GetBytes(name.Length));
            Check(JetUpdate(s, t2, IntPtr.Zero, 0, IntPtr.Zero), "JetUpdate");
        }
        Check(JetCloseTable(s, t2), "JetCloseTable");
        Check(JetCommitTransaction(s, 0), "JetCommitTransaction");

        Check(JetCloseDatabase(s, db, 0), "JetCloseDatabase");
        Check(JetDetachDatabaseA(s, file), "JetDetachDatabase");
        Check(JetEndSession(s, 0), "JetEndSession");
        Check(JetTerm(inst), "JetTerm");
    }
}
'@

$outputs = New-Object System.Collections.Generic.List[string]
$script:extraWords = @()

# --- 1. EVTX ---------------------------------------------------------------
Write-Host 'EVTX...'
$log = 'Fillyfoal'
if ([System.Diagnostics.EventLog]::Exists($log)) { Remove-EventLog -LogName $log }
New-EventLog -LogName $log -Source 'FillyfoalSource', 'FillyfoalOther'
Limit-EventLog -LogName $log -MaximumSize 1MB
$types = 'Information', 'Warning', 'Error', 'SuccessAudit', 'FailureAudit'
for ($i = 0; $i -lt 600; $i++) {
    $msg = "fillyfoal fixture event $i`r`nsecond line with a value of $($i * 7)"
    $raw = [byte[]](0..($i % 40) | ForEach-Object { [byte](($_ * 31 + $i) % 256) })
    $src = @('FillyfoalSource', 'FillyfoalOther')[$i % 2]
    Write-EventLog -LogName $log -Source $src -EventId (1000 + $i % 17) -EntryType $types[$i % 5] `
        -Category ([int16]($i % 4)) -Message $msg -RawData $raw
}
$evtx = Join-Path $OutDir 'fillyfoal.evtx'
if (Test-Path $evtx) { Remove-Item $evtx }
wevtutil epl $log $evtx
if ($LASTEXITCODE -ne 0) { throw 'wevtutil epl failed' }
Remove-EventLog -LogName $log
$outputs.Add($evtx)

# --- 2. Registry hives --------------------------------------------------------
Write-Host 'Registry hives...'
$keyPath = 'HKCU:\Software\Fillyfoal'
if (Test-Path $keyPath) { Remove-Item $keyPath -Recurse -Force }
New-Item -Path $keyPath | Out-Null
New-ItemProperty -Path $keyPath -Name 'String' -PropertyType String -Value 'hello registry' | Out-Null
New-ItemProperty -Path $keyPath -Name 'Expand' -PropertyType ExpandString -Value '%SystemRoot%\fillyfoal' | Out-Null
New-ItemProperty -Path $keyPath -Name 'Multi' -PropertyType MultiString -Value @('one', 'two', 'three') | Out-Null
New-ItemProperty -Path $keyPath -Name 'Dword' -PropertyType DWord -Value 0x12345678 | Out-Null
New-ItemProperty -Path $keyPath -Name 'Qword' -PropertyType QWord -Value 0x123456789ABCDEF0 | Out-Null
New-ItemProperty -Path $keyPath -Name 'SmallBinary' -PropertyType Binary -Value ([byte[]](1, 2, 3, 4)) | Out-Null
$big = New-Object byte[] 40000
(New-Object Random 42).NextBytes($big)
New-ItemProperty -Path $keyPath -Name 'BigBinary' -PropertyType Binary -Value $big | Out-Null   # > 16 KiB: big-data cell
Set-Item -Path $keyPath -Value 'default value'
New-ItemProperty -Path $keyPath -Name ('LongName' + ('x' * 200)) -PropertyType String -Value 'long value name' | Out-Null
# REG_NONE, REG_LINK-like and odd types through the .NET API.
$hkcu = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Fillyfoal', $true)
$hkcu.SetValue('None', [byte[]](9, 8, 7), [Microsoft.Win32.RegistryValueKind]::None)
$hkcu.Close()
# Many subkeys force the different subkey index lists (lh, and ri over several lh/li).
$many = Join-Path $keyPath 'Many'
New-Item -Path $many | Out-Null
for ($i = 0; $i -lt 2100; $i++) { New-Item -Path (Join-Path $many ('sub{0:D4}' -f $i)) | Out-Null }
New-Item -Path (Join-Path $keyPath 'Nested\Deeper\Deepest') -Force | Out-Null
Set-ItemProperty -Path (Join-Path $keyPath 'Nested\Deeper\Deepest') -Name 'Leaf' -Value 42
# Ownership and group: Administrators, not the user's SID.
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$keys = @(Get-Item $keyPath) + @(Get-ChildItem $keyPath -Recurse)
foreach ($k in $keys) {
    $acl = Get-Acl -Path $k.PSPath
    $acl.SetOwner($admins)
    $acl.SetGroup($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
    foreach ($sid in @($admins, $system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($sid, 'FullControl', 'ContainerInherit', 'None', 'Allow')))
    }
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($everyone, 'ReadKey', 'ContainerInherit', 'None', 'Allow')))
    Set-Acl -Path $k.PSPath -AclObject $acl
}
[FillyNative]::EnablePrivilege('SeBackupPrivilege')
foreach ($pair in @(@('fillyfoal-latest.hiv', 2), @('fillyfoal-standard.hiv', 1))) {
    $file = Join-Path $OutDir $pair[0]
    if (Test-Path $file) { Remove-Item $file -Force }
    [FillyNative]::SaveKey('Software\Fillyfoal', $file, [uint32]$pair[1])
    $outputs.Add($file)
}
Remove-Item $keyPath -Recurse -Force

# --- 3. ESE database ----------------------------------------------------------
Write-Host 'ESE database...'
$eseDir = Join-Path $OutDir 'ese-work'
if (Test-Path $eseDir) { Remove-Item $eseDir -Recurse -Force }
New-Item -ItemType Directory -Path $eseDir | Out-Null
$edb = Join-Path $eseDir 'fillyfoal.edb'
[FillyNative]::MakeEse($eseDir, $edb)
Copy-Item $edb (Join-Path $OutDir 'fillyfoal.edb') -Force
Remove-Item $eseDir -Recurse -Force
$outputs.Add((Join-Path $OutDir 'fillyfoal.edb'))

# --- 4. Minidumps -------------------------------------------------------------
Write-Host 'Minidumps...'
$ping = Start-Process -FilePath "$env:SystemRoot\System32\PING.EXE" -ArgumentList '-n 30 127.0.0.1' `
    -WindowStyle Hidden -WorkingDirectory $OutDir -PassThru
Start-Sleep -Seconds 2
try {
    # MiniDumpNormal; then + UnloadedModules (0x20), FullMemoryInfo (0x800), ThreadInfo (0x1000).
    foreach ($pair in @(@('ping-normal.dmp', 0), @('ping-info.dmp', 0x1820))) {
        $file = Join-Path $OutDir $pair[0]
        [FillyNative]::Dump($ping, $file, [uint32]$pair[1])
        $outputs.Add($file)
    }
} finally {
    Stop-Process -Id $ping.Id -Force -ErrorAction SilentlyContinue
}

# --- 5. PST (optional, needs Outlook) -------------------------------------------
if (-not $SkipPst) {
    try {
        $outlook = New-Object -ComObject Outlook.Application
        Write-Host 'PST via Outlook...'
        $pst = Join-Path $OutDir 'fillyfoal.pst'
        if (Test-Path $pst) { Remove-Item $pst -Force }
        $ns = $outlook.GetNamespace('MAPI')
        # The Outlook profile's names and addresses must not end up in the PST.
        try { $script:extraWords += $ns.CurrentUser.Name } catch { }
        foreach ($a in @($ns.Accounts)) {
            try { $script:extraWords += @($a.SmtpAddress, $a.DisplayName, $a.UserName) } catch { }
        }
        $ns.AddStoreEx($pst, 2)   # olStoreUnicode
        $store = $ns.Stores | Where-Object { $_.FilePath -eq $pst }
        $root = $store.GetRootFolder()
        $root.Name = 'fillyfoal'
        $folder = $root.Folders.Add('Fixtures')
        for ($i = 0; $i -lt 3; $i++) {
            $m = $outlook.CreateItem(0)
            $m.Subject = "fillyfoal fixture message $i"
            $m.Body = "Body of message $i.`r`nSecond line."
            $m.To = 'someone@example.com'
            $m.Importance = $i
            $m.Save()
            [void]$m.Move($folder)
        }
        $ns.RemoveStore($root)
        $outputs.Add($pst)
    } catch {
        Write-Host "No PST: $($_.Exception.Message)"
    }
}

# --- Privacy scan ----------------------------------------------------------------
Write-Host 'Privacy scan...'
$needles = New-Object System.Collections.Generic.List[byte[]]
$words = @($env:USERNAME, $env:USERDOMAIN)
try { $words += (Get-LocalUser -Name $env:USERNAME -ErrorAction Stop).FullName } catch { }
try { $words += ([ADSI]"WinNT://$env:COMPUTERNAME/$env:USERNAME,user").FullName } catch { }
$words += $script:extraWords
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$words += $sid.Value
$words += ($sid.AccountDomainSid.Value)
foreach ($w in $words) {
    if ($w -and $w.Length -ge 3 -and $w -ne 'FILLYFOAL') {
        $needles.Add([Text.Encoding]::ASCII.GetBytes($w.ToLowerInvariant()))
        $needles.Add([Text.Encoding]::Unicode.GetBytes($w.ToLowerInvariant()))
    }
}
foreach ($s in @($sid, $sid.AccountDomainSid)) {
    $b = New-Object byte[] $s.BinaryLength
    $s.GetBinaryForm($b, 0)
    $needles.Add($b)
}

$failed = $false
foreach ($f in $outputs) {
    $bytes = [IO.File]::ReadAllBytes($f)
    # Case-insensitive for text: compare against a lower-cased copy (ASCII letters only).
    $lower = [byte[]]($bytes.Clone())
    for ($i = 0; $i -lt $lower.Length; $i++) { if ($lower[$i] -ge 65 -and $lower[$i] -le 90) { $lower[$i] += 32 } }
    $hit = $false
    foreach ($n in $needles) { if ([FillyNative]::Contains($lower, $n) -or [FillyNative]::Contains($bytes, $n)) { $hit = $true; break } }
    if ($hit) {
        Write-Warning "IDENTIFIER FOUND in $(Split-Path $f -Leaf): deleting it"
        Remove-Item $f -Force
        $failed = $true
    } else {
        Write-Host ("ok  {0,-26} {1,10:N0} bytes" -f (Split-Path $f -Leaf), (Get-Item $f).Length)
    }
}
if ($failed) { Write-Warning 'Some outputs contained identifiers and were deleted; see above.' }
Write-Host "Done: $OutDir"
