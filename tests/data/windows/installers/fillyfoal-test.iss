; fillyfoal test - minimal Inno Setup 6 script (compiled by build.ps1 with each ISCC version)
#define MyAppName "fillyfoal test"

[Setup]
AppId={{3C9E2F4A-5B6D-4E7F-8A9B-0C1D2E3F4A5B}
AppName={#MyAppName}
AppVersion=1.0.0
AppVerName={#MyAppName} 1.0.0
AppPublisher=fillyfoal
AppCopyright=fillyfoal
VersionInfoVersion=1.0.0.0
VersionInfoCompany=fillyfoal
VersionInfoDescription={#MyAppName} setup
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
OutputBaseFilename=setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; keep the files small: no wizard bitmaps
WizardImageFile=
WizardSmallImageFile=

[Files]
Source: "readme.txt"; DestDir: "{app}"
Source: "data.txt"; DestDir: "{app}"

[Registry]
Root: HKCU; Subkey: "Software\fillyfoal test"; ValueType: string; ValueName: "Version"; ValueData: "1.0.0"; Flags: uninsdeletekey

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;

