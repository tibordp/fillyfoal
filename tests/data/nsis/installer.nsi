; A small installer for the NSIS fixtures (see make.sh): two files in two
; directories, a registry value, a shortcut and an uninstaller.
Unicode ${UNICODE}
SetCompressor ${COMPRESSOR}
Name "fillyfoal"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES\fillyfoal"
RequestExecutionLevel user
SetDateSave on

Page directory
Page instfiles

Section "Main"
  SetOutPath "$INSTDIR"
  File "payload/readme.txt"
  SetOutPath "$INSTDIR\docs"
  File "payload/docs/config.ini"
  WriteRegStr HKCU "Software\fillyfoal" "InstallDir" "$INSTDIR"
  CreateShortCut "$SMPROGRAMS\fillyfoal.lnk" "$INSTDIR\readme.txt"
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\docs\config.ini"
  Delete "$INSTDIR\readme.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR\docs"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\fillyfoal"
SectionEnd
