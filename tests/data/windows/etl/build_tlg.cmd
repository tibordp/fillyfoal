@echo off
rem Builds fillyfoal_tlg.exe, ff_klog.exe, ff_comp.exe (arm64) into C:\fillyfoal\winfix\work\etl
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsarm64.bat" >nul
cd /d C:\fillyfoal\winfix\work\etl
cl /nologo /W4 /O2 /Brepro C:\fillyfoal\winfix\scripts\etl\fillyfoal_tlg.c /Fe:fillyfoal_tlg.exe /link /Brepro advapi32.lib
cl /nologo /W4 /O2 /Brepro C:\fillyfoal\winfix\scripts\etl\ff_klog.c /Fe:ff_klog.exe /link /Brepro advapi32.lib
cl /nologo /W4 /O2 /Brepro C:\fillyfoal\winfix\scripts\etl\ff_comp.c /Fe:ff_comp.exe /link /Brepro advapi32.lib
