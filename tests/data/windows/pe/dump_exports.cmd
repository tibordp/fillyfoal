@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" arm64 >nul 2>&1
cd /d C:\fillyfoal\winfix\out\pe
dumpbin /nologo /exports fixture_lib.dll
dumpbin /nologo /imports fixture_lib.dll | findstr /i "dll delay"
dumpbin /nologo /imports fixture_use.exe | findstr /i "fixture_lib Ordinal fillyfoal"
dumpbin /nologo /exports fixture_lib_arm64x.dll | findstr /i "ordinal fillyfoal number"
dumpbin /nologo /headers fixture_lib_arm64x.dll | findstr /i "CHPE ARM64X hybrid"
