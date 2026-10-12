@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" arm64 >nul 2>&1
cd /d C:\fillyfoal\winfix\out\pe
dumpbin /nologo /loadconfig fixture_hello_arm64ec.exe | findstr /i "CHPE hybrid Dynamic"
dumpbin /nologo /loadconfig fixture_lib_arm64x.dll | findstr /i "CHPE hybrid Dynamic ARM64X"
