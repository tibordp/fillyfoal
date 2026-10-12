@echo off
rem fillyfoal pe/: item 2, x64 /Zi + /DEBUG:FASTLINK, built with the VS 2022 (v143, MSVC 14.44) toolset
rem installed into Build Tools 2026 (scripts\pe\install_v143.ps1), cross-compiled on the ARM64 host.
rem Builds in C:\fillyfoal\src, moves outputs to winfix\out\pe, removes every src\fixture* file afterwards.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" arm64_amd64 -vcvars_ver=14.44 || exit /b 1
cd /d C:\fillyfoal\src || exit /b 1
copy /y C:\fillyfoal\winfix\scripts\pe\fixture_hello.c . >nul
cl 2>&1 | findstr /i "version"
link 2>&1 | findstr /i "version"

cl /nologo /c /Zi /O1 /MD /Fofixture_hello_fastlink.obj /Fdfixture_hello_fastlink_cc.pdb fixture_hello.c || goto :fail
link /nologo /DEBUG:FASTLINK /INCREMENTAL:NO /OUT:fixture_hello_x64_fastlink.exe /PDB:fixture_hello_x64_fastlink.pdb fixture_hello_fastlink.obj || goto :fail

set OUT=C:\fillyfoal\winfix\out\pe
if not exist %OUT%\fastlink-obj mkdir %OUT%\fastlink-obj
move /y fixture_hello_x64_fastlink.exe %OUT%\ >nul
move /y fixture_hello_x64_fastlink.pdb %OUT%\ >nul
rem The FASTLINK PDB references these by absolute path (C:\fillyfoal\src\...); the obj in turn
rem references the compiler PDB (/Zi type server) that holds the type records.
move /y fixture_hello_fastlink.obj    %OUT%\fastlink-obj\ >nul
move /y fixture_hello_fastlink_cc.pdb %OUT%\fastlink-obj\ >nul
del /q fixture_hello.c
endlocal
exit /b 0

:fail
del /q fixture_hello.c fixture_hello_fastlink.* fixture_hello_fastlink_cc.pdb fixture_hello_x64_fastlink.* 2>nul
exit /b 1
