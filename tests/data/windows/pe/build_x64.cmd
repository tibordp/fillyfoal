@echo off
rem fillyfoal pe/ fixtures, x64 variants (cross-compiled on an ARM64 host).
rem Toolchain: VS Build Tools 2026 (v18), MSVC 14.51, vcvarsall arm64_amd64.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" arm64_amd64 || exit /b 1
cd /d C:\fillyfoal\src || exit /b 1
copy /y C:\fillyfoal\winfix\scripts\pe\fixture_hello.c . >nul
copy /y C:\fillyfoal\winfix\scripts\pe\fixture_lib.c   . >nul
copy /y C:\fillyfoal\winfix\scripts\pe\fixture_lib.def . >nul
copy /y C:\fillyfoal\winfix\scripts\pe\fixture_use.c   . >nul
cl 2>&1 | findstr /i "version"
link 2>&1 | findstr /i "version"

rem 1. /Zi + /DEBUG:FULL
cl /nologo /c /Zi /O1 /MD /Fofixture_hello_full.obj /Fdfixture_hello_full_cc.pdb fixture_hello.c || exit /b 1
link /nologo /DEBUG:FULL /INCREMENTAL:NO /OUT:fixture_hello_x64.exe /PDB:fixture_hello_x64.pdb fixture_hello_full.obj || exit /b 1

rem 2. /DEBUG:FASTLINK skipped: link 14.51 prints LNK4315 (FASTLINK no longer supported, falls back to FULL).

rem 5. DLL with exports (.def: named, NONAME ordinal, DATA, forwarder) + delay-load of version.dll
cl /nologo /c /Zi /O1 /MD /Fofixture_lib.obj /Fdfixture_lib_cc.pdb fixture_lib.c || exit /b 1
link /nologo /DLL /DEBUG:FULL /INCREMENTAL:NO /DEF:fixture_lib.def /OUT:fixture_lib.dll /PDB:fixture_lib.pdb fixture_lib.obj version.lib delayimp.lib /DELAYLOAD:version.dll || exit /b 1
cl /nologo /c /Zi /O1 /MD /Fofixture_use.obj /Fdfixture_use_cc.pdb fixture_use.c || exit /b 1
link /nologo /DEBUG:FULL /INCREMENTAL:NO /OUT:fixture_use.exe /PDB:fixture_use.pdb fixture_use.obj fixture_lib.lib || exit /b 1
endlocal


