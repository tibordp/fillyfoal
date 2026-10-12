@echo off
rem fillyfoal pe/ fixtures, native ARM64 / ARM64EC / ARM64X variants.
rem Toolchain: VS Community 2026 (v18), MSVC 14.51, vcvarsall arm64 (Build Tools 2026 lacks the arm64 CRT libs here).
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" arm64 || exit /b 1
cd /d C:\fillyfoal\src || exit /b 1
copy /y C:\fillyfoal\winfix\scripts\pe\fixture_hello.c . >nul
copy /y C:\fillyfoal\winfix\scripts\pe\fixture_lib.c   . >nul
copy /y C:\fillyfoal\winfix\scripts\pe\fixture_lib.def . >nul
cl 2>&1 | findstr /i "version"
link 2>&1 | findstr /i "version"

rem 1a. native ARM64 /Zi + /DEBUG:FULL
cl /nologo /c /Zi /O1 /MD /Fofixture_hello_a64.obj /Fdfixture_hello_a64_cc.pdb fixture_hello.c || exit /b 1
link /nologo /DEBUG:FULL /INCREMENTAL:NO /OUT:fixture_hello_arm64.exe /PDB:fixture_hello_arm64.pdb fixture_hello_a64.obj || exit /b 1

rem 4a. ARM64EC exe
cl /nologo /c /arm64EC /Zi /O1 /MD /Fofixture_hello_ec.obj /Fdfixture_hello_ec_cc.pdb fixture_hello.c || exit /b 1
link /nologo /MACHINE:ARM64EC /DEBUG:FULL /INCREMENTAL:NO /OUT:fixture_hello_arm64ec.exe /PDB:fixture_hello_arm64ec.pdb fixture_hello_ec.obj || exit /b 1

rem 4b. ARM64X DLL from an arm64 obj + an arm64ec obj (same exports in both halves)
cl /nologo /c /Zi /O1 /MD /Fofixture_lib_a64.obj /Fdfixture_lib_a64_cc.pdb fixture_lib.c || exit /b 1
cl /nologo /c /arm64EC /Zi /O1 /MD /Fofixture_lib_ec.obj /Fdfixture_lib_ec_cc.pdb fixture_lib.c || exit /b 1
link /nologo /DLL /MACHINE:ARM64X /DEBUG:FULL /INCREMENTAL:NO /DEF:fixture_lib.def /DEFARM64NATIVE:fixture_lib.def /OUT:fixture_lib_arm64x.dll /PDB:fixture_lib_arm64x.pdb fixture_lib_a64.obj fixture_lib_ec.obj version.lib delayimp.lib /DELAYLOAD:version.dll || exit /b 1
endlocal
