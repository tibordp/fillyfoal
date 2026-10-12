@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" arm64_amd64 >nul 2>&1
dumpbin /nologo /headers C:\fillyfoal\winfix\out\pe\fixture_hello_x64_fastlink.exe | findstr /i /c:"machine" /c:"cv " /c:"coffgrp" /c:"subsystem"
