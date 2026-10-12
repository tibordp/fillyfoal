@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" arm64 >nul
cd /d C:\fillyfoal\winfix\out\pe
for %%f in (*.exe *.dll) do (
  echo ===== %%f
  dumpbin /nologo /headers %%f | findstr /i /c:"machine" /c:"subsystem" /c:"cv " /c:"coffgrp" /c:"pogo" /c:"iltcg" /c:"repro" /c:"vc feature" /c:"Format:" /c:"characteristics" /c:"Certificates Directory" /c:"Load Config"
)
