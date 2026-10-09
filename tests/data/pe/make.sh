#!/bin/sh
# Builds the PE fixtures in tests/fixtures/external/pe with zig 0.15.2
# (clang 20 + lld-link + llvm-dlltool + resinator), without a C runtime.
# The build runs in a neutral directory so no local path ends up in the
# images (the CodeView record names the PDB by /pdbaltpath only).
#
#   sh tests/data/pe/make.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/pe}" && pwd)
B=/tmp/fixtures/pe
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/filly.c "$SRC"/filly.rc "$SRC"/*.def "$SRC"/resources.py "$B"
cd "$B"

uv run --with pillow==12.0.0 python3 resources.py .
zig rc /fo filly.res filly.rc

CFLAGS="-c -Os -fno-stack-protector -fno-builtin -fno-ident -mguard=cf"

# x86-64 DLL: exports (named, data, NONAME, forwarder), imports by name and
# ordinal, delay imports, TLS callbacks, CFG load config, .pdata, resources,
# CodeView + REPRO + EX_DLLCHARACTERISTICS debug entries.
zig cc -target x86_64-windows-gnu $CFLAGS filly.c -o x64.obj
for d in kernel32 fillyhelp fillydelay; do
    zig dlltool -m i386:x86-64 -d $d.def -l $d-x64.lib
done
zig lld-link /nologo /nodefaultlib /machine:x64 /dll /entry:filly_entry /def:filly.def \
    /out:filly64.dll x64.obj kernel32-x64.lib fillyhelp-x64.lib fillydelay-x64.lib filly.res \
    /delayload:fillydelay.dll /debug /pdb:filly64.pdb /pdbaltpath:filly64.pdb /Brepro \
    /guard:cf /cetcompat /release /dynamicbase /highentropyva /nxcompat /noimplib

# i386 console EXE: SafeSEH table, TLS, imports with stdcall decoration.
printf 'LIBRARY kernel32.dll\nEXPORTS\n  GetTickCount@0\n  Sleep@4\n  ExitProcess@4\n' > kernel32-x86.def
printf 'LIBRARY fillyhelp.dll\nEXPORTS\n  helper_named@4\n  helper_ord@4 @7 NONAME\n' > fillyhelp-x86.def
printf 'LIBRARY fillydelay.dll\nEXPORTS\n  delay_one@4\n  delay_two@4 @2 NONAME\n' > fillydelay-x86.def
zig cc -target x86-windows-gnu $(echo $CFLAGS | sed "s| -mguard=cf||") filly.c -o x86.obj
for d in kernel32 fillyhelp fillydelay; do
    zig dlltool -m i386 -k -d $d-x86.def -l $d-x86.lib
done
zig lld-link /nologo /nodefaultlib /machine:x86 /subsystem:console /entry:filly_main \
    /out:filly32.exe x86.obj kernel32-x86.lib fillyhelp-x86.lib fillydelay-x86.lib filly.res \
    /delayload:fillydelay.dll /safeseh /Brepro /release /dynamicbase /nxcompat /largeaddressaware

# ARM64 GUI EXE: ARM64 .pdata and unwind data.
zig cc -target aarch64-windows-gnu $CFLAGS filly.c -o arm64.obj
for d in kernel32 fillyhelp fillydelay; do
    zig dlltool -m arm64 -d $d.def -l $d-arm64.lib
done
zig lld-link /nologo /nodefaultlib /machine:arm64 /subsystem:windows /entry:filly_main \
    /out:fillyarm64.exe arm64.obj kernel32-arm64.lib fillyhelp-arm64.lib fillydelay-arm64.lib \
    /delayload:fillydelay.dll /Brepro /guard:cf

cp filly64.dll filly32.exe fillyarm64.exe "$OUT"/
ls -l "$OUT"/filly64.dll "$OUT"/filly32.exe "$OUT"/fillyarm64.exe
