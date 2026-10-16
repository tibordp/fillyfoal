"""Have TempleOS install itself onto a blank hard disk, the way its
installer does, and add a small tree with grown, nested and deleted
entries.

TempleOS V5.03's live CD booted in QEMU (TCG) with a blank 16 MiB IDE disk
(32130 blocks: two of DskPrt's 63*255-block units), driven over QMP:

    truncate -s 16450560 $OUT_DIR/disk.img
    docker run -d --rm --name templeos --hostname fillyfoal \\
        -p 127.0.0.1:4444:4444 -v $ISO_DIR:/iso:ro -v $OUT_DIR:/out \\
        <image with qemu-system-x86> \\
        qemu-system-x86_64 -accel tcg -m 512 -smp 1 \\
        -drive file=/out/disk.img,format=raw,if=ide,index=0 \\
        -cdrom /iso/TempleOS.ISO -boot d -display none \\
        -qmp tcp:0.0.0.0:4444,server,wait=off -rtc base=2026-01-01T00:00:00
    python3 qemu_install.py
    python3 scrub_unreachable.py $OUT_DIR/disk.img
    zstd -19 $OUT_DIR/disk.img -o templeos-installed.img.raw.zst

The steps are the installer's (`Misc/OSInstall.HC`), with a small tree in
place of the whole CD: `DskPrt(,0.5,0.5)` as `VMPrtDsk` does (two primary
partitions, C and D, formatted FAT32), C reformatted as RedSea as
`RegularInstallWiz`'s option 2 does (`Fmt`, not quick, so the FAT32 tables
are zeroed), the Kernel and Compiler sources copied from the CD so that
`BootHDIns('C')` can compile them (it answers the kernel configuration as
`VMInstallDrv` does: RAM drive B of 0x20000 blocks, C on the first IDE
port, the CD on the second), `BootMHDIns('C')` for the master boot record,
then the sources deleted again. Then a tree five directories deep, twelve
compressed files in one directory and five in the root (both directories
grow past one block, and the root moves), and some deletions: two files,
one root file and a directory with a subdirectory and a file in it.
"""
import json
import socket
import time

KEYS = {
    ' ': 'spc', '\n': 'ret', '.': 'dot', ',': 'comma', '/': 'slash',
    ';': 'semicolon', '-': 'minus', '=': 'equal', "'": 'apostrophe',
    '[': 'bracket_left', ']': 'bracket_right',
}
SHIFTED = {
    '"': 'apostrophe', '(': '9', ')': '0', ':': 'semicolon', '_': 'minus',
    '+': 'equal', '%': '5', '*': '8', '<': 'comma', '>': 'dot',
    '{': 'bracket_left', '}': 'bracket_right',
}

# (keys to type, seconds to wait afterwards)
STEPS = [
    ('', 35),  # boot to the first question
    ('n', 2),  # Install onto hard drive?
    ('n', 3),  # Take Tour?
    ('DskPrt(,0.5,0.5);\n', 4),
    ('C', 2),  # Drive letter
    ('\n', 2),  # Partition number: all
    ('p', 8),  # probe
    ('1\n', 4),  # the hard drive
    ('y', 12),  # Reformat whole drive?
    ("Fmt('C',FALSE,FALSE,FSt_REDSEA);DrvRep;\n", 12),
    ('CopyTree("T:/Kernel","C:/Kernel");CopyTree("T:/Compiler","C:/Compiler");\n', 25),
    ("BootHDIns('C');\n", 20),  # compiles the compiler, then asks
    ('\n', 2),  # boot drive: current
    ('B', 2), ('\n0x20000\n', 2),  # RAM drive B
    ('C', 2), ('\n', 2), ('p', 6), ('1\n', 2),  # C: first IDE port
    ('T', 2), ('p', 6), ('2\n', 2),  # T: the CD
    ('\n', 2), ('\n', 2), ('\n', 40),  # end of drives, disk cache, options
    ("BootMHDIns('C');\n", 10),
    ('DelTree("C:/Kernel");DelTree("C:/Compiler");Dir("C:/");\n', 10),
    ('DirMk("C:/Home");DirMk("C:/Home/A");DirMk("C:/Home/A/B");'
     'DirMk("C:/Home/A/B/C");DirMk("C:/Home/A/B/C/D");'
     'FileWrite("C:/Home/A/B/C/D/Deep.TXT","Five levels down.\n",18);'
     'FileWrite("C:/Home/A/B/Mid.TXT","Two levels down.\n",17);\n', 6),
    ('I64 i;U8 *s;for(i=0;i<12;i++){s=MStrPrint("C:/Home/Note%02d.DD.Z",i);'
     'FileWrite(s,s,StrLen(s));Free(s);}'
     'for(i=0;i<5;i++){s=MStrPrint("C:/Root%d.HC",i);'
     'FileWrite(s,"U0 Main() {}",12);Free(s);}Dir("C:/");Dir("C:/Home");\n', 8),
    ('Del("C:/Home/Note03.DD.Z");Del("C:/Home/Note07.DD.Z");Del("C:/Root2.HC");'
     'DelTree("C:/Home/A/B/C");Dir("C:/Home/A/B");\n', 8),
]


def call(f, name, **args):
    f.write(json.dumps({'execute': name, 'arguments': args}) + '\n')
    f.flush()
    while True:
        r = json.loads(f.readline())
        if 'return' in r or 'error' in r:
            return r


def typ(f, text):
    for ch in text:
        if ch in SHIFTED:
            keys = ['shift', SHIFTED[ch]]
        elif ch.isupper():
            keys = ['shift', ch.lower()]
        else:
            keys = [KEYS.get(ch, ch)]
        call(f, 'send-key', keys=[{'type': 'qcode', 'data': k} for k in keys])
        time.sleep(0.08)


def main():
    s = socket.create_connection(('127.0.0.1', 4444))
    f = s.makefile('rw')
    f.readline()
    call(f, 'qmp_capabilities')
    for keys, wait in STEPS:
        typ(f, keys)
        time.sleep(wait)
    call(f, 'quit')


main()
