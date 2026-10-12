"""Have TempleOS itself write a small RedSea ISO, and carve it out of the
guest's memory.

TempleOS V5.03's live CD booted in QEMU (TCG), driven over QMP:

    docker run -d --name templeos -p 127.0.0.1:4444:4444 \\
        -v $ISO_DIR:/iso:ro -v $OUT_DIR:/out <image with qemu-system-x86> \\
        qemu-system-x86_64 -accel tcg -m 512 -smp 1 \\
        -cdrom /iso/TempleOS.ISO -boot d -display none \\
        -qmp tcp:0.0.0.0:4444,server,wait=off -rtc base=2026-01-01T00:00:00
    python3 qemu_redseaiso.py /out/mem.bin $OUT_DIR/mem.bin templeos.iso

answers the live CD's two questions with "n", copies two files from the CD
(T:) into a directory tree on the RAM drive (B:), runs
`RedSeaISO("B:/Out","B:/Src")` (Adam/Opt/Boot/DskISORedSea.HC), which
writes B:/Out.ISO.C, then saves the guest's memory (`pmemsave`; the first
argument is the path inside the container, the second the same file on the
host) and carves the ISO from the RAM drive: its RedSea boot sector
(drv_offset 88) with the primary volume descriptor 0x3000 bytes before
it, as long as the descriptor's volume space size says.
"""
import json
import re
import socket
import struct
import sys
import time

KEYS = {
    ' ': 'spc', '\n': 'ret', '.': 'dot', ',': 'comma', '/': 'slash',
    ';': 'semicolon', '-': 'minus',
}
SHIFTED = {'"': 'apostrophe', '(': '9', ')': '0', ':': 'semicolon', '_': 'minus'}

COMMANDS = [
    'n',  # Install onto hard drive?
    'n',  # Take Tour?
    'DirMk("B:/Src");DirMk("B:/Src/Doc");'
    'Copy("T:/Demo/DateTime.HC.Z","B:/Src");'
    'Copy("T:/Doc/FileLowLevel.DD.Z","B:/Src/Doc");\n',
    'RedSeaISO("B:/Out","B:/Src");\n',
]


def qmp():
    s = socket.create_connection(('127.0.0.1', 4444))
    f = s.makefile('rw')
    f.readline()
    call(f, 'qmp_capabilities')
    return f


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
    guest_mem, host_mem, out = sys.argv[1:4]
    f = qmp()
    time.sleep(30)  # boot to the first question
    for c in COMMANDS:
        typ(f, c)
        time.sleep(5)
    call(f, 'human-monitor-command',
         **{'command-line': f'pmemsave 0 0x20000000 "{guest_mem}"'})
    mem = open(host_mem, 'rb').read()
    for m in re.finditer(re.escape(bytes([0x88, 0, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0])), mem):
        boot = m.start() - 3
        pvd = boot - 0x3000
        if mem[boot + 510:boot + 512] != b'\x55\xaa' or mem[pvd:pvd + 7] != b'\x01CD001\x01':
            continue
        sectors = struct.unpack_from('<I', mem, pvd + 80)[0]
        start = boot - 0xB000
        with open(out, 'wb') as o:
            o.write(mem[start:start + sectors * 2048])
        print(f'{sectors * 2048} bytes from guest address {start:#x}')
        return
    raise SystemExit('no RedSea ISO in guest memory')


main()
