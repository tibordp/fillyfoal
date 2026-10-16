"""Zero the blocks of a TempleOS-installed disk's RedSea partitions that
nothing on the disk refers to any more.

    python3 scrub_unreachable.py disk.img

For each MBR partition holding a RedSea volume (boot sector signature 0x88
at offset 3), walks every directory from the root, following deleted
entries as well as live ones (a deleted directory's blocks are listed when
they still hold a directory), and zeroes each block that the allocation
bitmap marks free and that no entry, live or deleted, covers. What is left
is what a reader of the volume can reach; what is zeroed is the stale
content of files whose directory entries were overwritten (the Kernel and
Compiler sources that BootHDIns compiled, deleted afterwards, whose entries
the root's later entries reused). Prints the blocks it zeroed.
"""
import struct
import sys

BLK = 512


def main():
    path = sys.argv[1]
    disk = bytearray(open(path, 'rb').read())
    total = 0
    for i in range(4):
        e = 0x1BE + 16 * i
        start = struct.unpack_from('<I', disk, e + 8)[0]
        if not start:
            continue
        boot = start * BLK
        if disk[boot + 3] != 0x88:
            continue
        drv_offset, sects, root, bitmap_sects = struct.unpack_from('<qqqq', disk, boot + 8)
        assert drv_offset == start
        data_area = drv_offset + bitmap_sects
        bitmap = disk[boot + BLK:boot + BLK + bitmap_sects * BLK]
        seen = set()
        reached = set()

        def cover(clus, size):
            for b in range(clus, clus + (size + BLK - 1) // BLK):
                reached.add(b)

        def walk(clus):
            if clus in seen or not (data_area <= clus < drv_offset + sects):
                return
            seen.add(clus)
            at = clus * BLK
            own_size = struct.unpack_from('<q', disk, at + 48)[0]
            own_attr, = struct.unpack_from('<H', disk, at)
            if own_size < 128 or own_size % BLK or not own_attr & 0x10:
                return
            cover(clus, own_size)
            for off in range(2 * 64, own_size, 64):
                ent = disk[at + off:at + off + 64]
                if not ent[2]:
                    break
                attr, = struct.unpack_from('<H', ent, 0)
                eclus, esize = struct.unpack_from('<qq', ent, 40)
                if attr & 0x10:
                    walk(eclus)
                elif esize > 0 and data_area <= eclus:
                    cover(eclus, esize)

        walk(root)
        zeroed = []
        for k in range(sects - bitmap_sects):
            blk = data_area + k
            used = bitmap[k // 8] >> (k % 8) & 1
            if used or blk in reached:
                continue
            at = blk * BLK
            if any(disk[at:at + BLK]):
                disk[at:at + BLK] = bytes(BLK)
                zeroed.append(blk)
        total += len(zeroed)
        print(f'partition {i + 1}: zeroed {len(zeroed)} unreachable free blocks')
    open(path, 'wb').write(disk)
    print(f'{total} blocks zeroed')


main()
