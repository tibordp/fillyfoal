"""Run inside the container by make.sh: SST files from rocksdict's
SstFileWriter with different table options.

- default-v6.sst: default options (format_version 6, XXH3 checksums,
  Snappy), 1 KiB blocks.
- v5-crc32c.sst: format_version 5, CRC-32C, no compression, 512-byte
  blocks, index restart interval 4 (delta-encoded index values).
- v6-xxhash.sst: format_version 6, xxHash32, no compression.
- v4-xxhash64.sst: format_version 4, xxHash64, no compression.
"""

import os
import sys

from rocksdict import (
    BlockBasedOptions,
    ChecksumType,
    DBCompressionType,
    Options,
    SstFileWriter,
)

out = sys.argv[1]
ROWS = [(b"key-%04d" % i, b"value %d " % i + b"fillyfoal " * (i % 7)) for i in range(150)]


def write(name, block_size, version=None, checksum=None, plain=False, restart=None):
    t = BlockBasedOptions()
    t.set_block_size(block_size)
    if version is not None:
        t.set_format_version(version)
    if checksum is not None:
        t.set_checksum_type(checksum)
    if restart is not None:
        t.set_index_block_restart_interval(restart)
    o = Options(raw_mode=True)
    o.set_block_based_table_factory(t)
    if plain:
        o.set_compression_type(DBCompressionType.none())
    path = os.path.join(out, name)
    if os.path.exists(path):
        os.remove(path)
    w = SstFileWriter(options=o)
    w.open(path)
    for k, v in ROWS:
        w[k] = v
    w.finish()


write("default-v6.sst", 1024)
write("v5-crc32c.sst", 512, 5, ChecksumType.crc32c(), plain=True, restart=4)
write("v6-xxhash.sst", 1024, 6, ChecksumType.xxhash(), plain=True)
write("v4-xxhash64.sst", 1024, 4, ChecksumType.xxhash64(), plain=True)
