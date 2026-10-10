"""Generates the words8.* checkpoint test vectors with the real encoders.

    mkdir out
    uv run --with zstandard --with lz4 --with brotli --with python-snappy \
        python -I words8.py words.txt out
    compression_tool -encode -a lzfse -i out/corpus.bin -o out/corpus.lzfse  # macOS

then: multi.zst -> words8.zst, multi.lz4 -> words8.lz4, block.lz4 ->
words8.lz4-block, corpus.br -> words8.br, corpus.sz -> words8.sz,
words.snappy -> words8.snappy, corpus.lzfse -> words8.lzfse.
"""
import sys, os, random, struct
words = open(sys.argv[1], 'rb').read()
out = sys.argv[2]
# Corpus: the first 40 KB of words.txt eight times, each copy with a few byte edits so copies
# are near (not exact) repeats 40 KB apart.
rnd = random.Random(1)
def variant(i):
    b = bytearray(words[:40000])
    for _ in range(40):
        p = rnd.randrange(len(b)); b[p] = rnd.choice(b'abcdefghijklmnopqrstuvwxyz ')
    return bytes(b)
data = b''.join(variant(i) for i in range(8))
noise = bytes(rnd.randrange(256) for _ in range(8192))
open(os.path.join(out, 'corpus.bin'), 'wb').write(data)

import zstandard as zstd
p1 = zstd.ZstdCompressionParameters.from_level(3, window_log=17, write_checksum=True, write_content_size=True)
f1 = zstd.ZstdCompressor(compression_params=p1).compress(data)
skip = struct.pack('<II', 0x184D2A5A, 5) + b'hello'
f2 = zstd.ZstdCompressor(level=1, write_checksum=False).compress(words[:1000] + noise)
p3 = zstd.ZstdCompressionParameters.from_level(19, window_log=12, write_checksum=True, write_content_size=False)
c3 = zstd.ZstdCompressor(compression_params=p3).compressobj()
f3 = c3.compress(words[:30000]) + c3.flush()
open(os.path.join(out, 'multi.zst'), 'wb').write(f1 + skip + f2 + f3)
open(os.path.join(out, 'multi.zst.expect'), 'wb').write(data + words[:1000] + noise + words[:30000])

import lz4.frame, lz4.block
a = lz4.frame.compress(data, block_size=lz4.frame.BLOCKSIZE_MAX64KB, block_linked=True, content_checksum=True, compression_level=12)
b = lz4.frame.compress(words[:40000] + noise, block_size=lz4.frame.BLOCKSIZE_MAX64KB, block_linked=False, block_checksum=True, compression_level=12)
open(os.path.join(out, 'multi.lz4'), 'wb').write(a + b)
open(os.path.join(out, 'multi.lz4.expect'), 'wb').write(data + words[:40000] + noise)
open(os.path.join(out, 'block.lz4'), 'wb').write(lz4.block.compress(data[:200000], store_size=False, mode='high_compression', compression=12))

import brotli
open(os.path.join(out, 'corpus.br'), 'wb').write(brotli.compress(data, quality=9, lgwin=16))

import snappy
open(os.path.join(out, 'corpus.sz'), 'wb').write(snappy.StreamCompressor().add_chunk(data[:100000] + noise[:2048]))
open(os.path.join(out, 'words.snappy'), 'wb').write(snappy.compress(data[:50000]))
