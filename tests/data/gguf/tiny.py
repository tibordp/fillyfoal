"""Writes synthetic/gguf/tiny.gguf by hand from the GGUF v3 layout
(llama.cpp `docs/gguf.md`): twelve metadata keys of most value types
(strings, u32, f32, bool, i64, arrays of strings and of f32) and three
tensors: F16 8x4, F32 8 and Q8_0 32x2 (two 34-byte blocks per row: an f16
scale and 32 int8 quants), data aligned to 32 bytes.

    python3 -I tests/data/gguf/tiny.py OUT

Checked with gguf-py's reader:
    uv run --with gguf==0.17.1 --with numpy python3 -I -c \
        "import gguf,sys; r=gguf.GGUFReader(sys.argv[1]); print([(t.name, t.tensor_type.name, list(t.shape), t.n_bytes) for t in r.tensors])" OUT
"""
import struct
import sys

ALIGN = 32


def s(text):
    b = text.encode()
    return struct.pack('<Q', len(b)) + b


def kv(key, vtype, payload):
    return s(key) + struct.pack('<I', vtype) + payload


U32, F32, BOOL, STR, ARR, I64 = 4, 6, 7, 8, 9, 11
kvs = [
    kv('general.architecture', STR, s('llama')),
    kv('general.name', STR, s('fillyfoal-tiny')),
    kv('general.alignment', U32, struct.pack('<I', ALIGN)),
    kv('llama.context_length', U32, struct.pack('<I', 128)),
    kv('llama.embedding_length', U32, struct.pack('<I', 8)),
    kv('llama.rope.freq_base', F32, struct.pack('<f', 10000.0)),
    kv('tokenizer.ggml.model', STR, s('llama')),
    kv('tokenizer.ggml.tokens', ARR,
       struct.pack('<IQ', STR, 4) + b''.join(s(t) for t in ('<unk>', '<s>', '</s>', 'hi'))),
    kv('tokenizer.ggml.scores', ARR,
       struct.pack('<IQ', F32, 4) + struct.pack('<4f', 0.0, 0.0, 0.0, -1.5)),
    kv('tokenizer.ggml.add_bos_token', BOOL, b'\x01'),
    kv('general.file_type', U32, struct.pack('<I', 1)),
    kv('test.signed', I64, struct.pack('<q', -42)),
]

# Tensor data, each piece padded to the alignment.
F16, F32T, Q8_0 = 1, 0, 8
embd = b''.join(struct.pack('<e', (i - 16) / 16) for i in range(32))  # 8x4 f16
norm = struct.pack('<8f', *[1.0] * 8)  # 8 f32
q8 = b''
for row in range(2):
    q8 += struct.pack('<e', 0.5 * (row + 1))
    q8 += bytes((3 * i + row) & 0x7f for i in range(32))  # 32 int8 quants
tensors = [
    ('token_embd.weight', [8, 4], F16, embd),
    ('output_norm.weight', [8], F32T, norm),
    ('blk.0.attn_q.weight', [32, 2], Q8_0, q8),
]


def pad(n):
    return (-n) % ALIGN


infos = b''
data = b''
for name, dims, ttype, payload in tensors:
    infos += s(name) + struct.pack('<I', len(dims))
    infos += b''.join(struct.pack('<Q', d) for d in dims)
    infos += struct.pack('<IQ', ttype, len(data))
    data += payload + b'\0' * pad(len(payload))

head = b'GGUF' + struct.pack('<IQQ', 3, len(tensors), len(kvs)) + b''.join(kvs) + infos
out = head + b'\0' * pad(len(head)) + data
with open(sys.argv[1], 'wb') as f:
    f.write(out)
