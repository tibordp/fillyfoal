"""Writes external/gguf/quant.gguf with gguf-py (llama.cpp's writer): small
tensors in each type gguf-py can quantize itself (F32, F16, BF16, Q4_0,
Q4_1, Q5_0, Q5_1, Q8_0, TQ1_0, TQ2_0) plus an I8 tensor, each two rows of
256 values, so every tensor's byte size follows from its type's block size
and shape.

    uv run --with gguf==0.17.1 --with numpy python3 -I tests/data/gguf/quant.py OUT
"""
import sys

import numpy as np
from gguf import GGMLQuantizationType as T, GGUFWriter
from gguf.quants import quantize

w = GGUFWriter(sys.argv[1], 'llama')
w.add_name('fillyfoal quant test')
values = np.linspace(-1, 1, 512, dtype=np.float32).reshape(2, 256)
for t in (T.F32, T.F16, T.BF16, T.Q4_0, T.Q4_1, T.Q5_0, T.Q5_1, T.Q8_0,
          T.TQ1_0, T.TQ2_0):
    data = quantize(values, t)
    w.add_tensor(f'{t.name.lower()}.weight', data, raw_dtype=t)
w.add_tensor('i8.weight', np.arange(-128, 128, dtype=np.int8).reshape(1, 256))
w.write_header_to_file()
w.write_kv_data_to_file()
w.write_tensors_to_file()
w.close()
