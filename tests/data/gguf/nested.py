"""Writes external/gguf/nested.gguf with gguf-py (llama.cpp's writer): a
few ordinary keys, a nested array (arrays of arrays, as `add_array` packs
them: every inner array has its own element type and count) and two small
tensors after it, so the tensor list depends on skipping the nested array.

    uv run --with gguf==0.17.1 --with numpy python3 -I tests/data/gguf/nested.py OUT
"""
import sys

import numpy as np
from gguf import GGUFWriter

w = GGUFWriter(sys.argv[1], 'llama')
w.add_name('fillyfoal nested test')
w.add_uint32('test.answer', 42)
w.add_array('test.nested', [[1, 2], [3, 4, 5]])
w.add_array('test.deep', [[['a', 'b']], [['c']]])
w.add_array('test.after', ['still', 'here'])
w.add_tensor('weight', np.arange(8, dtype=np.float32).reshape(2, 4))
w.add_tensor('bias', np.zeros(4, dtype=np.float16))
w.write_header_to_file()
w.write_kv_data_to_file()
w.write_tensors_to_file()
w.close()
