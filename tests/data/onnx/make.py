"""Writes external/onnx/{minimal,named}.onnx with the onnx package's
helpers (checked with onnx.checker): one without producer fields (the
graph follows ir_version directly) and one with producer, domain, model
version, doc string and metadata before the graph.

    uv run --with onnx==1.19.1 python3 -I tests/data/onnx/make.py OUTDIR
"""
import os
import sys

import onnx
from onnx import TensorProto, helper

out = sys.argv[1]
x = helper.make_tensor_value_info('X', TensorProto.FLOAT, [1, 4])
y = helper.make_tensor_value_info('Y', TensorProto.FLOAT, [1, 4])
w = helper.make_tensor('W', TensorProto.FLOAT, [1, 4], [0.5, 1.0, 1.5, 2.0])
nodes = [
    helper.make_node('Mul', ['X', 'W'], ['XW'], name='mul0'),
    helper.make_node('Relu', ['XW'], ['Y'], name='relu0'),
]
graph = helper.make_graph(nodes, 'fillyfoal_graph', [x], [y], [w])

minimal = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 13)])
minimal.ir_version = 7
onnx.checker.check_model(minimal)
onnx.save(minimal, os.path.join(out, 'minimal.onnx'))

named = helper.make_model(
    graph,
    producer_name='fillyfoal',
    producer_version='1.0',
    domain='org.example',
    model_version=3,
    doc_string='A two-node test model.',
    opset_imports=[helper.make_opsetid('', 17), helper.make_opsetid('ai.onnx.ml', 3)],
)
named.ir_version = 8
helper.set_model_props(named, {'license': 'CC0-1.0'})
onnx.checker.check_model(named)
onnx.save(named, os.path.join(out, 'named.onnx'))
print(onnx.__version__)
