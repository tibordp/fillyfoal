"""Writes the external Thrift fixtures with the Python `thrift` package,
calling the protocol API directly (no IDL, no generated code).

    uv run --with thrift==0.25.0 python make.py
"""

import os

from thrift.protocol.TBinaryProtocol import TBinaryProtocol
from thrift.protocol.TCompactProtocol import TCompactProtocol
from thrift.Thrift import TMessageType, TType
from thrift.transport.TTransport import TMemoryBuffer

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "external")


def field(p, name, ttype, fid, write):
    p.writeFieldBegin(name, ttype, fid)
    write()
    p.writeFieldEnd()


def point(p, x, y):
    p.writeStructBegin("Point")
    field(p, "x", TType.I32, 1, lambda: p.writeI32(x))
    field(p, "y", TType.I32, 2, lambda: p.writeI32(y))
    p.writeFieldStop()
    p.writeStructEnd()


def sample(p):
    p.writeStructBegin("Sample")
    field(p, "id", TType.I32, 1, lambda: p.writeI32(150))
    field(p, "name", TType.STRING, 2, lambda: p.writeString("fillyfoal"))
    field(p, "ratio", TType.DOUBLE, 3, lambda: p.writeDouble(0.25))
    field(p, "active", TType.BOOL, 4, lambda: p.writeBool(True))
    field(p, "level", TType.BYTE, 5, lambda: p.writeByte(-7))
    field(p, "short", TType.I16, 6, lambda: p.writeI16(-300))
    field(p, "big", TType.I64, 7, lambda: p.writeI64(-1234567890123))
    field(p, "blob", TType.STRING, 8, lambda: p.writeBinary(b"\x00\x01\xff"))

    def values():
        p.writeListBegin(TType.I32, 4)
        for v in (1, 2, 3, 300):
            p.writeI32(v)
        p.writeListEnd()

    field(p, "values", TType.LIST, 10, values)

    def names():
        p.writeSetBegin(TType.STRING, 2)
        p.writeString("a")
        p.writeString("b")
        p.writeSetEnd()

    field(p, "names", TType.SET, 11, names)

    def tags():
        p.writeMapBegin(TType.STRING, TType.I64, 2)
        p.writeString("alpha")
        p.writeI64(1)
        p.writeString("beta")
        p.writeI64(-2)
        p.writeMapEnd()

    field(p, "tags", TType.MAP, 12, tags)

    def shape():
        p.writeStructBegin("Shape")
        field(p, "kind", TType.I32, 1, lambda: p.writeI32(7))

        def points():
            p.writeListBegin(TType.STRUCT, 2)
            point(p, 1, -1)
            point(p, 100, 200)
            p.writeListEnd()

        field(p, "points", TType.LIST, 2, points)
        p.writeFieldStop()
        p.writeStructEnd()

    field(p, "shape", TType.STRUCT, 13, shape)

    def flags():
        p.writeListBegin(TType.BOOL, 3)
        for b in (True, False, True):
            p.writeBool(b)
        p.writeListEnd()

    field(p, "flags", TType.LIST, 14, flags)
    field(p, "off", TType.BOOL, 15, lambda: p.writeBool(False))

    def empty():
        p.writeMapBegin(TType.STRING, TType.I32, 0)
        p.writeMapEnd()

    field(p, "empty", TType.MAP, 16, empty)
    # A long jump in field ids (the compact protocol's long field header).
    field(p, "far", TType.STRING, 300, lambda: p.writeString("far away"))
    p.writeFieldStop()
    p.writeStructEnd()


def messages(p):
    p.writeMessageBegin("getUser", TMessageType.CALL, 42)
    p.writeStructBegin("getUser_args")
    field(p, "id", TType.I64, 1, lambda: p.writeI64(7))
    p.writeFieldStop()
    p.writeStructEnd()
    p.writeMessageEnd()
    p.writeMessageBegin("getUser", TMessageType.REPLY, 42)
    p.writeStructBegin("getUser_result")

    def success():
        p.writeStructBegin("User")
        field(p, "name", TType.STRING, 1, lambda: p.writeString("Ada"))
        p.writeFieldStop()
        p.writeStructEnd()

    field(p, "success", TType.STRUCT, 0, success)
    p.writeFieldStop()
    p.writeStructEnd()
    p.writeMessageEnd()


def long_list(p):
    p.writeStructBegin("Series")

    def samples():
        p.writeListBegin(TType.I32, 1200)
        for i in range(1200):
            p.writeI32((i * 37) % 1000 - 500)
        p.writeListEnd()

    field(p, "samples", TType.LIST, 1, samples)
    p.writeFieldStop()
    p.writeStructEnd()


for proto, name, ext in ((TBinaryProtocol, "thrift-binary", "tbin"), (TCompactProtocol, "thrift-compact", "tcompact")):
    for what, write in (("sample", sample), ("messages", messages), ("series", long_list)):
        buf = TMemoryBuffer()
        write(proto(buf))
        with open(os.path.join(OUT, name, f"{what}.{ext}"), "wb") as f:
            f.write(buf.getvalue())
