"""Reads the images gen.py wrote back with pyaff4 and compares them with the
source volume (snappy.aff4 leaves 16 KiB-32 KiB unmapped: zeros).

usage: python check.py <outdir>
"""
import os
import sys

from pyaff4 import container, rdfvalue

out = sys.argv[1]
src = open(os.path.join(out, "src.img"), "rb").read()
holed = src[:16384] + bytes(16384) + src[32768:]

for name, want in (("physical.aff4", src), ("snappy.aff4", holed)):
    urn = rdfvalue.URN.FromFileName(os.path.join(out, name))
    volume = container.Container.openURNtoContainer(urn)
    stream = volume.image.dataStream
    stream.SeekRead(0)
    got = stream.Read(len(want))
    assert got == want, name
    print(name, "ok", len(got))

urn = rdfvalue.URN.FromFileName(os.path.join(out, "logical.aff4"))
volume = container.Container.openURNtoContainer(urn)
for image in volume.images():
    s = volume.resolver.AFF4FactoryOpen(image.urn)
    print("logical", image.name(), len(s.Read(s.Size())))
