"""Writes small AFF4 images with pyaff4 0.31.

physical.aff4: a disk image (aff4:Image with an aff4:Map over an
aff4:ImageStream of zlib chunks), like aff4imager writes.
snappy.aff4: the same with snappy chunks, 8 KiB chunks, 4 chunks per bevy
(so several bevies) and a map with a hole.
logical.aff4: a logical container (two files: a ZIP segment and an
ImageStream).

usage: python gen.py <source image> <file> <outdir>
"""
import io
import os
import sys

from pyaff4 import aff4_file, aff4_image, aff4_map, container, data_store
from pyaff4 import lexicon, rdfvalue, zip as aff4zip
from pyaff4.container import Version

src, member, out = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(src, "rb").read()


def physical(path, compression, chunk_size, per_bevy, hole):
    urn = rdfvalue.URN.FromFileName(path)
    with data_store.MemoryDataStore() as resolver:
        resolver.Set(lexicon.transient_graph, urn,
                     lexicon.AFF4_STREAM_WRITE_MODE,
                     rdfvalue.XSDString("truncate"))
        version = Version(1, 0, "pyaff4")
        with aff4zip.ZipFile.NewZipFile(resolver, version, urn) as volume:
            vurn = volume.urn
            with volume.CreateMember(vurn.Append("container.description")) as f:
                f.Write(vurn.SerializeToString().encode())
            with volume.CreateMember(vurn.Append("version.txt")) as f:
                f.Write(str(version).encode())
            image_urn = rdfvalue.URN("aff4://fd0e3d3d-0000-4000-8000-000000000001")
            map_urn = rdfvalue.URN("aff4://fd0e3d3d-0000-4000-8000-000000000002")
            stream_urn = map_urn.Append("data")
            resolver.Set(vurn, stream_urn, lexicon.AFF4_IMAGE_COMPRESSION,
                         rdfvalue.URN(compression))
            resolver.Set(vurn, stream_urn, lexicon.AFF4_IMAGE_CHUNK_SIZE,
                         rdfvalue.XSDInteger(chunk_size))
            resolver.Set(vurn, stream_urn, lexicon.AFF4_IMAGE_CHUNKS_PER_SEGMENT,
                         rdfvalue.XSDInteger(per_bevy))
            with aff4_map.AFF4Map.NewAFF4Map(resolver, map_urn, vurn) as m:
                if hole:
                    # The first 16 KiB, then a hole, then the rest.
                    m.SeekWrite(0)
                    m.Write(data[:16384])
                    m.SeekWrite(32768)
                    m.Write(data[32768:])
                else:
                    m.Write(data)
            resolver.Add(vurn, image_urn, lexicon.AFF4_TYPE,
                         rdfvalue.URN(lexicon.standard.Image))
            resolver.Add(vurn, image_urn, lexicon.AFF4_TYPE,
                         rdfvalue.URN(lexicon.AFF4_NAMESPACE + "DiskImage"))
            resolver.Set(vurn, image_urn, lexicon.standard.dataStream, map_urn)
            resolver.Set(vurn, image_urn, lexicon.AFF4_STREAM_SIZE,
                         rdfvalue.XSDInteger(len(data)))
            resolver.Set(vurn, map_urn, lexicon.AFF4_STREAM_SIZE,
                         rdfvalue.XSDInteger(len(data)))


physical(os.path.join(out, "physical.aff4"),
         lexicon.AFF4_IMAGE_COMPRESSION_ZLIB, 32768, 1024, False)
physical(os.path.join(out, "snappy.aff4"),
         lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY, 8192, 4, True)

# Logical: a small file (ZIP segment) and a larger one (ImageStream).
path = os.path.join(out, "logical.aff4")
with data_store.MemoryDataStore() as resolver:
    curn = rdfvalue.URN.FromFileName(path)
    with container.Container.createURN(resolver, curn) as volume:
        volume.maxSegmentResidentSize = 4096
        small = open(member, "rb").read()
        volume.writeLogical("docs/hello.txt", io.BytesIO(small), len(small))
        volume.writeLogical("disk/fat.img", io.BytesIO(data), len(data))
