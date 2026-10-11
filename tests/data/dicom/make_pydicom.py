"""DICOM files with undefined-length sequences and items, written by pydicom.

    uv run --with pydicom==3.0.2 --with numpy==2.3.4 python tests/data/dicom/make_pydicom.py OUTDIR

Writes, in OUTDIR:
- implicit-nested.dcm: Implicit VR Little Endian. Procedure Code Sequence
  (0008,1032) of undefined length with two items of undefined length; the
  first item holds a Concept Name Code Sequence (0040,A043) of undefined
  length with one undefined-length item. A private sequence (0009,1010)
  of undefined length with one undefined-length item follows (its tag is
  unknown to a reader, so its VR is not). Elements follow the sequences
  (Patient's Name, image attributes, Pixel Data).
- implicit-defined-items.dcm: the same without the nested sequence and
  with defined-length items inside the undefined-length sequence.
- explicit-undefined-items.dcm: Explicit VR Little Endian, the sequence
  and its items of undefined length, nested as in implicit-nested.dcm.
- rle-encapsulated.dcm: explicit-undefined-items.dcm compressed with
  pydicom's RLE Lossless encoder (needs numpy): encapsulated Pixel Data.
All UIDs are fixed, so the files are reproducible byte for byte.
"""

import sys

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.sequence import Sequence
from pydicom.uid import ExplicitVRLittleEndian, ImplicitVRLittleEndian, RLELossless

SC = "1.2.840.10008.5.1.4.1.1.7"  # Secondary Capture Image Storage


def make(path, syntax, undefined_items, nested, rle=False):
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = SC
    meta.MediaStorageSOPInstanceUID = "1.2.3.4.5"
    meta.TransferSyntaxUID = syntax
    ds = Dataset()
    ds.file_meta = meta
    ds.SOPClassUID = SC
    ds.SOPInstanceUID = "1.2.3.4.5"
    first = Dataset()
    first.CodeValue = "ABC"
    first.CodingSchemeDesignator = "L"
    if nested:
        inner = Dataset()
        inner.CodeValue = "X"
        inner.CodeMeaning = "Inner"
        inner.is_undefined_length_sequence_item = True
        first.ConceptNameCodeSequence = Sequence([inner])
        first["ConceptNameCodeSequence"].is_undefined_length = True
    second = Dataset()
    second.CodeValue = "DEF"
    for item in (first, second):
        item.is_undefined_length_sequence_item = undefined_items
    ds.ProcedureCodeSequence = Sequence([first, second])
    ds["ProcedureCodeSequence"].is_undefined_length = True
    if nested:
        # A private sequence: implicit-VR readers that do not know the tag
        # can only tell it is a sequence from its undefined length.
        ds.add_new(0x00090010, "LO", "FILLYFOAL")
        private = Dataset()
        private.CodeValue = "P"
        private.is_undefined_length_sequence_item = True
        ds.add_new(0x00091010, "SQ", Sequence([private]))
        ds[0x00091010].is_undefined_length = True
    ds.PatientName = "FILLYFOAL^TEST"
    ds.PatientID = "FILLYFOAL"
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = 2
    ds.Columns = 2
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = bytes([0, 64, 128, 255])
    if rle:
        # pydicom's own RLE encoder; Pixel Data becomes encapsulated (an
        # undefined length, a basic offset table and one fragment per frame).
        ds.compress(
            RLELossless, encoding_plugin="pydicom", generate_instance_uid=False
        )
    ds.save_as(path, enforce_file_format=True)


out = sys.argv[1]
make(f"{out}/implicit-nested.dcm", ImplicitVRLittleEndian, True, True)
make(f"{out}/implicit-defined-items.dcm", ImplicitVRLittleEndian, False, False)
make(f"{out}/explicit-undefined-items.dcm", ExplicitVRLittleEndian, True, True)
make(f"{out}/rle-encapsulated.dcm", ExplicitVRLittleEndian, True, True, rle=True)
