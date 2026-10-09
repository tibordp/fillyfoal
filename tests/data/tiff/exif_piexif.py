"""Writes an Exif block (the TIFF stream of a JPEG APP1 segment, without its
"Exif\\0\\0" prefix) with piexif: IFD0, Exif, GPS and Interoperability IFDs
and an IFD1 JPEG thumbnail made by Pillow.

    uv run --with pillow==12.3.0 --with piexif==1.1.3 \
        python tests/data/tiff/exif_piexif.py tests/fixtures/external/tiff/exif-piexif.tif
"""

import io
import sys

import piexif
from PIL import Image

thumb = io.BytesIO()
Image.new("RGB", (16, 12), (200, 80, 40)).save(thumb, "JPEG", quality=50)
zeroth = {
    piexif.ImageIFD.Make: b"Canon",
    piexif.ImageIFD.Model: b"Canon EOS R5",
    piexif.ImageIFD.Orientation: 6,
    piexif.ImageIFD.XResolution: (72, 1),
    piexif.ImageIFD.YResolution: (72, 1),
    piexif.ImageIFD.ResolutionUnit: 2,
    piexif.ImageIFD.Software: b"fillyfoal fixture",
    piexif.ImageIFD.DateTime: b"2024:05:01 12:00:00",
    piexif.ImageIFD.YCbCrPositioning: 2,
    piexif.ImageIFD.Artist: b"A. Photographer",
}
exif = {
    piexif.ExifIFD.ExposureTime: (1, 250),
    piexif.ExifIFD.FNumber: (40, 10),
    piexif.ExifIFD.ExposureProgram: 3,
    piexif.ExifIFD.ISOSpeedRatings: 200,
    piexif.ExifIFD.SensitivityType: 2,
    piexif.ExifIFD.ExifVersion: b"0232",
    piexif.ExifIFD.DateTimeOriginal: b"2024:05:01 12:00:00",
    piexif.ExifIFD.DateTimeDigitized: b"2024:05:01 12:00:00",
    piexif.ExifIFD.OffsetTimeOriginal: b"+02:00",
    piexif.ExifIFD.ComponentsConfiguration: b"\x01\x02\x03\x00",
    piexif.ExifIFD.ShutterSpeedValue: (7965784, 1000000),
    piexif.ExifIFD.ApertureValue: (4, 1),
    piexif.ExifIFD.ExposureBiasValue: (-1, 3),
    piexif.ExifIFD.MaxApertureValue: (4, 1),
    piexif.ExifIFD.MeteringMode: 5,
    piexif.ExifIFD.Flash: 16,
    piexif.ExifIFD.FocalLength: (50, 1),
    piexif.ExifIFD.SubjectArea: (3000, 2000, 400, 300),
    piexif.ExifIFD.UserComment: b"ASCII\x00\x00\x00Hello from the fixture",
    piexif.ExifIFD.SubSecTimeOriginal: b"25",
    piexif.ExifIFD.FlashpixVersion: b"0100",
    piexif.ExifIFD.ColorSpace: 1,
    piexif.ExifIFD.PixelXDimension: 6000,
    piexif.ExifIFD.PixelYDimension: 4000,
    piexif.ExifIFD.FocalPlaneXResolution: (6000000, 1415),
    piexif.ExifIFD.FocalPlaneYResolution: (4000000, 943),
    piexif.ExifIFD.FocalPlaneResolutionUnit: 2,
    piexif.ExifIFD.FileSource: b"\x03",
    piexif.ExifIFD.SceneType: b"\x01",
    piexif.ExifIFD.CustomRendered: 0,
    piexif.ExifIFD.ExposureMode: 0,
    piexif.ExifIFD.WhiteBalance: 0,
    piexif.ExifIFD.DigitalZoomRatio: (0, 1),
    piexif.ExifIFD.FocalLengthIn35mmFilm: 50,
    piexif.ExifIFD.SceneCaptureType: 0,
    piexif.ExifIFD.BodySerialNumber: b"012345678901",
    piexif.ExifIFD.LensSpecification: ((24, 1), (105, 1), (4, 1), (4, 1)),
    piexif.ExifIFD.LensModel: b"RF24-105mm F4 L IS USM",
}
gps = {
    piexif.GPSIFD.GPSVersionID: (2, 3, 0, 0),
    piexif.GPSIFD.GPSLatitudeRef: b"N",
    piexif.GPSIFD.GPSLatitude: ((48, 1), (51, 1), (2964, 100)),
    piexif.GPSIFD.GPSLongitudeRef: b"E",
    piexif.GPSIFD.GPSLongitude: ((2, 1), (17, 1), (402, 10)),
    piexif.GPSIFD.GPSAltitudeRef: 0,
    piexif.GPSIFD.GPSAltitude: (352, 10),
    piexif.GPSIFD.GPSTimeStamp: ((10, 1), (0, 1), (5, 1)),
    piexif.GPSIFD.GPSSpeedRef: b"K",
    piexif.GPSIFD.GPSSpeed: (0, 1),
    piexif.GPSIFD.GPSImgDirectionRef: b"T",
    piexif.GPSIFD.GPSImgDirection: (12345, 100),
    piexif.GPSIFD.GPSMapDatum: b"WGS-84",
    piexif.GPSIFD.GPSDateStamp: b"2024:05:01",
}
interop = {piexif.InteropIFD.InteroperabilityIndex: b"R98"}
first = {
    piexif.ImageIFD.Compression: 6,
    piexif.ImageIFD.XResolution: (72, 1),
    piexif.ImageIFD.YResolution: (72, 1),
    piexif.ImageIFD.ResolutionUnit: 2,
}
blob = piexif.dump(
    {
        "0th": zeroth,
        "Exif": exif,
        "GPS": gps,
        "Interop": interop,
        "1st": first,
        "thumbnail": thumb.getvalue(),
    }
)
assert blob.startswith(b"Exif\x00\x00")
with open(sys.argv[1], "wb") as out:
    out.write(blob[6:])
