"""Regenerates the external NIfTI fixtures with nibabel.

uv run --with nibabel==5.4.2 --with numpy python tests/data/nifti/make.py
(run from the repository root)
"""

import os

import nibabel as nib
import numpy as np

out = "tests/fixtures/external/nifti"
os.makedirs(out, exist_ok=True)

affine = np.array(
    [
        [-2.0, 0.0, 0.0, 90.0],
        [0.0, 2.0, 0.0, -126.0],
        [0.0, 0.0, 2.5, -72.0],
        [0.0, 0.0, 0.0, 1.0],
    ]
)

# NIfTI-1 single file: a 4x3x2x2 int16 time series with an AFNI XML
# extension and a comment extension, qform and sform set, slice timing.
data = (np.arange(4 * 3 * 2 * 2, dtype=np.int16) * 7 - 40).reshape(4, 3, 2, 2)
img = nib.Nifti1Image(data, affine)
h = img.header
h.set_xyzt_units("mm", "sec")
h["pixdim"][4] = 2.0
h.set_qform(affine, code=1)
h.set_sform(affine, code=4)
h.set_dim_info(freq=0, phase=1, slice=2)
h["slice_start"] = 0
h["slice_end"] = 1
h["slice_code"] = 1  # sequential increasing
h["slice_duration"] = 1.0
h["descrip"] = b"fillyfoal nibabel phantom"
h["aux_file"] = b"phantom.lut"
h["cal_min"] = -40
h["cal_max"] = 120
h["scl_slope"] = 0.5
h["scl_inter"] = 10
h["toffset"] = 0.25
h.extensions.append(
    nib.nifti1.Nifti1Extension(
        "afni",
        b'<?xml version="1.0" ?>\n<AFNI_attributes self_idcode="XYZ_fillyfoal" NIfTI_nums="4,3,2,2,1,4">\n</AFNI_attributes>\n',
    )
)
h.extensions.append(nib.nifti1.Nifti1Extension("comment", b"made by fillyfoal tests"))
nib.save(img, os.path.join(out, "series.nii"))

# NIfTI-1 statistic map with an intent (t-test, 12 dof), float32.
stat = np.linspace(-3, 3, 3 * 3 * 3, dtype=np.float32).reshape(3, 3, 3)
img = nib.Nifti1Image(stat, affine)
img.header.set_intent("t test", (12,), name="tstat")
img.header.set_xyzt_units("mm")
img.header["descrip"] = b"t map"
nib.save(img, os.path.join(out, "tstat.nii"))

# NIfTI-1 header/image pair: only the .hdr is a fixture (ni1 magic).
pair = nib.Nifti1Pair(np.zeros((2, 2, 2), dtype=np.uint8), affine)
pair.header["descrip"] = b"pair header"
nib.save(pair, os.path.join(out, "pair.hdr"))
os.remove(os.path.join(out, "pair.img"))

# NIfTI-2 single file (540-byte header, 64-bit fields), uint16.
v = np.arange(5 * 4 * 3, dtype=np.uint16).reshape(5, 4, 3)
img2 = nib.Nifti2Image(v, affine)
img2.header.set_xyzt_units("mm")
img2.header["descrip"] = b"fillyfoal nifti-2"
img2.header.set_qform(affine, code=2)
img2.header.set_sform(affine, code=2)
img2.header.extensions.append(nib.nifti1.Nifti1Extension("comment", b"nifti-2 comment"))
nib.save(img2, os.path.join(out, "volume2.nii"))
