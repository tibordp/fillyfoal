"""A CI artifact holding a saved plan: a ZIP (Python's zipfile, deflate)
with one member `tfplan` that is the whole saved plan `create.tfplan`
(itself a ZIP), as `terraform plan -out=tfplan` and an upload-artifact
step leave it. Fixed timestamp, so the output is reproducible.

Usage: python3 -I tests/data/terraform-plan/make_artifact.py \
           tests/fixtures/external/terraform-plan/create.tfplan \
           tests/fixtures/external/zip/tfplan-artifact.zip
"""

import sys
import zipfile

with open(sys.argv[1], "rb") as f:
    plan = f.read()
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    info = zipfile.ZipInfo("tfplan", date_time=(2024, 1, 2, 3, 4, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    z.writestr(info, plan)
