"""Run inside python:3.12-slim by make.sh: a small dbm.gnu database."""

import dbm.gnu
import os
import sys

path = sys.argv[1]
if os.path.exists(path):
    os.remove(path)
db = dbm.gnu.open(path, "nf")
for key, value in [
    (b"alpha", b"first"),
    (b"beta", b"second value"),
    (b"gamma", b"3"),
    (b"delta", b"fillyfoal" * 4),
    (b"epsilon", b""),
]:
    db[key] = value
db.close()
