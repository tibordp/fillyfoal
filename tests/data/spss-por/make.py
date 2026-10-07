"""Regenerates the external SPSS portable (.por) fixture with pyreadstat
(ReadStat).

    uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I make.py

ReadStat writes the current date and time (`8/yyyyMMdd6/hhmmss` in the
portable file's character set, which ReadStat leaves as ASCII, possibly broken
across an 80-column line); the script overwrites the digits with a fixed
value (the only edit).
"""

import datetime
import pathlib
import re

import pandas as pd
import pyreadstat

OUT = pathlib.Path(__file__).resolve().parent / "../../fixtures/external/spss-por"

df = pd.DataFrame(
    {
        "id": [1.0, 2.0, 3.0, 4.0, 5.0],
        "name": ["Alice", "Bob", "Cedomir", "", "Eve with a longer name"],
        "score": [12.5, -99.0, None, 7.25, 1e10],
        "born": [
            datetime.date(1980, 1, 15),
            datetime.date(1999, 12, 31),
            None,
            datetime.date(1960, 1, 1),
            datetime.date(2024, 2, 29),
        ],
    }
)
OUT.mkdir(parents=True, exist_ok=True)
path = OUT / "survey.por"
pyreadstat.write_por(
    df,
    str(path),
    file_label="fillyfoal survey",
    column_labels=["Respondent", "Full name", "Test score", "Date of birth"],
)
data = bytearray(path.read_bytes())
m = re.search(rb"SPSSPORTA8/((?:(?:\r\n)?\d){8})6/((?:(?:\r\n)?\d){6})", bytes(data))
digits = iter(b"20261007110000")
for group in (1, 2):
    for i in range(m.start(group), m.end(group)):
        if data[i] in b"0123456789":
            data[i] = next(digits)
path.write_bytes(bytes(data))
