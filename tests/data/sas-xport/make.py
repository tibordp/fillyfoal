"""Regenerates the external SAS transport (XPORT) fixtures with pyreadstat
(ReadStat).

    uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I make.py

ReadStat stamps the current time into the library and member headers
(`ddMMMyy:hh:mm:ss`); the script overwrites every such stamp with a fixed
one of the same length so the output is reproducible (the only edit).
"""

import datetime
import pathlib
import re

import pandas as pd
import pyreadstat

OUT = pathlib.Path(__file__).resolve().parent / "../../fixtures/external/sas-xport"


def frame():
    return pd.DataFrame(
        {
            "ID": [1.0, 2.0, 3.0, 4.0, 5.0],
            "NAME": ["Alice", "Bob", "Cedomir", "", "Eve with a longer name"],
            "SCORE": [12.5, -99.0, None, 7.25, 1e10],
            "BORN": [
                datetime.date(1980, 1, 15),
                datetime.date(1999, 12, 31),
                None,
                datetime.date(1960, 1, 1),
                datetime.date(2024, 2, 29),
            ],
        }
    )


def write(name, version):
    path = OUT / name
    pyreadstat.write_xport(
        frame(),
        str(path),
        file_label="fillyfoal survey",
        column_labels=["Respondent", "Full name", "Test score", "Date of birth"],
        table_name="SURVEY",
        file_format_version=version,
    )
    data = path.read_bytes()
    data = re.sub(rb"\d\d[A-Z]{3}\d\d:\d\d:\d\d:\d\d", b"07OCT26:11:00:00", data)
    path.write_bytes(data)


OUT.mkdir(parents=True, exist_ok=True)
write("survey-v5.xpt", 5)
write("survey-v8.xpt", 8)
