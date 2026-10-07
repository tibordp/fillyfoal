"""Regenerates the external SPSS fixtures with pyreadstat (ReadStat).

    uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I make.py

ReadStat stamps the creation date and time into the header; the script
overwrites them with a fixed value afterwards so the output is reproducible
(the only edit).
"""

import datetime
import pathlib

import pandas as pd
import pyreadstat

OUT = pathlib.Path(__file__).resolve().parent / "../../fixtures/external/spss-sav"


def survey():
    return pd.DataFrame(
        {
            "id": [1.0, 2.0, 3.0, 4.0, 5.0],
            "name": ["Alice", "Bob", "Čedomir", "", "Eve with a longer name"],
            "sex": [1.0, 2.0, 2.0, 1.0, None],
            "score": [12.5, 99.0, None, 7.25, 1e10],
            "born": [
                datetime.date(1980, 1, 15),
                datetime.date(1999, 12, 31),
                None,
                datetime.date(1960, 1, 1),
                datetime.date(2024, 2, 29),
            ],
        }
    )


META = dict(
    file_label="fillyfoal survey",
    column_labels={
        "id": "Respondent",
        "name": "Full name",
        "sex": "Sex of respondent",
        "score": "Test score",
        "born": "Date of birth",
    },
    variable_value_labels={"sex": {1: "Male", 2: "Female"}, "score": {99: "Refused"}},
    missing_ranges={"score": [99]},
    note="Generated for fillyfoal's test suite",
)


def fix_header(path):
    # Creation date (9 bytes) and time (8 bytes) at 0x5c.
    data = bytearray(path.read_bytes())
    assert data[:3] == b"$FL"
    data[0x5C : 0x5C + 17] = b"07 Oct 2611:00:00"
    path.write_bytes(bytes(data))


def write(name, df, **kw):
    path = OUT / name
    pyreadstat.write_sav(df, str(path), **kw)
    fix_header(path)


OUT.mkdir(parents=True, exist_ok=True)
write("survey.sav", survey(), **META)
write("survey-bytecode.sav", survey(), row_compress=True, **META)
long = pd.DataFrame(
    {
        "n": [float(i) for i in range(300)],
        "sq": [float(i * i) if i % 7 else None for i in range(300)],
        "tag": ["even" if i % 2 == 0 else "odd" for i in range(300)],
    }
)
write("long.zsav", long, compress=True, file_label="300 rows, zlib")
