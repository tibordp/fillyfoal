"""Regenerates the external Stata fixtures with pyreadstat (ReadStat) and
pandas' own writer (`DataFrame.to_stata`).

    uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I make.py

pandas takes a fixed time stamp. ReadStat stamps the current time into the
header; the script overwrites it with a fixed value of the same length
afterwards so the output is reproducible (the only edit).
"""

import datetime
import pathlib
import re

import pandas as pd
import pyreadstat

OUT = pathlib.Path(__file__).resolve().parent / "../../fixtures/external/stata-dta"
STAMP = datetime.datetime(2026, 10, 7, 11, 0)


def frame():
    return pd.DataFrame(
        {
            "id": pd.array([1, 2, 3, 4, 5], dtype="int32"),
            "small": pd.array([1, -2, 100, 0, 7], dtype="int8"),
            "mid": pd.array([300, -300, 0, 32000, 1], dtype="int16"),
            "ratio": pd.array([0.5, -1.25, float("nan"), 3.0, 1e-3], dtype="float32"),
            "score": [12.5, 99.0, None, 7.25, 1e10],
            "name": ["Alice", "Bob", "Cedomir", "", "Eve with a longer name"],
            "born": pd.to_datetime(
                ["1980-01-15", "1999-12-31", None, "1960-01-01", "2024-02-29"]
            ),
        }
    )


LABELS = {
    "id": "Respondent",
    "small": "An int8",
    "mid": "An int16",
    "ratio": "A float",
    "score": "Test score",
    "name": "Full name",
    "born": "Date of birth",
}


def fix_readstat(path):
    data = bytearray(path.read_bytes())
    fixed = b"07 Oct 2026 11:00"
    if data.startswith(b"<stata_dta>"):
        m = re.search(rb"<timestamp>(.)", bytes(data))
        start = m.start(1) + 1
        assert data[m.start(1)] == 17
    else:
        # 4-byte header, nvar, nobs, 81-byte label, then the time stamp.
        start = 4 + 2 + 4 + 81
    data[start : start + 17] = fixed
    path.write_bytes(bytes(data))


def readstat(name, version):
    path = OUT / name
    df = frame()
    df["born"] = df["born"].dt.date
    pyreadstat.write_dta(
        df,
        str(path),
        file_label="fillyfoal survey",
        column_labels=LABELS,
        version=version,
        variable_value_labels={"small": {1: "one", 7: "seven"}},
    )
    fix_readstat(path)


def pandas_writer(name, version, **kw):
    df = frame()
    df["grade"] = pd.Categorical(["b", "a", "c", "a", "b"])
    df.to_stata(
        OUT / name,
        write_index=False,
        version=version,
        time_stamp=STAMP,
        data_label="fillyfoal survey",
        variable_labels=LABELS,
        convert_dates={"born": "td"},
        **kw,
    )


OUT.mkdir(parents=True, exist_ok=True)
readstat("readstat-113.dta", 8)
readstat("readstat-115.dta", 12)
readstat("readstat-118.dta", 14)
pandas_writer("pandas-114.dta", 114)
pandas_writer("pandas-117.dta", 117, convert_strl=["name"])
pandas_writer("pandas-118.dta", 118)
pandas_writer("pandas-119.dta", 119)
