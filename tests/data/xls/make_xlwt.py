"""Writes tests/fixtures/external/xls/xlwt.xls with xlwt (BIFF8).

    uv run --with xlwt==1.3.0 python tests/data/xls/make_xlwt.py <out.xls>
"""

import datetime
import sys

import xlwt

wb = xlwt.Workbook(encoding="utf-8")
wb.owner = "fillyfoal"
bold = xlwt.easyxf("font: bold on, colour red; align: horiz center")
date = xlwt.easyxf(num_format_str="YYYY-MM-DD")
money = xlwt.easyxf(num_format_str="#,##0.00 [$EUR]")

s = wb.add_sheet("Data")
o = wb.add_sheet("Other")
s.write(0, 0, "Item", bold)
s.write(0, 1, "Count", bold)
s.write(0, 2, "Price", bold)
s.write(0, 3, "When", bold)
rows = [("apple", 3, 0.5), ("pear", 120, 1.25), ("plum", -7, 1e-3), ("fig", 2**20, 12345.678)]
for i, (name, n, p) in enumerate(rows, start=1):
    s.write(i, 0, name)
    s.write(i, 1, n)
    s.write(i, 2, p, money)
    s.write(i, 3, datetime.date(2026, 1, i), date)
s.write(5, 0, "Total")
s.write(5, 1, xlwt.Formula("SUM(B2:B5)"))
s.write(5, 2, xlwt.Formula("SUMPRODUCT(B2:B5;C2:C5)"))
s.write(6, 0, xlwt.Formula('IF(B6>100;"big";"small")&" total"'))
s.write(6, 1, xlwt.Formula("Other!A1*2+ROUND(PI();2)"))
s.write(6, 2, True)
s.write_merge(7, 7, 0, 3, "merged across four columns")
s.col(0).width = 4000

o.write(0, 0, 21)
o.write(1, 0, "Ünïcödé text")
o.write(2, 0, "apple")

wb.save(sys.argv[1])
