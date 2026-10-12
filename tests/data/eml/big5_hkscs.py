"""Writes tests/fixtures/external/eml/big5-hkscs.eml with CPython's email
package: a message whose subject and body are Big5-HKSCS (the WHATWG label
`big5-hkscs`), with HKSCS characters code page 950 lacks: one outside the BMP
(U+2010C) and one that decodes to two code points (U+00CA U+0304).

    uv run --python 3.13 python3 -I tests/data/eml/big5_hkscs.py OUT.eml
"""

import email.charset
import sys
from email.header import Header
from email.mime.text import MIMEText

# Python's own codec name is big5hkscs; label the parts big5-hkscs.
email.charset.add_charset(
    "big5-hkscs", email.charset.BASE64, email.charset.BASE64, "big5-hkscs"
)
email.charset.add_codec("big5-hkscs", "big5hkscs")

body = "香港增補字符集：\U0002010c、Ê̄、①、𠄌。\n廣東話：佢哋喺度食緊嘢。\n"
msg = MIMEText(body, "plain", "big5-hkscs")
msg["Subject"] = Header("香港字\U0002010c測試", "big5-hkscs")
msg["From"] = "fillyfoal <fillyfoal@example.com>"
msg["To"] = "fillyfoal <fillyfoal@example.com>"
msg["Date"] = "Mon, 12 Oct 2026 10:00:00 +0800"
msg["Message-ID"] = "<big5-hkscs@example>"
with open(sys.argv[1], "wb") as f:
    f.write(msg.as_bytes())
