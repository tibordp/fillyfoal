"""Writes the external PST fixtures with Aspose.Email for Python via .NET.

    uv run --with aspose-email-for-python-via-net==26.8 python -I tests/data/pst/generate.py OUT_DIR

Aspose runs unlicensed (evaluation mode). The output is not byte-for-byte
reproducible: the writer stamps fresh entry IDs, record keys and times.
The harness inflates `*.gz`; the files are mostly zero-filled preallocated
pages, so they are stored as `gzip -9 -n`.
"""

import datetime
import gzip
import os
import struct
import sys
import zlib

from aspose.email.mapi import MapiMessage, MapiProperty, MapiPropertyTag, MapiRecipientType
from aspose.email.storage.pst import FileFormatVersion, PersonalStorage, StandardIpmFolder

def png_1x1():
    """A 1x1 RGBA PNG (an attachment for the dissector to identify)."""
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00\xff", 9)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


PNG = png_1x1()


def when(day, hour):
    return datetime.datetime(2024, 3, day, hour, 30, 0)


def message(sender, to, subject, body, day):
    msg = MapiMessage(sender, to, subject, body)
    name = sender.split("@")[0].capitalize()
    for tag, value in ((MapiPropertyTag.SENDER_NAME_W, name),
                       (MapiPropertyTag.SENDER_EMAIL_ADDRESS_W, sender),
                       (MapiPropertyTag.SENT_REPRESENTING_NAME_W, name),
                       (MapiPropertyTag.SENT_REPRESENTING_EMAIL_ADDRESS_W, sender)):
        msg.set_string_property_value(tag, value)
    msg.delivery_time = when(day, 9)
    msg.client_submit_time = when(day, 8)
    return msg


def build(path, version):
    if os.path.exists(path):
        os.remove(path)
    pst = PersonalStorage.create(path, version)
    inbox = pst.create_predefined_folder("Inbox", StandardIpmFolder.INBOX)
    sent = pst.create_predefined_folder("Sent Items", StandardIpmFolder.SENT_ITEMS)
    projects = inbox.add_sub_folder("Projects")

    inbox.add_message(
        message("alice@example.com", "bob@example.com", "Lunch on Friday?",
                "Hi Bob,\r\nShall we get lunch on Friday?\r\nAlice", 4))

    html = message("carol@example.com", "bob@example.com", "Quarterly report",
                   "The report is attached.", 5)
    html.set_property(MapiProperty(
        MapiPropertyTag.BODY_HTML,
        b"<html><body><p>The <b>report</b> is attached.</p></body></html>"))
    html.recipients.add("dave@example.com", "Dave", MapiRecipientType.CC)
    html.attachments.add("pixel.png", PNG)
    html.attachments.add("notes.txt", b"Quarterly notes: all good.\r\n")
    inbox.add_message(html)

    fwd = message("dave@example.com", "bob@example.com", "Fwd: Lunch on Friday?",
                  "See below.", 6)
    inner = message("alice@example.com", "dave@example.com", "Lunch on Friday?",
                    "Forwarded original.", 4)
    fwd.attachments.add("Lunch on Friday.msg", inner)
    projects.add_message(fwd)

    # A body larger than a block (8 KiB), stored as a data tree.
    long_body = "".join("Line %04d of a long message body.\r\n" % i for i in range(400))
    projects.add_message(message("erin@example.com", "bob@example.com",
                                 "Long message", long_body, 7))

    sent.add_message(
        message("bob@example.com", "alice@example.com", "Re: Lunch on Friday?",
                "Sounds good!", 4))


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    # Aspose cannot create ANSI files ("The ANSI file version creation is
    # not implemented").
    for name, make in (("unicode.pst", build),):
        path = os.path.join(out, name)
        make(path, FileFormatVersion.UNICODE)
        with open(path, "rb") as f:
            data = f.read()
        with open(path + ".gz", "wb") as f:
            f.write(gzip.compress(data, 9, mtime=0))
        os.remove(path)
        print(name, len(data))


main()
