"""Writes tests/fixtures/synthetic/olm/export.olm: an Outlook for Mac
archive laid out as exports are (no Outlook for Mac runs here): a ZIP of
Categories.xml and one XML file per item under
Accounts/<account>/com.microsoft.__Messages/<folder>/message_NNNNN.xml
(the paths olm-convert's olmConvert.py parses), with an attachment under
com.microsoft.__Attachments. The XML content is a placeholder in the shape
of an exported message, not Outlook's full schema.

    python tests/data/olm/make.py <out>
"""

import sys
import zipfile

ACCOUNT = "Accounts/fillyfoal@example.com"
message = """<?xml version="1.0" encoding="UTF-8"?>
<emails>
  <email>
    <OPFMessageCopySubject>fillyfoal test message</OPFMessageCopySubject>
    <OPFMessageCopySenderAddress>
      <emailAddress OPFContactEmailAddressAddress="sender@example.com" OPFContactEmailAddressName="Sender"/>
    </OPFMessageCopySenderAddress>
    <OPFMessageCopyBody>Hello from fillyfoal.</OPFMessageCopyBody>
    <OPFMessageCopyAttachmentList>
      <messageAttachment OPFAttachmentName="note.txt" OPFAttachmentContentType="text/plain"
        OPFAttachmentURL="{account}/com.microsoft.__Attachments/note.txt"/>
    </OPFMessageCopyAttachmentList>
  </email>
</emails>
""".format(account=ACCOUNT)
categories = """<?xml version="1.0" encoding="UTF-8"?>
<categories>
  <category OPFCategoryCopyName="fillyfoal" OPFCategoryCopyBackgroundColor="#7FB2E5"/>
</categories>
"""

with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    def add(name, data):
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, data)

    add("Categories.xml", categories)
    add(ACCOUNT + "/com.microsoft.__Messages/Inbox/message_00000.xml", message)
    add(ACCOUNT + "/com.microsoft.__Attachments/note.txt", "An attached note.\n")
