"""Prepares the throwaway LibreOffice profile used for the CFB fixtures.

Run `soffice -env:UserInstallation=file:///tmp/fixtures/office-cfb/lo-profile --headless
--terminate_after_init` once to create it, then this script, then
lo-convert.sh. It sets a neutral user name ("fillyfoal") and turns off the
preview images Impress embeds in the summary information (hundreds of KiB).
"""

PATH = "/tmp/fixtures/office-cfb/lo-profile/user/registrymodifications.xcu"

ITEMS = [
    ("/org.openoffice.UserProfile/Data", "givenname", "fillyfoal"),
    ("/org.openoffice.UserProfile/Data", "sn", ""),
    ("/org.openoffice.UserProfile/Data", "initials", "FF"),
    ("/org.openoffice.UserProfile/Data", "o", ""),
    ("/org.openoffice.UserProfile/Data", "mail", ""),
    ("/org.openoffice.Office.Common/Save/Document", "GenerateThumbnail", "false"),
    ("/org.openoffice.Office.Common/Filter/Microsoft/Export", "EnablePowerPointPreview", "false"),
    ("/org.openoffice.Office.Common/Filter/Microsoft/Export", "EnableExcelPreview", "false"),
    ("/org.openoffice.Office.Common/Filter/Microsoft/Export", "EnableWordPreview", "false"),
]

with open(PATH) as f:
    s = f.read()
add = "".join(
    f'<item oor:path="{path}"><prop oor:name="{name}" oor:op="fuse"><value>{value}</value></prop></item>\n'
    for path, name, value in ITEMS
)
s = s.replace("</oor:items>", add + "</oor:items>")
with open(PATH, "w") as f:
    f.write(s)
