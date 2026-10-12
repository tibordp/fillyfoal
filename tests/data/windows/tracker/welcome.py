"""Answer OpenMPT's first-run 'Welcome' dialog: no update checks, no statistics, artist 'fillyfoal'.
Then close OpenMPT so mptrack.ini is written. Usage: python welcome.py <pid>
"""
import sys
import time
from pywinauto import Application

pid = int(sys.argv[1])
app = Application(backend="win32").connect(process=pid)
dlg = app.window(title="Welcome to OpenMPT!")
dlg.wait("visible", timeout=20)
for title in ("&Automatically check for new versions of OpenMPT",
              "Help OpenMPT development by providing basic s&tatistics"):
    cb = dlg.child_window(title=title, class_name="Button")
    if cb.is_enabled() and cb.get_check_state():
        cb.uncheck()
dlg.child_window(class_name="Edit", found_index=0).set_edit_text("fillyfoal")
dlg.child_window(title="&OK", class_name="Button").click()
time.sleep(2)
main = app.window(title_re="OpenMPT.*", class_name_re="Afx:.*")
main.close()
time.sleep(3)
print("done")
