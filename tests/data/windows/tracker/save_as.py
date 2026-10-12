"""Drive a running OpenMPT: File > <menu item> and save to <out path> via the standard file dialog.
Usage: python save_as.py <pid> <out path> [menu item, default 'Save As...']
"""
import os
import sys
import time
from pywinauto import Application, Desktop
from pywinauto.keyboard import send_keys

pid = int(sys.argv[1])
out = sys.argv[2]
item = sys.argv[3] if len(sys.argv) > 3 else "Save As..."
app = Application(backend="win32").connect(process=pid)
main = app.window(class_name_re="Afx:.*", title_re="OpenMPT.*")
main.set_focus()
main.menu_select("File->" + item)
time.sleep(2)
dlg = None
for _ in range(20):
    wins = [w for w in app.windows(class_name="#32770") if w.is_visible()]
    if wins:
        dlg = wins[0]
        break
    time.sleep(0.5)
print("dialog:", dlg.window_text())
for c in dlg.descendants():
    if c.class_name() in ("ComboBox", "Button", "Static") and c.window_text():
        print("  ", c.class_name(), repr(c.window_text()))
if os.path.exists(out):
    os.remove(out)
edit = dlg.child_window(class_name="Edit", found_index=0)
edit.set_edit_text(out)
time.sleep(0.5)
edit.set_focus()
send_keys("{ENTER}")
time.sleep(3)
for w in app.windows(class_name="#32770"):
    if w.is_visible():
        print("left-over dialog:", w.window_text(), [c.window_text() for c in w.children()])
print("exists:", os.path.exists(out), os.path.getsize(out) if os.path.exists(out) else None)
