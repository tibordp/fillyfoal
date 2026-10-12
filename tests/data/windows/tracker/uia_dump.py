"""Dump top-level windows (and optionally controls) of a process via UI Automation.
Usage: python uia_dump.py <pid> [depth] [backend]
"""
import sys
from pywinauto import Application, Desktop

pid = int(sys.argv[1])
depth = int(sys.argv[2]) if len(sys.argv) > 2 else 0
backend = sys.argv[3] if len(sys.argv) > 3 else "uia"
app = Application(backend=backend).connect(process=pid)
for w in app.windows():
    print("WIN", repr(w.window_text()), w.element_info.class_name, w.rectangle(), w.is_visible())
    if depth:
        app.window(handle=w.handle).print_control_identifiers(depth=depth)
