"""UI Automation helpers for OpenMPT 1.32 (pywinauto, UIA backend).

  python omp.py <pid> artist <name>            set Artist field on General tab
  python omp.py <pid> save <menu item> <path>  File > <menu item> and save to <path>
                                              (menu item e.g. 'Save As...' or 'Compatibility Export...')
  python omp.py <pid> windows                  list child windows (dialogs)
  python omp.py <pid> exit                     File > Exit
"""
import os
import sys
import time
from pywinauto import Application
from pywinauto.keyboard import send_keys

pid = int(sys.argv[1])
cmd = sys.argv[2]
app = Application(backend="uia").connect(process=pid)
w = app.window(title_re="OpenMPT 1.32.*")
w32 = Application(backend="win32").connect(process=pid).window(title_re="OpenMPT 1.32.*",
                                                                 class_name_re="Afx:.*")


def dialogs():
    return [c for c in w.children(control_type="Window")]


def dismiss_hints():
    for c in dialogs():
        if c.window_text() == "OpenMPT":
            texts = [d.window_text() for d in c.descendants()]
            print("hint:", [t for t in texts if t])
            for d in c.descendants(control_type="CheckBox"):
                if d.window_text().startswith("Do not show"):
                    d.toggle()
            for d in c.descendants(control_type="Button"):
                if d.window_text() in ("OK", "Yes"):
                    d.invoke()
                    break
            time.sleep(1)


if cmd == "windows":
    for c in dialogs():
        print(repr(c.window_text()))
        for d in c.descendants():
            if d.window_text() and d.element_info.control_type in ("Text", "Button", "CheckBox", "Edit", "ComboBox"):
                print("   ", d.element_info.control_type, repr(d.window_text()[:200]))
elif cmd == "artist":
    e = w.child_window(title="Artist:", control_type="Edit")
    # type_keys() (VK_PACKET) doubles every character in this edit and set_edit_text() is not
    # committed to the song, so click the field and type real virtual-key strokes.
    e.click_input()
    send_keys("^a{DEL}")
    send_keys(sys.argv[3], vk_packet=False)
    send_keys("{TAB}")
    print("artist now", e.get_value())
elif cmd == "save":
    item, path = sys.argv[3], sys.argv[4]
    if os.path.exists(path):
        os.remove(path)
    w32.set_focus()
    w32.menu_select("File->" + item)
    time.sleep(2)
    dismiss_hints()
    d = None
    for _ in range(20):
        ds = [c for c in dialogs() if c.window_text() in ("Save As", "Compatibility Export", "Save")]
        if ds:
            d = w.child_window(title=ds[0].window_text(), control_type="Window")
            break
        dismiss_hints()
        time.sleep(0.5)
    print("dialog", d.window_text())
    print("type:", d.child_window(title="Save as type:", control_type="ComboBox").selected_text())
    e = d.child_window(auto_id="1001", control_type="Edit")
    e.set_focus()
    e.type_keys("^a{BACKSPACE}")
    e.type_keys(path, with_spaces=True)
    e.type_keys("{ENTER}")
    time.sleep(3)
    dismiss_hints()
    print("remaining dialogs:", [c.window_text() for c in dialogs()])
    print("exists", os.path.exists(path), os.path.getsize(path) if os.path.exists(path) else None)
elif cmd == "mptm":
    # View > Song Properties > Type: "OpenMPT MPTM" > OK
    w32.set_focus()
    w32.menu_select("View->Song Properties")
    time.sleep(2)
    d = Application(backend="win32").connect(process=pid).window(title="Song Properties")
    cb = d.child_window(class_name="ComboBox", found_index=0)
    cb.select(cb.item_texts().index("OpenMPT MPTM"))
    time.sleep(0.5)
    d.child_window(title="OK", class_name="Button").click()
    time.sleep(2)
    dismiss_hints()
    print("type set; dialogs:", [c.window_text() for c in dialogs()])
elif cmd == "exit":
    w32.menu_select("File->Exit")
    time.sleep(2)
