"""List or restore top-level windows of a process.

usage: winlist.py <pid|image.exe> [restore <hwnd>]
"""
import ctypes
import subprocess
import sys
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsIconic.argtypes = [wintypes.HWND]
user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]


def pids_for(arg):
    if arg.isdigit():
        return {int(arg)}
    out = subprocess.run(["tasklist.exe", "/FI", f"IMAGENAME eq {arg}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True).stdout
    return {int(line.split('","')[1]) for line in out.splitlines() if line.startswith('"')}


def windows(pids):
    found = []

    def cb(hwnd, _):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in pids:
            title = ctypes.create_unicode_buffer(256)
            cls = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, title, 256)
            user32.GetClassNameW(hwnd, cls, 256)
            rect = wintypes.RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rect))
            found.append((hwnd, pid.value, title.value, cls.value, bool(user32.IsWindowVisible(hwnd)),
                          bool(user32.IsIconic(hwnd)), (rect.left, rect.top, rect.right, rect.bottom)))
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return found


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[2] == "restore":
        hwnd = int(sys.argv[3])
        print("ShowWindow(SW_RESTORE) ->", user32.ShowWindow(hwnd, 9))
    for w in windows(pids_for(sys.argv[1])):
        if w[2] or w[4]:
            print(w)
