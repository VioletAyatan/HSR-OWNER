"""Elevated input helper: foreground a window, then run actions.

usage: input_elevated.py <hwnd> <result.txt> action...
actions: click:X:Y  key:VK  sleep:SECONDS
"""
import ctypes
import sys
import time
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("pad", ctypes.c_byte * 32)]
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _U)]


def send(*inputs):
    arr = (INPUT * len(inputs))(*inputs)
    return user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT))


def main():
    hwnd, out = int(sys.argv[1]), sys.argv[2]
    user32.SetProcessDPIAware()
    log = []
    user32.ShowWindow(hwnd, 9)
    user32.keybd_event(0x12, 0, 0, 0)
    log.append(f"SetForegroundWindow={user32.SetForegroundWindow(hwnd)}")
    user32.keybd_event(0x12, 0, 2, 0)
    time.sleep(0.8)
    log.append(f"foreground={user32.GetForegroundWindow()} target={hwnd}")
    for action in sys.argv[3:]:
        kind, *args = action.split(":")
        if kind == "click":
            x, y = int(args[0]), int(args[1])
            user32.SetCursorPos(x, y)
            time.sleep(0.15)
            down, up = INPUT(type=0), INPUT(type=0)
            down.mi.dwFlags, up.mi.dwFlags = 0x0002, 0x0004
            log.append(f"click {x},{y} -> {send(down)}")
            time.sleep(0.08)
            send(up)
        elif kind == "key":
            vk = int(args[0], 0)
            down, up = INPUT(type=1), INPUT(type=1)
            down.ki.wVk = up.ki.wVk = vk
            up.ki.dwFlags = 0x0002
            log.append(f"key {vk:#x} -> {send(down)}")
            time.sleep(0.08)
            send(up)
        elif kind == "sleep":
            time.sleep(float(args[0]))
    open(out, "w").write("\n".join(log))


main()
