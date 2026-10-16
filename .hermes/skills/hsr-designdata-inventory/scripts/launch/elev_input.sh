#!/usr/bin/env bash
# usage: elev_input.sh <hwnd> action...   actions: click:X:Y key:VK sleep:S
# Runs input_elevated.py through UAC RunAs (needed for elevated game/launcher windows).
here=$(cd "$(dirname "$0")" && pwd)
W=$(cygpath -w "$here"); PY=$(cygpath -w "$(which python)")
rm -f "$here/input_result.txt"; hwnd=$1; shift
timeout 120 powershell.exe -NoProfile -Command "Start-Process -FilePath '$PY' -ArgumentList '\"$W\input_elevated.py\" $hwnd \"$W\input_result.txt\" $*' -Verb RunAs -Wait -WindowStyle Hidden"
cat "$here/input_result.txt"; echo
