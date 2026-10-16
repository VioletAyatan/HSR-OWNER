"""Find functions that reference given string literals (via IL2CPP usage slots).

Usage: python xref2.py "BlockExternals/" ".volume.json" ...
"""
import bisect
import re
import struct
import sys

import xref

data, secs = xref.load_pe(xref.GA)
idx = xref.load_script_index()
methods = idx["methods"]
starts = [m[0] for m in methods]
strings = {int(k): v for k, v in idx["strings"].items()}
by_value = {}
for addr, v in strings.items():
    by_value.setdefault(v, []).append(addr)


def func_of(rva):
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0:
        return None
    end = starts[i + 1] if i + 1 < len(starts) else starts[i] + 0x1000
    return methods[i][0], end, methods[i][1]


def rva_to_off(rva):
    for name, va, vsize, raw, rsize, chars in secs:
        if va <= rva < va + max(vsize, rsize):
            return raw + (rva - va)


targets = {}
for v in sys.argv[1:]:
    for a in by_value.get(v, []):
        targets[a] = v
print("slots:", {hex(a): v for a, v in targets.items()})
# mov/lea r64,[rip+disp32]: REX(48/4C) 8B/8D modrm(00 reg 101)
rx = re.compile(rb"[\x48\x4c][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
hits = {}
for name, va, vsize, raw, rsize, chars in secs:
    if not chars & 0x20000000:
        continue
    blob = data[raw:raw + rsize]
    for m in rx.finditer(blob):
        p = m.start() + 3
        if p + 4 > len(blob):
            break
        disp = struct.unpack_from("<i", blob, p)[0]
        tgt = va + p + 4 + disp
        if tgt in targets:
            hits.setdefault(func_of(va + p), []).append((va + p, targets[tgt]))
for f, refs in hits.items():
    fs, fe, fname = f
    print(f"== 0x{fs:X} {fname} size=0x{fe - fs:X} refs={[r[1] for r in refs]}")
    off = rva_to_off(fs)
    code = data[off:off + (fe - fs)]
    lits = []
    for p in range(0, len(code) - 4):
        disp = struct.unpack_from("<i", code, p)[0]
        t = fs + p + 4 + disp
        if t in strings:
            lits.append(strings[t])
    print("   literals:", lits[:60])
    calls = []
    for p in range(0, len(code) - 5):
        if code[p] == 0xE8:
            rel = struct.unpack_from("<i", code, p + 1)[0]
            t = fs + p + 5 + rel
            g = func_of(t)
            if g and g[0] == t:
                calls.append(g[2])
    print("   calls:", calls[:40])
