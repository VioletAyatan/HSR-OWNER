"""Find callers of a GameAssembly RVA and the string literals each caller references.

Usage: python xref.py <target_rva_hex> [more ...]
Uses DUMP/script-mini.json (ScriptMethod/ScriptString addresses are RVAs).
"""
import bisect
import json
import os
import re
import struct
import sys

GA = os.path.join(os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta"), "GameAssembly.dll")
SCRIPT = os.path.join(os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta"), "DUMP/script-mini.json")
W = os.environ.get("HSR_INV_WORK", os.getcwd())
CACHE = os.path.join(W, "script_index.json")


def load_pe(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    secs = []
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode()
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        secs.append((name, va, vsize, raw, rsize, chars))
    return data, secs


def load_script_index():
    if os.path.exists(CACHE):
        return json.load(open(CACHE, encoding="utf-8"))
    methods, strings = [], {}
    section = None
    addr = None
    with open(SCRIPT, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s.startswith('"ScriptMethod"'):
                section = "m"
            elif s.startswith('"ScriptString"'):
                section = "s"
            elif s.startswith('"ScriptMetadata"'):
                section = None
            if section is None:
                continue
            if s.startswith('"Address":'):
                addr = int(s.split(":", 1)[1].strip().rstrip(","))
            elif section == "m" and s.startswith('"Name":'):
                methods.append((addr, json.loads(s.split(":", 1)[1].strip().rstrip(","))))
            elif section == "s" and s.startswith('"Value":'):
                strings[str(addr)] = json.loads(s.split(":", 1)[1].strip().rstrip(","))
    methods.sort()
    idx = {"methods": methods, "strings": strings}
    json.dump(idx, open(CACHE, "w", encoding="utf-8"))
    return idx


def main():
    data, secs = load_pe(GA)
    idx = load_script_index()
    methods = idx["methods"]
    starts = [m[0] for m in methods]
    strings = {int(k): v for k, v in idx["strings"].items()}
    text = [s for s in secs if s[5] & 0x20000000]  # executable

    def rva_to_off(rva):
        for name, va, vsize, raw, rsize, chars in secs:
            if va <= rva < va + max(vsize, rsize):
                return raw + (rva - va)
        return None

    def func_of(rva):
        i = bisect.bisect_right(starts, rva) - 1
        if i < 0:
            return None
        end = starts[i + 1] if i + 1 < len(starts) else starts[i] + 0x1000
        return methods[i][0], end, methods[i][1]

    def literals_in(start, end):
        off = rva_to_off(start)
        code = data[off:off + (end - start)]
        found = []
        for p in range(0, len(code) - 4):
            disp = struct.unpack_from("<i", code, p)[0]
            tgt = start + p + 4 + disp
            if tgt in strings:
                found.append((start + p, strings[tgt]))
        return found

    def callers(target):
        out = set()
        for name, va, vsize, raw, rsize, chars in text:
            blob = data[raw:raw + rsize]
            for m in re.finditer(rb"[\xe8\xe9]", blob):
                p = m.start()
                if p + 5 > len(blob):
                    break
                rel = struct.unpack_from("<i", blob, p + 1)[0]
                if va + p + 5 + rel == target:
                    out.add(va + p)
        return sorted(out)

    if sys.argv[1] == "--func":
        for t in sys.argv[2:]:
            fs, fe, fname = func_of(int(t, 16))
            print(f"== function 0x{fs:X} {fname} size=0x{fe - fs:X}")
            for at, lit in literals_in(fs, fe):
                print(f"      literal @0x{at:X}: {lit!r}")
            off = rva_to_off(fs)
            code = data[off:off + (fe - fs)]
            for p in range(0, len(code) - 5):
                if code[p] in (0xE8, 0xE9):
                    rel = struct.unpack_from("<i", code, p + 1)[0]
                    tgt = fs + p + 5 + rel
                    g = func_of(tgt)
                    if g and g[0] == tgt:
                        print(f"      call @0x{fs + p:X} -> 0x{tgt:X} {g[2]}")
        return
    for t in sys.argv[1:]:
        target = int(t, 16)
        f = func_of(target)
        print(f"== target 0x{target:X} {f[2] if f else '?'}")
        for site in callers(target):
            fs, fe, fname = func_of(site)
            print(f"  call @0x{site:X} in 0x{fs:X} {fname} (size 0x{fe - fs:X})")
            for at, lit in literals_in(fs, fe)[:40]:
                print(f"      literal @0x{at:X}: {lit!r}")


if __name__ == "__main__":
    main()
