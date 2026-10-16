"""Classify every GameCoreConfigLoader.Load*(string) by its call pattern.

Checks the assumption used by the dumper's inventory decoder: a loader calls
IMNECEGBJLE.BAPACPLOLNH (binary reader) and then a static
`<Type>$$<deserializer>(FCOEMCEDLNL, out T)` declared on the loader's return
type (or one of its bases).
"""
import bisect
import collections
import json
import re
import sys

import capstone

import xref

data, secs = xref.load_pe(xref.GA)
idx = xref.load_script_index()
methods = idx["methods"]
starts = [m[0] for m in methods]
names_at = {a: n for a, n in methods}


def rva_to_off(rva):
    for name, va, vsize, raw, rsize, chars in secs:
        if va <= rva < va + max(vsize, rsize):
            return raw + (rva - va)


def func_end(rva):
    i = bisect.bisect_right(starts, rva)
    return starts[i] if i < len(starts) else rva + 0x400


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# reader-taking static methods: from dump.cs signatures "(FCOEMCEDLNL , out X& )"
dump = open(r"D:/StarRail_Beta/DUMP/dump.cs", encoding="utf-8", errors="replace").read()
sig = re.compile(r"(?:public|internal|private|protected) static (?:void|bool) (\w+)\(FCOEMCEDLNL [^,]*, out ([\w.<>,\[\] ]+)& [^)]*\) \{\} // VA: 0x[0-9A-F]+ RVA: 0x([0-9A-F]+)")
deser = {}
for m in sig.finditer(dump):
    deser[int(m.group(3), 16)] = (m.group(1), m.group(2))
print("reader deserializers in dump.cs:", len(deser))

rows = []
for line in open("loaders.txt", encoding="utf-8"):
    m = re.match(r"(\S.*?) (Load\w+)\(string \) 0x([0-9A-F]+)", line.strip())
    if not m:
        continue
    ret, name, rva = m.group(1), m.group(2), int(m.group(3), 16)
    end = min(func_end(rva), rva + 0x600)
    off = rva_to_off(rva)
    targets = []
    for ins in md.disasm(data[off:off + (end - rva)], rva):
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            targets.append(int(ins.op_str, 16))
    calls_reader = any("BAPACPLOLNH" in names_at.get(t, "") or "LoadBinaryConfig" in names_at.get(t, "") for t in targets)
    ds = [(t, names_at.get(t, "?"), deser.get(t)) for t in targets if t in deser]
    if not calls_reader:
        kind = "no-binary-reader"
    elif not ds:
        kind = "reader-but-no-direct-deserializer"
    else:
        owner = ds[0][1].split("$$")[0]
        short_ret = ret.split(".")[-1]
        kind = "deserializer-on-return-type" if owner.split(".")[-1] == short_ret else "deserializer-elsewhere"
    rows.append({"loader": name, "ret": ret, "rva": f"{rva:X}", "kind": kind,
                 "deser": [n for _, n, _ in ds],
                 "other_calls": [names_at.get(t, f"0x{t:X}") for t in targets
                                 if t not in deser and "JsonToBinaryPath" not in names_at.get(t, "")
                                 and "BAPACPLOLNH" not in names_at.get(t, "")][:6]})

c = collections.Counter(r["kind"] for r in rows)
print(dict(c))
json.dump(rows, open("loader_patterns.json", "w", encoding="utf-8"), indent=1)
for kind in ["deserializer-elsewhere", "reader-but-no-direct-deserializer", "no-binary-reader"]:
    sel = [r for r in rows if r["kind"] == kind]
    print(f"\n== {kind}: {len(sel)}")
    for r in sel[:25]:
        print(f"  {r['loader']:55s} ret={r['ret'][:40]:40s} deser={r['deser'][:2]} other={r['other_calls'][:4]}")
