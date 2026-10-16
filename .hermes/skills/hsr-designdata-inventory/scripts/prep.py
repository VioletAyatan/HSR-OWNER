"""Prepare string corpora from HSR-OWNER dumps (run once per client build).

Inputs (from HSR-OWNER dumper output in <client>/DUMP):
  script-mini.json  -> script_strings.txt   (all IL2CPP string literals)
  dump.cs           -> dumpcs_identifiers.txt, excel_table_stems.txt
"""
import json
import os
import re

GAME = os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta")
W = os.environ.get("HSR_INV_WORK", os.getcwd())
DUMP = os.path.join(GAME, "DUMP")

lits = []
section = False
with open(os.path.join(DUMP, "script-mini.json"), encoding="utf-8") as f:
    for line in f:
        s = line.strip()
        if s.startswith('"ScriptString"'):
            section = True
        elif s.startswith('"ScriptMetadata"'):
            break
        elif section and s.startswith('"Value": '):
            lits.append(json.loads(s[len('"Value": '):].rstrip(",")))
lits = sorted(set(lits))
with open(os.path.join(W, "script_strings.txt"), "w", encoding="utf-8") as f:
    for s in lits:
        f.write(s.replace("\n", "\\n") + "\n")
print("literals", len(lits))

txt = open(os.path.join(DUMP, "dump.cs"), encoding="utf-8", errors="replace").read()
ids = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,100}", txt))
open(os.path.join(W, "dumpcs_identifiers.txt"), "w", encoding="utf-8").write("\n".join(sorted(ids)))
excel = set(re.findall(r"\b([A-Za-z0-9_]+)ExcelTable\b", txt))
open(os.path.join(W, "excel_table_stems.txt"), "w", encoding="utf-8").write("\n".join(sorted(excel)))
print("identifiers", len(ids), "excel table stems", len(excel))

# identifier tokens inside every indexed chunk (dictionary for gap attacks)
import designindex as di  # noqa: E402

toks, seen = set(), set()
rx = re.compile(rb"[A-Za-z0-9_\-]{3,120}")
for name in di.ROOTS:
    snap = di.open_snapshot(name)
    for fi in snap["files"]:
        if fi["path"] and fi["path"] not in seen:
            seen.add(fi["path"])
            toks.update(m.group().decode("ascii") for m in rx.finditer(open(fi["path"], "rb").read()))
open(os.path.join(W, "tokens_payload.txt"), "w", encoding="utf-8").write("\n".join(sorted(toks)))
print("payload tokens", len(toks))
