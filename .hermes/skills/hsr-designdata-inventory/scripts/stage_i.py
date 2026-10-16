"""Stage I: integer IDs from decoded Excel tables (HSR-Offline export of the same
revision) fill single-slot templates: literal prefixes, literal {0} templates and
skeleton families from named paths in directories that still have gaps."""
import collections
import glob
import json
import os
import re

import lib

st = lib.Store()
W = lib.W
SRC = os.environ.get("HSR_OFFLINE_EXPORT", r"D:/Projects/HSR-Projects/HSR-Offline/target/path-alias-resource-replay")
files = glob.glob(SRC + "/**/ExcelOutput/*.json", recursive=True)
ints = set()


def walk(v):
    if isinstance(v, bool):
        return
    if isinstance(v, int):
        if 0 <= v < 10 ** 12:
            ints.add(str(v))
    elif isinstance(v, list):
        for x in v:
            walk(x)
    elif isinstance(v, dict):
        for x in v.values():
            walk(x)


for f in files:
    try:
        walk(json.load(open(f, encoding="utf-8-sig")))
    except Exception:
        pass
lib.log("excel files", len(files), "distinct ints", len(ints))

literals = open(os.path.join(W, "script_strings.txt"), encoding="utf-8").read().splitlines()
prefixes = [s for s in literals if re.match(r"(Config|Story)/", s) and s.endswith(("_", "/"))]
templates = [s for s in literals if re.match(r"(Config|Story)/", s) and s.count("{0}") >= 1
             and not re.search(r"\{[1-9]\}", s) and s.endswith(".json")]
lib.log("prefixes", prefixes)
lib.log("templates", len(templates))
before = len(st.names)
for v in ints:
    for p in prefixes:
        st.offer("BakedConfig/" + p + v + ".bytes", "excel_id_prefix")
    for t in templates:
        s = t.replace("{0}", v)
        st.offer("BakedConfig/" + s[:-5] + ".bytes", "excel_id_template")
lib.log("literal fills +", len(st.names) - before)

# skeleton families (single numeric slot) in directories with gaps
gap_dirs = set()
for prev, nxt, k in st.gaps():
    for p in (prev, nxt):
        if p:
            gap_dirs.add(p.rsplit("/", 1)[0])
SEG = re.compile(r"(\d+)")
fam = collections.defaultdict(list)
for p in st.names.values():
    d, f = p.rsplit("/", 1)
    if d not in gap_dirs:
        continue
    parts = SEG.split(f)
    if len(parts) == 3:
        fam[(d, parts[0], parts[2], len(parts[1]))].append(int(parts[1]))
lib.log("single-slot families", len(fam))
sorted_ints = sorted(int(v) for v in ints)
import bisect
b2 = len(st.names)
tried = 0
for (d, a, z, L), vals in fam.items():
    lo, hi = min(vals), max(vals)
    span = max(hi - lo, 10)
    i0 = bisect.bisect_left(sorted_ints, max(lo - span, 0))
    i1 = bisect.bisect_right(sorted_ints, hi + span)
    if i1 - i0 > 200_000:
        continue
    for v in sorted_ints[i0:i1]:
        s = str(v)
        if len(s) <= L:
            st.offer(f"{d}/{a}{s.zfill(L)}{z}", "excel_id_family")
            tried += 1
lib.log("family fills +", len(st.names) - b2, "tried", tried)
lib.transforms(st)
lib.interpolation(st)
st.save()
