"""Residual gap report: where unnamed entries sit between named neighbours."""
import collections
import json
import os
import sys

import designindex as di

W = os.environ.get("HSR_INV_WORK", os.getcwd())
P = di.open_snapshot("Persistent")
S = di.open_snapshot("StreamingAssets")
names = {int(k, 16): v["path"] for k, v in json.load(open(os.path.join(W, "names_state.json"), encoding="utf-8")).items()}


def common_dir(a, b):
    pa, pb = a.split("/")[:-1], b.split("/")[:-1]
    i = 0
    while i < min(len(pa), len(pb)) and pa[i] == pb[i]:
        i += 1
    return "/".join(pa[:i])


gaps = []
for snap in (P, S):
    byfile = collections.defaultdict(list)
    for h, (fno, off, size) in snap["entries"].items():
        byfile[fno].append((off, size, h))
    for fno, ents in byfile.items():
        ents.sort()
        prev, cur = None, []
        for off, size, h in ents:
            nm = names.get(h)
            if nm is None:
                cur.append((off, size, h))
                continue
            if cur:
                gaps.append((snap["name"], fno, prev, nm, cur))
                cur = []
            prev = nm
        if cur:
            gaps.append((snap["name"], fno, prev, None, cur))

bydir = collections.Counter()
examples = collections.defaultdict(list)
for snapname, fno, a, b, cur in gaps:
    d = common_dir(a, b) if a and b else ((a or b or "?").rsplit("/", 1)[0] + " (edge)")
    key = f"{snapname[0]}[{fno}] {d}"
    bydir[key] += len(cur)
    if len(examples[key]) < int(sys.argv[2]) if len(sys.argv) > 2 else 3:
        examples[key].append((a, len(cur), b, [s for _, s, _ in cur][:4]))
top = int(sys.argv[1]) if len(sys.argv) > 1 else 30
print("unnamed total", sum(bydir.values()), "dirs", len(bydir))
for key, n in bydir.most_common(top):
    print(f"{n:6d}  {key}")
    for a, k, b, sizes in examples[key]:
        print(f"         {a and a.rsplit('/', 1)[-1]}  --[{k} unnamed sizes={sizes}]-->  {b and b.rsplit('/', 1)[-1]}")
