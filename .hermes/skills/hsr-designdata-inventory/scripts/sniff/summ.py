import collections
import json
import os
import sys

rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 60
c = collections.Counter()
for r in rows:
    t = r["truth_type"]
    m = r["matches"]
    if t:
        c[("truth", "hit" if t in m else "miss", "ambig" if len(m) > 1 else "uniq" if m else "none")] += 1
    else:
        c[("notruth", "none" if not m else "uniq" if len(m) == 1 else "ambig")] += 1
for k, v in sorted(c.items()):
    print(k, v)
miss = collections.Counter()
for r in rows:
    if r["truth_type"] and r["truth_type"] not in r["matches"]:
        e = (r["truth_error"] or "")
        # last meaningful fragment
        key = e.split(": ")[-1][:120] if e else "?"
        miss[key] += 1
print("truth miss reasons:")
for k, v in miss.most_common(15):
    print(f"  {v:6d} {k}")
for r in rows[:limit]:
    print(r["json"][-50:], r["size"], (r["truth_type"] or "-").replace("RPG.GameCore.", ""),
          (r["truth_error"] or "")[-110:], [m.replace("RPG.GameCore.", "") for m in r["matches"][:5]])
