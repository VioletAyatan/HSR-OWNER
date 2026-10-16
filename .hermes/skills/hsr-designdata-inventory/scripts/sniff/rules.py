"""Derive family -> loader rules from typesniff evidence + runtime ground truth."""
import collections
import json
import os
import re

W = os.path.join(os.environ.get("HSR_INV_WORK", "."), "sniff")
fams = json.load(open(f"{W}/families.json", encoding="utf-8"))
loader_types = json.load(open(f"{W}/loader_types.json", encoding="utf-8"))
type_loaders = collections.defaultdict(list)
for loader, ty in sorted(loader_types.items()):
    type_loaders[ty].append(loader)

# loaders observed in the runtime log, by type (prefer these when a type has several)
truth_loaders = collections.Counter()
for line in open(f"{W}/sniff_all.jsonl", encoding="utf-8"):
    r = json.loads(line)
    if r["truth"]:
        truth_loaders[(r["truth_type"], r["truth"])] += 1


def loader_for(ty):
    used = [l for (t, l), _ in truth_loaders.most_common() if t == ty]
    if used:
        return used[0]
    cands = type_loaders.get(ty, [])
    return cands[0] if cands else None


rules, review = {}, []
for fam, v in fams.items():
    n, covered = v["n"], v["covered"]
    if covered == n:
        continue
    decision = None
    why = ""
    if fam.endswith(".layout") or ".layout" in fam.rsplit("/", 1)[-1]:
        decision, why = "LoadConfigBakeLayoutInfoList", "client BinaryBakeLayoutPath transform"
    elif v["truth"]:
        ty = v["truth"][0][0]
        decision, why = loader_for(ty), f"runtime truth {ty}"
    else:
        cands = v["cands"]
        if cands and cands[0][1] > 0:
            top = cands[0]
            second = cands[1] if len(cands) > 1 else None
            if second is None or second[1] * 2 < top[1] or (second[1] < top[1] and top[3] > second[3]):
                decision, why = loader_for(top[0]), f"sniff exact {top[1]}/{n} {top[0]}"
    if decision:
        rules[fam] = {"loader": decision, "why": why, "missing": n - covered, "n": n}
    else:
        review.append((n - covered, fam, v["cands"][:3]))

json.dump(rules, open(f"{W}/rules_auto.json", "w", encoding="utf-8"), indent=1)
total_missing = sum(v["n"] - v["covered"] for v in fams.values())
ruled = sum(r["missing"] for r in rules.values())
print(f"uncovered entries {total_missing}; with auto rule {ruled}; families needing review {len(review)} "
      f"({sum(m for m, _, _ in review)} entries)")
by_loader = collections.Counter()
for r in rules.values():
    by_loader[r["loader"]] += r["missing"]
print("by loader:", by_loader.most_common(25))
review.sort(reverse=True)
for m, fam, c in review[:120]:
    print(f"{m:6d} {fam[:80]:80s} {[(t.replace('RPG.GameCore.', ''), e, g) for t, e, g, _ in c]}")
