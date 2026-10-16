"""Aggregate typesniff output: calibrate against runtime ground truth and
infer a root type per path family."""
import collections
import json
import os
import re
import sys

W = os.path.join(os.environ.get("HSR_INV_WORK", "."), "sniff")
roots = json.load(open(f"{W}/roots.json", encoding="utf-8"))
loader_types = json.load(open(f"{W}/loader_types.json", encoding="utf-8"))
type_loaders = collections.defaultdict(list)
for loader, ty in loader_types.items():
    type_loaders[ty].append(loader)
rows = [json.loads(l) for l in open(f"{W}/sniff_all.jsonl", encoding="utf-8")]
NUM = re.compile(r"\d+")


def family(path):
    p = path[len("BakedConfig/"):]
    d, f = p.rsplit("/", 1) if "/" in p else ("", p)
    d = NUM.sub("#", d)
    stem = f[: -len(".bytes")] if f.endswith(".bytes") else f
    m = re.match(r"([A-Za-z_]*?)(?:[_-]?\d.*)?((?:\.[A-Za-z_]+)*)$", stem)
    # filename shape: leading alpha prefix + secondary extensions (.layout/.partial)
    ext = "".join(re.findall(r"\.[A-Za-z_]+", stem))
    prefix = re.match(r"[A-Za-z]*", stem).group(0)
    if len(prefix) > 24:
        prefix = prefix[:24]
    return f"{d}/{prefix}*{ext}"


# calibration
cal = collections.Counter()
for r in rows:
    t = r["truth_type"]
    if not t or t not in roots:
        continue
    ti = roots.index(t)
    exact = set(r["exact"])
    gap = {i for i, _ in r["gap"]}
    cal["exact" if ti in exact else "gap" if ti in gap else "fail"] += 1
print("calibration (truth type status):", dict(cal))

fams = collections.defaultdict(list)
for r in rows:
    fams[family(r["path"])].append(r)

result = {}
for fam, members in fams.items():
    n = len(members)
    stat = collections.defaultdict(lambda: [0, 0, 0.0])  # exact, gap, gap-offset-fraction sum
    for r in members:
        for i in r["exact"]:
            stat[i][0] += 1
        for i, off in r["gap"]:
            stat[i][1] += 1
            stat[i][2] += off / max(r["size"], 1)
    cands = []
    for i, (e, g, frac) in stat.items():
        if e + g == n:  # never definitively rejected
            cands.append((e, frac, g, roots[i]))
    cands.sort(reverse=True)
    truth = collections.Counter(r["truth_type"] for r in members if r["truth_type"])
    covered = sum(1 for r in members if r["covered"])
    result[fam] = {
        "n": n,
        "covered": covered,
        "bytes": sum(r["size"] for r in members),
        "truth": truth.most_common(3),
        "cands": [(t, e, g, round(frac / max(g, 1), 3)) for e, frac, g, t in cands[:6]],
    }
json.dump(result, open(f"{W}/families.json", "w", encoding="utf-8"), indent=1)

# report: truth agreement where truth known, then biggest uncovered families
agree = collections.Counter()
for fam, v in result.items():
    if v["truth"]:
        top = v["cands"][0][0] if v["cands"] else None
        tt = v["truth"][0][0]
        agree["top==truth" if top == tt else "truth-in-cands" if any(c[0] == tt for c in v["cands"]) else "truth-missing"] += 1
print("families", len(result), "truth agreement", dict(agree))
limit = int(sys.argv[1]) if len(sys.argv) > 1 else 80
todo = sorted(((v["n"] - v["covered"], f) for f, v in result.items()), reverse=True)
for missing, fam in todo[:limit]:
    v = result[fam]
    c = [(t.replace("RPG.GameCore.", ""), e, g, fr) for t, e, g, fr in v["cands"][:4]]
    tr = [(t.replace("RPG.GameCore.", ""), k) for t, k in v["truth"]] if v["truth"] else ""
    print(f"{missing:6d}/{v['n']:<6d} {fam[:70]:70s} {tr} {c}")
