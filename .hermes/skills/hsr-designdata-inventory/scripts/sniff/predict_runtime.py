"""Predict the inventory step's decode outcome from the offline strict parser.

For every sniffed entry, apply the embedded rules exactly like the dumper
(override -> family -> layout -> directory default), map each loader to its
root type and check whether the strict offline parser decoded the entry
exactly with that type.
"""
import collections
import json
import os
import re
import sys

S = os.path.join(os.environ.get("HSR_INV_WORK", "."), "sniff")
RULES = sys.argv[1] if len(sys.argv) > 1 else r"D:/Projects/HSR-Projects/HSR-OWNER/crates/dumper/resources/designdata/rules.tsv"
roots = json.load(open(f"{S}/roots.json", encoding="utf-8"))
loader_types = json.load(open(f"{S}/loader_types.json", encoding="utf-8"))
root_index = {t: i for i, t in enumerate(roots)}

overrides, families, defaults = [], {}, []
for line in open(RULES, encoding="utf-8"):
    if line.startswith("#") or not line.strip():
        continue
    kind, key, loaders, *_ = line.rstrip("\n").split("\t")
    loaders = [l for l in loaders.split("|") if l]
    if kind == "O":
        overrides.append((key, loaders))
    elif kind == "F":
        families[key] = loaders
    elif kind == "D":
        defaults.append((key, loaders))
overrides.sort(key=lambda x: -len(x[0]))
defaults.sort(key=lambda x: -len(x[0]))

NUM = re.compile(r"\d+")


def family(path):
    p = path[len("BakedConfig/"):]
    d, f = p.rsplit("/", 1) if "/" in p else ("", p)
    d = NUM.sub("#", d)
    stem = f[: -len(".bytes")] if f.endswith(".bytes") else f
    ext = "".join(re.findall(r"\.[A-Za-z_]+", stem))
    prefix = re.match(r"[A-Za-z]*", stem).group(0)[:24]
    return f"{d}/{prefix}*{ext}"


def candidates(path):
    json_path = path[len("BakedConfig/"):-len(".bytes")] + ".json"
    for prefix, loaders in overrides:
        if json_path.startswith(prefix):
            return loaders, "override"
    fam = family(path)
    if fam in families:
        return families[fam], "family"
    if ".layout." in json_path.rsplit("/", 1)[-1]:
        return ["LoadConfigBakeLayoutInfoList"], "layout"
    for prefix, loaders in defaults:
        if json_path.startswith(prefix):
            return loaders, "default"
    return None, None


outcome = collections.Counter()
attempts = collections.Counter()
by_dir = collections.defaultdict(collections.Counter)
truth_check = collections.Counter()
for line in open(f"{S}/sniff_all.jsonl", encoding="utf-8"):
    r = json.loads(line)
    path = r["path"]
    if not path.startswith("BakedConfig/") or not path.endswith(".bytes") or "/ExcelOutput" in path:
        continue
    loaders, why = candidates(path)
    exact = set(r["exact"])
    top = "/".join(path.split("/")[1:4])
    if loaders is None:
        state = "no-rule"
    else:
        state = "rejected-all"
        for i, loader in enumerate(loaders):
            ty = loader_types.get(loader)
            attempts["tries"] += 1
            if ty in root_index and root_index[ty] in exact:
                state = f"exact@{i + 1}"
                break
            if ty not in root_index:
                state = "type-unknown"
                break
    if r["truth"]:
        # Runtime truth: the loader used at runtime for this very path.
        first = loaders[0] if loaders else None
        truth_check["first==truth" if first == r["truth"] else "first!=truth"] += 1
    key = ("covered" if r["covered"] else "uncovered", state)
    outcome[key] += 1
    if not r["covered"]:
        by_dir[top][state] += 1

for k, v in sorted(outcome.items()):
    print(f"{v:7d} {k}")
print("attempts", dict(attempts))
print("truth check", dict(truth_check))
print("\nuncovered entries not exact with any candidate, by directory:")
rows = sorted(((sum(c.values()) - c.get("exact@1", 0) - c.get("exact@2", 0) - c.get("exact@3", 0), d, dict(c)) for d, c in by_dir.items()), reverse=True)
for miss, d, c in rows[:25]:
    if miss:
        print(f"  {miss:6d} {d:60s} {c}")
