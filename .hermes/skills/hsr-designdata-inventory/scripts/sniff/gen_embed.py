"""Generate HSR-OWNER embedded DesignData tables.

Outputs (into crates/dumper/resources/designdata/):
  names.lz4   sorted logical paths, front-coded ("<shared>\\t<suffix>\\n"),
              LZ4 block with 4-byte LE size prefix (lz4_flex compatible)
  rules.tsv   family key \\t loader candidates (|-separated) \\t evidence
"""
import collections
import csv
import json
import os
import re
import sys

import lz4.block

W = os.environ.get("HSR_INV_WORK", ".")
S = W + "/sniff"
INV = os.path.join(os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta"), "HSR-OWNER/designdata-inventory/designdata_inventory.csv")
OUT = sys.argv[1] if len(sys.argv) > 1 else r"D:/Projects/HSR-Projects/HSR-OWNER/crates/dumper/resources/designdata"
os.makedirs(OUT, exist_ok=True)

# ---------------------------------------------------------------- names
names = set()
with open(INV, encoding="utf-8-sig") as f:
    for row in csv.DictReader(f):
        if row["logical_path"]:
            names.add(row["logical_path"])
names = sorted(names)
lines, prev = [], ""
for n in names:
    shared = 0
    for a, b in zip(prev, n):
        if a != b:
            break
        shared += 1
    lines.append(f"{shared}\t{n[shared:]}\n")
    prev = n
blob = "".join(lines).encode("utf-8")
packed = lz4.block.compress(blob, store_size=True, mode="high_compression", compression=12)
open(f"{OUT}/names.lz4", "wb").write(packed)
print(f"names {len(names)} front-coded {len(blob)} lz4 {len(packed)}")

# ---------------------------------------------------------------- rules
fams = json.load(open(f"{S}/families.json", encoding="utf-8"))
auto = json.load(open(f"{S}/rules_auto.json", encoding="utf-8"))
loader_types = json.load(open(f"{S}/loader_types.json", encoding="utf-8"))
type_loaders = collections.defaultdict(list)
for loader, ty in sorted(loader_types.items()):
    type_loaders[ty].append(loader)

# Directory defaults: the client's naming of these trees matches the loaded type.
DEFAULTS = [
    ("Config/ConfigEntity/", "LoadEntityConfig"),
    ("Config/ConfigAnimEvents/", "LoadCharacterAnimEventConfig"),
    ("Config/Activity/RtBattle/AnimEvents/", "LoadCharacterAnimEventConfig"),
    ("Config/ConfigAI/ComplexSkillAIGlobalGroup/", "LoadComplexSkillAIGlobalGroupLookup"),
    ("Config/ConfigAI/", "LoadAIConfig"),
    ("Config/ConfigAnimZone/", "LoadAnimatorZoneConfig"),
    ("Config/ConfigFreeStyle/StateInfo/", "LoadFreeStyleStateConfig"),
    ("Config/ConfigFreeStyle/TransitionInfo/", "LoadFreeStyleTransitionInfoConfig"),
    ("Config/ConfigFreeStyle/StateGraph/", "LoadFreeStyleTriggerGraphTemplateConfig"),
    ("Config/ConfigFreeStyle/AnimDesignerEventBakedInfoConfig/", "LoadFreeStyleAnimEventInfoConfig"),
    ("Config/ConfigFreeStyle/AnimAudioEventInfoConfig/", "LoadFreeStyleAnimEventInfoConfig"),
    ("Config/ConfigBooklet/", "LoadSectionConfig"),
    ("Config/ConfigPlayerOutfit/", "LoadAvatarOutfitModelConfig"),
    ("Config/ConfigActivityClockPark/", "LoadClockParkStoryConfig"),
    ("Config/Gameplays/Fate/MasterConfig/", "LoadFateMasterConfig"),
    ("Config/Gameplays/Fate/TraitConfig/", "LoadFateTraitConfig"),
    ("Config/Gameplays/Fate/ReijuConfig/", "LoadFateContentConfig"),
    ("Config/Level/", "LoadLevelGraphConfig"),
    ("Story/", "LoadLevelGraphConfig"),
]
EXTRA = json.load(open(f"{S}/extra_defaults.json", encoding="utf-8")) if os.path.exists(f"{S}/extra_defaults.json") else []
DEFAULTS = [tuple(x) for x in EXTRA] + DEFAULTS

CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+")


def tokens(text):
    out = set()
    for part in re.split(r"[/_.\-#*]+", text):
        for t in CAMEL.findall(part):
            t = t.lower()
            if len(t) > 2 and t not in {"config", "json", "bytes"}:
                out.add(t.rstrip("s"))
    return out


def token_score(fam, ty):
    a = tokens(fam.split("/", 1)[1] if "/" in fam else fam)
    b = tokens(ty.rsplit(".", 1)[-1])
    return len(a & b) / max(len(b), 1)


rules = {}
for fam, r in auto.items():
    rules[fam] = ([r["loader"]], r["why"])
for fam, v in fams.items():
    if v["covered"] == v["n"] or fam in rules:
        continue
    json_prefix = fam  # family keys are JSON-domain style without BakedConfig/
    cands, why = [], []
    for prefix, loader in DEFAULTS:
        if json_prefix.startswith(prefix):
            cands.append(loader)
            why.append(f"dir:{prefix}")
            break
    exact_cands = [(ty, exact) for ty, exact, gap, _ in v["cands"] if exact > 0 and type_loaders.get(ty)]
    top_exact = exact_cands[0][1] if exact_cands else 0
    # Tiny/empty files decode under many types; then the sniff carries no type information.
    informative = exact_cands and sum(1 for _, e in exact_cands if e == top_exact) <= 2
    scored = sorted(((token_score(fam, ty), ty) for ty in type_loaders), reverse=True)
    name_pick = scored[0][1] if scored and scored[0][0] >= 0.66 else None
    if informative:
        for ty, exact in exact_cands[:2]:
            cands.append(type_loaders[ty][0])
            why.append(f"sniff:{ty.rsplit('.', 1)[-1]}={exact}")
    if name_pick:
        cands.append(type_loaders[name_pick][0])
        why.append(f"name:{name_pick.rsplit('.', 1)[-1]}")
    seen, ordered = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    if ordered:
        rules[fam] = (ordered[:3], ";".join(why[:3]))

# Families the runtime Config step already covers keep their observed loader, so the
# inventory step still decodes them when a later client drops a discovery route.
truth_loaders = collections.Counter()
for line in open(f"{S}/sniff_all.jsonl", encoding="utf-8"):
    r = json.loads(line)
    if r["truth"]:
        truth_loaders[(r["truth_type"], r["truth"])] += 1
covered_rules = 0
for fam, v in fams.items():
    if fam in rules or not v["truth"]:
        continue
    ty = v["truth"][0][0]
    used = [l for (t, l), _ in truth_loaders.most_common() if t == ty]
    loader = used[0] if used else (type_loaders.get(ty) or [None])[0]
    if loader:
        rules[fam] = ([loader], f"runtime truth {ty}")
        covered_rules += 1
print("rules for runtime-covered families", covered_rules)
OVERRIDES = [
    ("Config/LevelOutput/HeartDial/HeartDial_Floor_", "LoadGameLevelHeartDialConfigCollection"),
    ("Config/LevelOutput/HeartDial/HeartDial_Script_", "LoadGameLevelHeartDialScriptConfig"),
]
with open(f"{OUT}/rules.tsv", "w", encoding="utf-8", newline="\n") as f:
    f.write("# kind\tkey\tloaders\tevidence\n")
    f.write("# O = JSON path prefix override (checked first), F = family key, D = JSON path prefix default (longest wins, checked last)\n")
    f.write("# generated by gen_embed.py from typesniff exact decodes, runtime loader log and client xrefs\n")
    for prefix, loader in OVERRIDES:
        f.write(f"O\t{prefix}\t{loader}\tclient xref HeartDialModule\n")
    for fam in sorted(rules):
        loaders, why = rules[fam]
        f.write(f"F\t{fam}\t{'|'.join(loaders)}\t{why}\n")
    for prefix, loader in DEFAULTS:
        f.write(f"D\t{prefix}\t{loader}\tdirectory default\n")
missing_total = sum(v["n"] - v["covered"] for v in fams.values())
ruled = sum(fams[f]["n"] - fams[f]["covered"] for f in rules if f in fams)
print(f"rules {len(rules)} covering {ruled}/{missing_total} uncovered entries")
unruled = sorted(((v["n"] - v["covered"], f) for f, v in fams.items() if v["covered"] < v["n"] and f not in rules), reverse=True)
print("unruled families", len(unruled), "entries", sum(m for m, _ in unruled))
for m, f in unruled[:40]:
    print(f"  {m:5d} {f}")
