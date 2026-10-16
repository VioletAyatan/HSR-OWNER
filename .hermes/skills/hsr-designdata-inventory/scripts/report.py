"""Build the DesignData inventory deliverables from names_state.json."""
import collections
import csv
import datetime
import json
import os
import re
import sys

import lib

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(lib.W, "out")
os.makedirs(OUT, exist_ok=True)
st = lib.Store()
LOG = os.path.join(os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta"), "hsr-owner.log")

# ---- runtime Resources coverage (latest finished run in hsr-owner.log)
loaded_json, excel_written, textmap_written = set(), set(), 0
run_lines = []
with open(LOG, encoding="utf-8", errors="replace") as f:
    for line in f:
        if "[Resources #" in line:
            run_lines.append(line)
start = max(i for i, l in enumerate(run_lines) if re.search(r"\[Resources #\d+\] start", l))
run_id = re.search(r"\[Resources #(\d+)\]", run_lines[start]).group(1)
finished = [l for l in run_lines[start:] if f"[Resources #{run_id}] finished" in l]
for l in run_lines[start:]:
    m = re.search(r"begin Config: load \w+ path=(\S+)", l)
    if m:
        loaded_json.add(m.group(1))
    m = re.search(r"end stream table .* -> \./DUMP/Resources/ExcelOutput/(.+)\.json", l)
    if m:
        excel_written.add(m.group(1))
    m = re.search(r"end ExcelOutput: reuse runtime table .* -> \./DUMP/Resources/ExcelOutput/(.+)\.json", l)
    if m:
        excel_written.add(m.group(1))
lib.log("runtime run", run_id, "finished" if finished else "unfinished", "loaded configs", len(loaded_json),
        "excel files", len(excel_written))


def json_domain(logical):
    if logical.startswith("BakedConfig/ExcelOutput"):
        return None
    if logical.startswith("BakedConfig/") and logical.endswith(".bytes"):
        return logical[len("BakedConfig/"):-len(".bytes")] + ".json"
    return None


def category(logical):
    parts = logical.split("/")
    if parts[0] == "BakedConfig":
        parts = parts[1:]
    if parts and parts[0] == "Config":
        return "/".join(parts[:2]) if len(parts) > 2 else "Config (root files)"
    if parts and parts[0].startswith("ExcelOutput"):
        stem = parts[-1]
        return "TextMap" if stem.startswith("Textmap") else parts[0]
    return "/".join(parts[:2]) if len(parts) > 2 else parts[0]


def kind(logical):
    if ".partial.layout." in logical:
        return "partial-layout"
    if ".layout." in logical:
        return "bake-layout"
    if ".partial." in logical:
        return "mission-partial"
    if ".binary_header." in logical:
        return "binary-header"
    return "data"


def runtime_covered(logical):
    if logical is None:
        return ""
    parts = logical.split("/")
    if len(parts) == 3 and parts[1].startswith("ExcelOutput"):
        stem = parts[2][:-len(".bytes")] if parts[2].endswith(".bytes") else parts[2]
        if stem.startswith("Textmap"):
            return "active-language-only" if stem.startswith("Textmap_") else "no"
        return "yes" if stem in excel_written else "no"
    jd = json_domain(logical)
    if jd and jd in loaded_json:
        return "yes"
    return "no"


# neighbour directory for unnamed entries
near = {}
for _, _, ents in st.sequences():
    named_pos = [i for i, e in enumerate(ents) if e[2] in st.names]
    prev = None
    for i, (off, size, h) in enumerate(ents):
        if h in st.names:
            prev = st.names[h]
            continue
        nxt = next((st.names[e[2]] for e in ents[i + 1:] if e[2] in st.names), None)
        a = prev.rsplit("/", 1)[0] if prev else None
        b = nxt.rsplit("/", 1)[0] if nxt else None
        if a and b:
            pa, pb = a.split("/"), b.split("/")
            n = 0
            while n < min(len(pa), len(pb)) and pa[n] == pb[n]:
                n += 1
            near[h] = "/".join(pa[:n]) or "?"
        else:
            near[h] = a or b or "?"

rows = []
for snap in (st.P, st.S):
    for h, (fno, off, size) in snap["entries"].items():
        fi = snap["files"][fno]
        logical = st.names.get(h)
        rows.append({
            "snapshot": snap["name"],
            "revision": snap["revision"],
            "path_hash": f"{h:016x}",
            "chunk": fi["digest"],
            "tag": fi["tag"] or "",
            "chunk_present": "yes" if fi["path"] else "no",
            "offset": off,
            "size": size,
            "logical_path": logical or "",
            "json_path": (json_domain(logical) or "") if logical else "",
            "kind": kind(logical) if logical else "",
            "category": category(logical) if logical else "",
            "unnamed_near_dir": "" if logical else near.get(h, "?"),
            "recovered_by": ";".join(sorted(st.sources.get(h, ()))) if logical else "",
            "runtime_dump_2026-10-08": runtime_covered(logical) if logical else "unknown",
        })
rows.sort(key=lambda r: (r["snapshot"] != "Persistent", r["chunk"], r["offset"]))
csv_path = os.path.join(OUT, "designdata_inventory.csv")
with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
lib.log("csv rows", len(rows), csv_path)
with open(os.path.join(OUT, "unnamed_entries.csv"), "w", encoding="utf-8-sig", newline="") as f:
    cols = ["snapshot", "path_hash", "chunk", "tag", "offset", "size", "unnamed_near_dir"]
    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    w.writerows(r for r in rows if not r["logical_path"])
with open(os.path.join(OUT, "not_in_runtime_dump.csv"), "w", encoding="utf-8-sig", newline="") as f:
    cols = ["category", "logical_path", "json_path", "size", "path_hash"]
    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    w.writerows(sorted((r for r in rows if r["snapshot"] == "Persistent" and r["logical_path"]
                        and r["kind"] == "data" and r["runtime_dump_2026-10-08"] == "no"),
                       key=lambda r: r["logical_path"].lower()))

# ---- summary
P = [r for r in rows if r["snapshot"] == "Persistent"]
S = [r for r in rows if r["snapshot"] == "StreamingAssets"]
named = [r for r in P if r["logical_path"]]
unnamed = [r for r in P if not r["logical_path"]]
summary = {
    "generated": datetime.datetime.now().isoformat(timespec="seconds"),
    "persistent": {"revision": st.P["revision"], "index": st.P["index_digest"], "entries": len(P),
                   "bytes": sum(r["size"] for r in P), "named": len(named), "unnamed": len(unnamed),
                   "unnamed_bytes": sum(r["size"] for r in unnamed),
                   "chunks": len(st.P["files"]),
                   "missing_chunks": [(fi["digest"], fi["tag"], fi["count"]) for fi in st.P["files"] if not fi["path"]]},
    "streaming": {"revision": st.S["revision"], "entries": len(S), "named": sum(1 for r in S if r["logical_path"]),
                  "not_in_persistent": sum(1 for r in S if int(r["path_hash"], 16) not in st.P["entries"])},
    "runtime_run": run_id,
}
cat = collections.defaultdict(lambda: collections.Counter())
for r in named:
    c = cat[r["category"]]
    c["entries"] += 1
    c["bytes"] += r["size"]
    c[r["kind"]] += 1
    if r["runtime_dump_2026-10-08"].startswith("yes"):
        c["runtime_yes"] += 1
    elif r["kind"] == "data":
        c["runtime_no_data"] += 1
near_c = collections.Counter(r["unnamed_near_dir"] for r in unnamed)
near_b = collections.Counter()
for r in unnamed:
    near_b[r["unnamed_near_dir"]] += r["size"]
src_c = collections.Counter()
for r in named:
    for s in r["recovered_by"].split(";"):
        src_c[s] += 1
summary["categories"] = {k: dict(v) for k, v in sorted(cat.items(), key=lambda kv: -kv[1]["entries"])}
summary["unnamed_by_dir"] = near_c.most_common()
summary["sources"] = src_c.most_common()
json.dump(summary, open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
lib.log("summary written", OUT)
print(json.dumps({k: summary[k] for k in ("persistent", "streaming")}, ensure_ascii=False, indent=1))
for k, v in list(summary["categories"].items())[:40]:
    print(f"{v['entries']:7d} {v['bytes'] / 1e6:8.1f}MB data={v.get('data', 0):6d} layout={v.get('bake-layout', 0):5d} "
          f"rt_yes={v.get('runtime_yes', 0):6d} rt_no_data={v.get('runtime_no_data', 0):6d}  {k}")
print("unnamed by dir (top 25):")
for d, n in near_c.most_common(25):
    print(f"  {n:6d} {near_b[d] / 1e6:6.2f}MB {d}")
