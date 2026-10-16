"""Iterative name recovery for DesignData entries.

Usage: .venv/Scripts/python.exe recover.py
Reads named.json (stage-1 output) and writes names_state.json + gap reports.
"""
import collections
import itertools
import json
import os
import re
import string
import sys
import time

import xxhash

import designindex as di

W = os.environ.get("HSR_INV_WORK", os.getcwd())
T0 = time.time()


def log(*a):
    print(f"[{time.time() - T0:7.1f}s]", *a, flush=True)


def h64(s):
    return xxhash.xxh64_intdigest(s.encode("utf-8"), 0)


# ---------------------------------------------------------------- snapshots
P = di.open_snapshot("Persistent")
S = di.open_snapshot("StreamingAssets")
ALL = {}
for h in P["entries"]:
    ALL[h] = "Persistent"
for h in S["entries"]:
    ALL.setdefault(h, "StreamingAssets")
log("index entries", len(ALL))

state_path = os.path.join(W, "names_state.json")
base_path = os.path.join(W, "named.json")
names, sources = {}, collections.defaultdict(set)
for path in (base_path, state_path):
    if os.path.exists(path):
        for k, v in json.load(open(path, encoding="utf-8")).items():
            h = int(k, 16)
            names[h] = v["path"]
            sources[h].update(v["sources"])
log("starting names", len(names))

stage_gain = collections.Counter()


def offer(path, source):
    h = h64(path)
    if h in ALL:
        if h not in names:
            names[h] = path
            sources[h].add(source)
            stage_gain[source] += 1
            return True
        sources[h].add(source)
    return False


def logical_variants(s):
    s = s.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    s = s.lstrip("/")
    if not s or len(s) > 400:
        return ()
    if s.startswith("BakedConfig/"):
        out = [s]
        if s.endswith(".json"):
            out.append(s[:-5] + ".bytes")
        return out
    if s.endswith(".json"):
        return ["BakedConfig/" + s[:-5] + ".bytes", "BakedConfig/" + s, s]
    if s.endswith(".bytes"):
        return ["BakedConfig/" + s, s]
    return ["BakedConfig/" + s + ".bytes", "BakedConfig/" + s + ".json"]


def offer_raw(s, source):
    hit = False
    for v in logical_variants(s):
        hit |= offer(v, source)
    return hit


def save():
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({f"{h:016x}": {"path": p, "sources": sorted(sources[h])}
                   for h, p in names.items()}, f, ensure_ascii=False)


# ------------------------------------------------------------ literal pools
literals = open(os.path.join(W, "script_strings.txt"), encoding="utf-8").read().splitlines()
payload = open(os.path.join(W, "candidates_payload.txt"), encoding="utf-8").read().splitlines()
log("literals", len(literals), "payload strings", len(payload))

# stage A: literals as direct paths / excel stems
for s in literals:
    if "/" in s or s.endswith((".json", ".bytes")):
        offer_raw(s, "script_literal")
    elif re.fullmatch(r"[A-Za-z0-9_]{2,80}", s):
        offer(f"BakedConfig/ExcelOutput/{s}.bytes", "script_literal_stem")
        offer(f"BakedConfig/ExcelOutputGameCore/{s}.bytes", "script_literal_stem")
for lang in ["en", "cn", "jp", "kr", "chs", "cht", "de", "es", "fr", "ru", "th", "vi", "pt", "id"]:
    for stem in [s for s in literals if re.fullmatch(r"Textmap\w*", s)] + ["Textmap", "TextmapMain"]:
        offer(f"BakedConfig/ExcelOutput/{stem}_{lang}.bytes", "textmap_literal")
log("after literals", len(names), dict(stage_gain))

# ------------------------------------------------------------ value pools
numbers = set()
tokens = set()
for p in itertools.chain(names.values(), payload, literals):
    for m in re.finditer(r"\d{1,12}", p):
        numbers.add(m.group())
for p in itertools.chain(names.values(), literals):
    for comp in re.split(r"[/\.]", p):
        if 1 < len(comp) <= 60 and re.fullmatch(r"[A-Za-z0-9_\-]+", comp):
            tokens.add(comp)
log("numbers", len(numbers), "tokens", len(tokens))

# stage B: literal format templates
templates = sorted({s for s in literals if "{0}" in s and re.search(r"(Config|Story|Stages|\.json|\.bytes)", s)
                    and len(s) < 200})
log("templates", len(templates))
for t in templates:
    slots = sorted(set(re.findall(r"\{(\d)\}", t)))
    if len(slots) == 1:
        pool = numbers | tokens if not re.search(r"[A-Za-z]\{0\}|\{0\}[A-Za-z]", t) else numbers | tokens
        for v in pool:
            offer_raw(t.replace("{0}", v), "literal_template")
    elif len(slots) == 2:
        # observed tuples from existing names matching the template
        rx = re.escape(t)
        rx = rx.replace(r"\{0\}", r"(?P<a>[^/]+?)").replace(r"\{1\}", r"(?P<b>[^/]+?)")
        rx = re.compile(r"^(?:BakedConfig/)?" + rx.replace(r"\.json", r"\.(?:json|bytes)") + r"$")
        pairs = set()
        for p in names.values():
            m = rx.match(p)
            if m:
                pairs.add((m.group("a"), m.group("b")))
        for v in numbers:
            pairs.add((v, v))
        for a, b in pairs:
            offer_raw(t.replace("{0}", a).replace("{1}", b), "literal_template")
log("after templates", len(names), dict(stage_gain))
save()

# ----------------------------------------------------------- gap analysis
PUNCT = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
WEIGHT = {c: i for i, c in enumerate(PUNCT, 1)}
for i, c in enumerate(string.digits + string.ascii_lowercase, len(PUNCT) + 1):
    WEIGHT[c] = i


def order_key(p):
    parts = p.split("/")
    return [(0 if i == len(parts) - 1 else 1, tuple(WEIGHT.get(ch, 1000 + ord(ch)) for ch in c.lower()))
            for i, c in enumerate(parts)]


def chunk_sequences():
    for snap in (P, S):
        byfile = collections.defaultdict(list)
        for h, (fno, off, size) in snap["entries"].items():
            byfile[fno].append((off, size, h))
        for fno, ents in byfile.items():
            ents.sort()
            yield snap["name"], fno, ents


SEG = re.compile(r"(\d+)")


def num_variants(sa, i, lo, hi):
    w = len(sa[i])
    for nv in range(max(lo, 0), hi + 1):
        s1 = str(nv)
        yield s1
        if len(s1) < w:
            yield s1.zfill(w)


def interp_candidates(a, b, reach=40, cap=5000):
    da, fa = a.rsplit("/", 1)
    sa = SEG.split(fa)
    for i in range(1, len(sa), 2):
        v = int(sa[i])
        for s_val in num_variants(sa, i, v - reach, v + reach):
            s2 = list(sa)
            s2[i] = s_val
            yield da + "/" + "".join(s2)
    if b:
        db, fb = b.rsplit("/", 1)
        sb = SEG.split(fb)
        if db == da and len(sa) == len(sb) and all(sa[j] == sb[j] for j in range(0, len(sa), 2)):
            diff = [j for j in range(1, len(sa), 2) if sa[j] != sb[j]]
            for i in diff:
                lo, hi = sorted((int(sa[i]), int(sb[i])))
                if hi - lo <= cap:
                    for base in (sa, sb):
                        for s_val in num_variants(base, i, lo, hi):
                            s2 = list(base)
                            s2[i] = s_val
                            yield da + "/" + "".join(s2)


def run_interpolation(label="interpolation", rounds=6):
    for r in range(rounds):
        gained = 0
        for snapname, fno, ents in chunk_sequences():
            prev = None
            pending = False
            for off, size, h in ents:
                nm = names.get(h)
                if nm is None:
                    pending = True
                    continue
                if pending:
                    if prev:
                        for c in interp_candidates(prev, nm):
                            gained += offer(c, label)
                    for c in interp_candidates(nm, None):
                        gained += offer(c, label)
                    pending = False
                prev = nm
            if pending and prev:
                for c in interp_candidates(prev, None):
                    gained += offer(c, label)
        log(f"{label} round {r}: +{gained} total={len(names)}")
        if not gained:
            break


run_interpolation()
save()

# ------------------------------------------- directory token substitution
EXTS = (".layout.bytes", ".bytes", ".json")


def split_name(fname):
    for e in EXTS:
        if fname.endswith(e):
            return fname[: -len(e)], e
    return fname, ""


def dir_token_substitution(max_dir=20000):
    """Within a directory that still has unnamed gaps, recombine observed name pieces."""
    gap_dirs = collections.Counter()
    for snapname, fno, ents in chunk_sequences():
        prev = None
        pending = 0
        for off, size, h in ents:
            nm = names.get(h)
            if nm is None:
                pending += 1
                continue
            if pending and prev:
                gap_dirs[prev.rsplit("/", 1)[0]] += pending
                gap_dirs[nm.rsplit("/", 1)[0]] += pending
            pending = 0
            prev = nm
    bydir = collections.defaultdict(list)
    for p in names.values():
        d, f = p.rsplit("/", 1)
        bydir[d].append(f)
    gained = 0
    budget = 30_000_000
    for d in gap_dirs:
        files = bydir.get(d, [])
        if not files or len(files) > max_dir:
            continue
        stems = [split_name(f) for f in files]
        exts = {e for _, e in stems} | {".bytes"}
        # last-token and first-token recombination only (bounded)
        heads_last, tails_last = set(), set()
        heads_first, tails_first = set(), set()
        for stem, _ in stems:
            if "_" in stem:
                a, b = stem.rsplit("_", 1)
                heads_last.add(a)
                tails_last.add(b)
                a, b = stem.split("_", 1)
                heads_first.add(a)
                tails_first.add(b)
        for heads, tails in ((heads_last, tails_last), (heads_first, tails_first)):
            n = len(heads) * len(tails) * len(exts)
            if n > 300_000 or n > budget:
                continue
            budget -= n
            for hd in heads:
                for tl in tails:
                    for e in exts:
                        gained += offer(f"{d}/{hd}_{tl}{e}", "dir_recombine")
    log(f"dir_recombine: +{gained} total={len(names)} dirs={len(gap_dirs)} budget_left={budget}")
    return gained


for r in range(3):
    if not dir_token_substitution():
        break
    run_interpolation("interpolation2", rounds=3)
save()

# --------------------------------------------------------------- report
unnamed = [h for h in ALL if h not in names]
log("FINAL named", len(names), "of", len(ALL), f"({len(names) / len(ALL):.1%}) unnamed", len(unnamed))
log("gains by stage", dict(stage_gain))
