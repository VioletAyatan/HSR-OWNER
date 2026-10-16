"""Stage C2: interval-constrained dictionary attack (fast keys, bounded)."""
import bisect
import collections
import os
import re

import lib

st = lib.Store()
W = lib.W

payload_tokens = open(os.path.join(W, "tokens_payload.txt"), encoding="utf-8").read().split("\n")
literals = open(os.path.join(W, "script_strings.txt"), encoding="utf-8").read().splitlines()


def split_ext(fname):
    i = fname.find(".")
    return (fname, "") if i < 0 else (fname[:i], fname[i:])


def build():
    bydir = collections.defaultdict(list)
    for p in st.names.values():
        d, f = p.rsplit("/", 1)
        bydir[d].append(f)
    suf_by_dir = {}
    for d, files in bydir.items():
        cnt = collections.Counter()
        for f in files:
            stem, _ = split_ext(f)
            for m in re.finditer(r"_", stem):
                cnt[stem[m.start():]] += 1
        suf_by_dir[d] = {s for s, c in cnt.most_common(25) if c >= 2 and len(s) <= 40}
    bases = set()
    for d, files in bydir.items():
        sufs = suf_by_dir[d]
        for f in files:
            stem, _ = split_ext(f)
            bases.add(stem)
            for m in re.finditer(r"_", stem):
                if stem[m.start():] in sufs:
                    bases.add(stem[: m.start()])
    for s in literals:
        if re.fullmatch(r"[A-Za-z0-9_\-]{2,120}", s):
            bases.add(s)
    bases.update(payload_tokens)
    bases.discard("")
    lower_sorted = sorted({b.lower() for b in bases})
    variants = collections.defaultdict(list)
    for b in bases:
        variants[b.lower()].append(b)
    lib.log("dictionary: dirs", len(bydir), "bases", len(bases))
    return bydir, suf_by_dir, lower_sorted, variants


def with_prefix(lower_sorted, variants, prefix, cap):
    lo = bisect.bisect_left(lower_sorted, prefix)
    hi = bisect.bisect_left(lower_sorted, prefix + "\uffff")
    if hi - lo > cap:
        return None
    out = []
    for i in range(lo, hi):
        out.extend(variants[lower_sorted[i]])
    return out


def common_prefix(a, b):
    a, b = a.lower(), b.lower()
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    return a[:i]


def attack(d, lo, hi, prefix, cap, label, ctx):
    bydir, suf_by_dir, lower_sorted, variants = ctx
    cand = with_prefix(lower_sorted, variants, prefix, cap)
    if not cand:
        return
    sufs = suf_by_dir.get(d, set()) | {""}
    exts = {split_ext(f)[1] for f in bydir.get(d, [])} | {".bytes"}
    klo = lib.name_key(lo) if lo else None
    khi = lib.name_key(hi) if hi else None
    budget = 60_000
    for base in cand:
        for suf in sufs:
            stem = base + suf
            for ext in exts:
                name = stem + ext
                k = lib.name_key(name)
                if (klo is None or klo < k) and (khi is None or k < khi):
                    st.offer(f"{d}/{name}", label)
                budget -= 1
        if budget <= 0:
            return


for rnd in range(3):
    ctx = build()
    before = len(st.names)
    gaps = list(st.gaps())
    for i, (prev, nxt, k) in enumerate(gaps):
        if i % 200 == 0:
            lib.log(f"round {rnd} gap {i}/{len(gaps)} named={len(st.names)}")
        if prev is None:
            continue
        dp, fp = prev.rsplit("/", 1)
        dn, fn = nxt.rsplit("/", 1) if nxt else (None, None)
        if dn == dp:
            cp = common_prefix(split_ext(fp)[0], split_ext(fn)[0])
            if len(cp) >= 2:
                attack(dp, fp, fn, cp, 30000, "interval_same_dir", ctx)
            for f in (fp, fn):
                first = split_ext(f)[0].split("_")[0].lower()
                if len(first) >= 2 and first != cp:
                    attack(dp, fp, fn, first, 4000, "interval_same_dir_weak", ctx)
        else:
            first = split_ext(fp)[0].split("_")[0].lower()
            if len(first) >= 2:
                attack(dp, fp, None, first, 4000, "interval_dir_tail", ctx)
            if fn:
                first = split_ext(fn)[0].split("_")[0].lower()
                if len(first) >= 2:
                    attack(dn, None, fn, first, 4000, "interval_dir_head", ctx)
    lib.log(f"round {rnd}: +{len(st.names) - before}", dict(st.gain))
    st.save()
    lib.transforms(st)
    lib.interpolation(st)
    if len(st.names) == before:
        break
st.save()
