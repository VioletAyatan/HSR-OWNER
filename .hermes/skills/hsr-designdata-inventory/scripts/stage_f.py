"""Stage F: Excel roots from class names, sorted-key interval attack with a large
dictionary (names, literals, payload tokens, dump.cs identifiers), and numeric
skeleton brute force between same-shaped neighbours."""
import bisect
import collections
import os
import re

import lib

st = lib.Store()
W = lib.W
nk = lib.name_key


def split_ext(fname):
    i = fname.find(".")
    return (fname, "") if i < 0 else (fname[:i], fname[i:])


# ---------------------------------------------------------------- (a) Excel roots
roots = ["ExcelOutput", "ExcelOutputGameCore", "ExcelOutputAdventureGame"]
excel_stems = open(os.path.join(W, "excel_table_stems.txt"), encoding="utf-8").read().split("\n")
literals = open(os.path.join(W, "script_strings.txt"), encoding="utf-8").read().splitlines()
ident = [w for w in open(os.path.join(W, "dumpcs_identifiers.txt"), encoding="utf-8").read().split("\n")
         if not re.fullmatch(r"[A-Z]{11}", w)]
payload_tokens = open(os.path.join(W, "tokens_payload.txt"), encoding="utf-8").read().split("\n")
lib.log("dump.cs identifiers (non-obfuscated)", len(ident))
for s in excel_stems:
    for r in roots:
        st.offer(f"BakedConfig/{r}/{s}.bytes", "excel_class_stem")
        st.offer(f"BakedConfig/{r}/{s}ExcelTable.binary_header.bytes", "excel_class_stem")
for s in set(ident) | {x for x in literals if re.fullmatch(r"[A-Za-z0-9_]{2,100}", x)}:
    for r in roots:
        st.offer(f"BakedConfig/{r}/{s}.bytes", "excel_identifier")
lib.log("after excel roots", len(st.names), dict(st.gain))

# ------------------------------------------------- (b) sorted-key interval attack
words = set(ident)
words.update(x for x in literals if re.fullmatch(r"[A-Za-z0-9_\-\. ()]{2,120}", x))
words.update(payload_tokens)
for p in st.names.values():
    stem, _ = split_ext(p.rsplit("/", 1)[1])
    words.add(stem)
    for m in re.finditer(r"_", stem):
        words.add(stem[: m.start()])
words.discard("")
pairs = sorted((nk(w), w) for w in words)
keys = [k for k, _ in pairs]
by_key = collections.defaultdict(list)
for k, w in pairs:
    by_key[k].append(w)
lib.log("dictionary words", len(pairs))


def dir_tables():
    bydir = collections.defaultdict(list)
    for p in st.names.values():
        d, f = p.rsplit("/", 1)
        bydir[d].append(f)
    sufs, exts = {}, {}
    for d, files in bydir.items():
        cnt = collections.Counter()
        e = {".bytes"}
        for f in files:
            stem, ext = split_ext(f)
            e.add(ext or ".bytes")
            for m in re.finditer(r"_", stem):
                cnt[stem[m.start():]] += 1
        sufs[d] = [s for s, c in cnt.most_common(12) if c >= 2 and len(s) <= 40]
        exts[d] = sorted(e)
    return sufs, exts


def attack(d, lo, hi, sufs, exts, label, budget=300_000):
    klo = nk(lo) if lo else ""
    khi = nk(hi) if hi else None
    i0 = bisect.bisect_right(keys, klo)
    i1 = bisect.bisect_left(keys, khi) if khi is not None else len(keys)
    bases = []
    for n in range(1, len(klo) + 1):  # prefixes of the lower bound
        bases.extend(by_key.get(klo[:n], ()))
    span = i1 - i0
    use_sufs = [""] + (sufs if span < 20000 else [])
    if span * len(use_sufs) * len(exts) > budget:
        i1 = i0 + max(1, budget // (len(use_sufs) * len(exts)))
    for i in range(i0, min(i1, len(pairs))):
        bases.append(pairs[i][1])
    for b in bases:
        for s in use_sufs:
            for e in exts:
                name = b + s + e
                k = nk(name)
                if k > klo and (khi is None or k < khi):
                    st.offer(f"{d}/{name}", label)


def interval_round():
    sufs, exts = dir_tables()
    before = len(st.names)
    gaps = list(st.gaps())
    for n, (prev, nxt, k) in enumerate(gaps):
        if n % 300 == 0:
            lib.log(f"interval gap {n}/{len(gaps)} named={len(st.names)}")
        if not prev:
            continue
        dp, fp = prev.rsplit("/", 1)
        if nxt:
            dn, fn = nxt.rsplit("/", 1)
        if nxt and dn == dp:
            attack(dp, fp, fn, sufs.get(dp, []), exts.get(dp, [".bytes"]), "interval2_same_dir")
        else:
            attack(dp, fp, None, sufs.get(dp, []), exts.get(dp, [".bytes"]), "interval2_dir_tail", 60_000)
            if nxt:
                attack(dn, None, fn, sufs.get(dn, []), exts.get(dn, [".bytes"]), "interval2_dir_head", 60_000)
    lib.log(f"interval round: +{len(st.names) - before}", dict(st.gain))
    return len(st.names) - before


# ------------------------------------------------ (c) numeric skeleton brute force
SEG = re.compile(r"(\d+)")


def numeric_round(cap1=3_000_000, cap2=4_000_000):
    observed = collections.defaultdict(set)  # (dir, skeleton, slot) -> values
    for p in st.names.values():
        d, f = p.rsplit("/", 1)
        parts = SEG.split(f)
        skel = tuple(parts[0::2])
        for i in range(1, len(parts), 2):
            observed[(d, skel, i)].add(parts[i])
    before = len(st.names)
    for prev, nxt, k in list(st.gaps()):
        if not prev or not nxt:
            continue
        dp, fp = prev.rsplit("/", 1)
        dn, fn = nxt.rsplit("/", 1)
        if dp != dn:
            continue
        a, b = SEG.split(fp), SEG.split(fn)
        if len(a) != len(b) or a[0::2] != b[0::2]:
            continue
        skel = tuple(a[0::2])
        diff = [i for i in range(1, len(a), 2) if a[i] != b[i]]
        if len(diff) == 1:
            i = diff[0]
            lo, hi = sorted((int(a[i]), int(b[i])))
            if hi - lo > cap1:
                continue
            w = len(a[i]) if len(a[i]) == len(b[i]) else 0
            for v in range(lo + 1, hi):
                s = str(v).zfill(w) if w else str(v)
                c = list(a)
                c[i] = s
                st.offer(f"{dp}/{''.join(c)}", "numeric_range")
        elif len(diff) == 2:
            i, j = diff
            lo, hi = sorted((int(a[i]), int(b[i])))
            vals_i = sorted({int(x) for x in observed[(dp, skel, i)] if lo <= int(x) <= hi})
            if len(vals_i) < 2 and hi - lo <= 2000:
                vals_i = list(range(lo, hi + 1))
            obs_j = [int(x) for x in observed[(dp, skel, j)]]
            top = min(max(obs_j) + 50 if obs_j else 1000, 5000)
            if len(vals_i) * top > cap2:
                continue
            wi = len(a[i]) if len(a[i]) == len(b[i]) else 0
            for vi in vals_i:
                for vj in range(0, top + 1):
                    c = list(a)
                    c[i] = str(vi).zfill(wi) if wi else str(vi)
                    c[j] = str(vj)
                    st.offer(f"{dp}/{''.join(c)}", "numeric_product")
    lib.log(f"numeric round: +{len(st.names) - before}", dict(st.gain))
    return len(st.names) - before


for r in range(3):
    g = numeric_round()
    g += interval_round()
    lib.transforms(st)
    lib.interpolation(st)
    st.save()
    if not g:
        break
