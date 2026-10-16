"""Stage G: numeric template instantiation.

G1  tuple harvesting: for multi-slot file-name skeletons (e.g. Group_F#_G#,
    CrossMapBriefInfo_P#_F#), harvest slot tuples from every token in the corpus
    that contains the skeleton core (F(\\d+)_G(\\d+)) and instantiate.
G2  related-slot templates: full-path skeletons whose slots are equal or
    prefix-related (Mission/{A}/Mission_{A..}) instantiated from the number pool.
"""
import collections
import os
import re

import lib

st = lib.Store()
W = lib.W
SEG = re.compile(r"(\d+)")

payload_tokens = open(os.path.join(W, "tokens_payload.txt"), encoding="utf-8").read().split("\n")
literals = open(os.path.join(W, "script_strings.txt"), encoding="utf-8").read().splitlines()
corpus = set(payload_tokens)
corpus.update(literals)
corpus.update(p.rsplit("/", 1)[1] for p in st.names.values())
corpus_text = "\n".join(corpus)
numbers = set(re.findall(r"\d{3,12}", corpus_text))
numbers.update(re.findall(r"\d{3,12}", "\n".join(st.names.values())))
lib.log("corpus tokens", len(corpus), "numbers", len(numbers))

gap_dirs = set()
for prev, nxt, k in st.gaps():
    for p in (prev, nxt):
        if p:
            d = p.rsplit("/", 1)[0]
            gap_dirs.add(d)
            gap_dirs.add(d.rsplit("/", 1)[0])
lib.log("gap dirs", len(gap_dirs))


def g1():
    before = len(st.names)
    skels = collections.defaultdict(set)  # (dir, parts-tuple) -> example
    for p in st.names.values():
        d, f = p.rsplit("/", 1)
        if d not in gap_dirs:
            continue
        parts = SEG.split(f)
        if 5 <= len(parts) <= 7:  # 2 or 3 numeric slots
            skels[(d, tuple(parts[0::2]))].add(f)
    lib.log("g1 skeletons", len(skels))
    done_core = {}
    for (d, lits), examples in skels.items():
        # core: last 2 chars of first literal + middle literals
        head = lits[0][-2:] if len(lits[0]) >= 2 else lits[0]
        core = re.escape(head) + r"(\d+)" + "".join(re.escape(x) + r"(\d+)" for x in lits[1:-1])
        if core not in done_core:
            done_core[core] = set(re.findall(core, corpus_text))
        tuples = done_core[core]
        if len(tuples) > 300000:
            continue
        for t in tuples:
            name = lits[0]
            for i, v in enumerate(t):
                name += v + lits[i + 1]
            st.offer(f"{d}/{name}", "tuple_harvest")
    lib.log(f"g1: +{len(st.names) - before}")


def g2():
    before = len(st.names)
    by_len = collections.defaultdict(list)
    for n in numbers:
        by_len[len(n)].append(n)
    groups = collections.defaultdict(list)  # skeleton -> list of slot tuples
    for p in st.names.values():
        d = p.rsplit("/", 1)[0]
        if d not in gap_dirs and d.rsplit("/", 1)[0] not in gap_dirs:
            continue
        parts = SEG.split(p)
        if len(parts) < 3 or len(parts) > 9:
            continue
        groups[tuple(parts[0::2])].append(tuple(parts[1::2]))
    lib.log("g2 skeletons", len(groups))
    total = 0
    for lits, tuples in groups.items():
        if len(tuples) < 2:
            continue
        n = len(tuples[0])
        # choose the longest slot as the driver
        lens = [collections.Counter(len(t[i]) for t in tuples).most_common(1)[0][0] for i in range(n)]
        drv = max(range(n), key=lambda i: lens[i])
        rel = []
        ok = True
        for i in range(n):
            if i == drv:
                rel.append(("drv", None))
            elif all(t[i] == t[drv] for t in tuples):
                rel.append(("eq", None))
            elif all(t[drv].startswith(t[i]) for t in tuples) and len({len(t[i]) for t in tuples}) == 1:
                rel.append(("prefix", len(tuples[0][i])))
            elif len({t[i] for t in tuples}) <= 3:
                rel.append(("set", sorted({t[i] for t in tuples})))
            else:
                ok = False
                break
        if not ok:
            continue
        lo = min(int(t[drv]) for t in tuples)
        hi = max(int(t[drv]) for t in tuples)
        span = max(hi - lo, 1)
        pool = [x for x in by_len[lens[drv]] if lo - span <= int(x) <= hi + span]
        if len(pool) > 200000:
            continue
        for x in pool:
            fills = [[]]
            for i, (kind, arg) in enumerate(rel):
                if kind in ("drv", "eq"):
                    vals = [x]
                elif kind == "prefix":
                    vals = [x[:arg]]
                else:
                    vals = arg
                fills = [f + [v] for f in fills for v in vals]
            for f in fills:
                s = lits[0]
                for i, v in enumerate(f):
                    s += v + lits[i + 1]
                st.offer(s, "related_slot_template")
                total += 1
    lib.log(f"g2: tried {total} +{len(st.names) - before}")


for r in range(3):
    b = len(st.names)
    g1()
    g2()
    lib.transforms(st)
    lib.interpolation(st)
    st.save()
    if len(st.names) == b:
        break
