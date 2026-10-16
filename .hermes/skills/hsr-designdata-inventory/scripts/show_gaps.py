"""Show residual gaps (full paths + payload strings) for given substrings of the neighbour paths."""
import re
import sys

import lib

st = lib.Store()
filters = sys.argv[1:]
per = 3
shown = {f: 0 for f in filters}
handles = {}


def read(snap, fno, off, size):
    key = (snap["name"], fno)
    if key not in handles:
        handles[key] = open(snap["files"][fno]["path"], "rb")
    f = handles[key]
    f.seek(off)
    return f.read(size)


for snap in (st.P, st.S):
    import collections
    byfile = collections.defaultdict(list)
    for h, (fno, off, size) in snap["entries"].items():
        byfile[fno].append((off, size, h))
    for fno, ents in byfile.items():
        ents.sort()
        i = 0
        while i < len(ents):
            if ents[i][2] in st.names:
                i += 1
                continue
            j = i
            while j < len(ents) and ents[j][2] not in st.names:
                j += 1
            prev = st.names.get(ents[i - 1][2]) if i else None
            nxt = st.names.get(ents[j][2]) if j < len(ents) else None
            for f in filters:
                if shown[f] < per and ((prev and f in prev) or (nxt and f in nxt)):
                    shown[f] += 1
                    print(f"=== [{f}] {j - i} unnamed\n  after  {prev}\n  before {nxt}")
                    for off, size, h in ents[i:min(j, i + 4)]:
                        b = read(snap, fno, off, min(size, 100000))
                        ss = [m.group().decode() for m in re.finditer(rb"[\x20-\x7e]{5,}", b)][:6]
                        print(f"    {h:016x} size={size} {[s[:90] for s in ss]}")
            i = j
