import collections
import json

import xxhash

import designindex as di

snap = di.open_snapshot("Persistent")


def read(path):
    h = xxhash.xxh64(path.encode()).intdigest()
    fno, off, size = snap["entries"][h]
    with open(snap["files"][fno]["path"], "rb") as f:
        f.seek(off)
        return f.read(size)


def varint(b, p):
    r = s = 0
    while True:
        x = b[p]
        p += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, p


def zz(v):
    return (v >> 1) ^ -(v & 1)


b = read("BakedConfig/ExcelOutput/Textmap_cn.bytes")
p = 0
n, p = varint(b, p)
n = zz(n)
flags_c = collections.Counter()
rows = []
for _ in range(n):
    fl, p = varint(b, p)
    flags_c[fl] += 1
    row = {}
    if fl & 1:
        h, p = varint(b, p)
        row["Hash"] = zz(h)
        h64, p = varint(b, p)
        row["Hash64"] = h64
    if fl & 2:
        k, p = varint(b, p)
        row["Text"] = b[p:p + k].decode()
        p += k
    if fl & 4:
        v, p = varint(b, p)
        row["HasParam"] = v
    rows.append((fl, row))
print("count", n, "end", p == len(b), "flags", flags_c.most_common())
rt = json.load(open(r"D:/Download/TurnBasedGameData-main/TextMap/TextMapEN.json", encoding="utf-8"))
mism = collections.Counter()
for (fl, r), x in zip(rows, rt):
    if r.get("Hash", 0) != x["ID"]["Hash"]:
        mism["Hash"] += 1
    if r.get("Hash64", 0) != x["ID"]["Hash64"]:
        mism["Hash64"] += 1
    if r.get("Text", None) != x["Text"]:
        mism[("Text", fl & 2, repr(x["Text"])[:10])] += 1
    if bool(r.get("HasParam", 0)) != x["HasParam"]:
        mism["HasParam"] += 1
    if r.get("HasParam", 0) not in (0, 1):
        mism["HasParamValue"] += 1
print("mismatch", mism.most_common(8))
print("hash range", min(r.get("Hash", 0) for _, r in rows), max(r.get("Hash", 0) for _, r in rows))
print("rt keys", collections.Counter(tuple(x.keys()) for x in rt).most_common(3),
      collections.Counter(tuple(x["ID"].keys()) for x in rt).most_common(3))
# exact text of the runtime file vs our formatting of the first rows
raw = open(r"D:/Download/TurnBasedGameData-main/TextMap/TextMapEN.json", "rb").read(600)
print(repr(raw[:300]))
