"""Shared helpers for DesignData name recovery (scratch tooling)."""
import collections
import json
import os
import re
import string
import time

import xxhash

import designindex as di

W = os.environ.get("HSR_INV_WORK", os.getcwd())
STATE = os.path.join(W, "names_state.json")
T0 = time.time()


def log(*a):
    print(f"[{time.time() - T0:7.1f}s]", *a, flush=True)


def h64(s):
    return xxhash.xxh64_intdigest(s.encode("utf-8"), 0)


# Packing order inside a chunk: directory-first traversal (files before
# subdirectories), case-insensitive, punctuation < digits < letters.
_PUNCT = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
_ORDER = _PUNCT + string.digits + string.ascii_lowercase
_TABLE = {ord(c): chr(0x21 + i) for i, c in enumerate(_ORDER)}


def name_key(component):
    return component.lower().translate(_TABLE)


def path_key(p):
    parts = p.split("/")
    return [("0" if i == len(parts) - 1 else "1") + name_key(c) for i, c in enumerate(parts)]


class Store:
    def __init__(self):
        self.P = di.open_snapshot("Persistent")
        self.S = di.open_snapshot("StreamingAssets")
        self.all = {}
        for snap in (self.P, self.S):
            for h in snap["entries"]:
                self.all.setdefault(h, snap["name"])
        self.names = {}
        self.sources = collections.defaultdict(set)
        for k, v in json.load(open(STATE, encoding="utf-8")).items():
            self.names[int(k, 16)] = v["path"]
            self.sources[int(k, 16)].update(v["sources"])
        self.gain = collections.Counter()
        log("store: entries", len(self.all), "named", len(self.names))

    def offer(self, path, label):
        h = h64(path)
        if h in self.all and h not in self.names:
            self.names[h] = path
            self.sources[h].add(label)
            self.gain[label] += 1
            return True
        return False

    def save(self):
        tmp = STATE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({f"{h:016x}": {"path": p, "sources": sorted(self.sources[h])}
                       for h, p in self.names.items()}, f, ensure_ascii=False)
        os.replace(tmp, STATE)
        log("saved", len(self.names), f"({len(self.names) / len(self.all):.2%})", dict(self.gain))

    def sequences(self):
        for snap in (self.P, self.S):
            byfile = collections.defaultdict(list)
            for h, (fno, off, size) in snap["entries"].items():
                byfile[fno].append((off, size, h))
            for fno, ents in byfile.items():
                ents.sort()
                yield snap["name"], fno, ents

    def gaps(self):
        """Yield (prev_name, next_name, unnamed_count) over every chunk."""
        for _, _, ents in self.sequences():
            prev, k = None, 0
            for off, size, h in ents:
                nm = self.names.get(h)
                if nm is None:
                    k += 1
                    continue
                if k:
                    yield prev, nm, k
                k = 0
                prev = nm
            if k:
                yield prev, None, k


def insert_tag(path, tag):
    i = path.rfind(".")
    return path[:i] + "." + tag + "." + path[i + 1:]


def transforms(store, rounds=3):
    """Client path transforms from GameCoreConfigLoader (BinaryBakeLayoutPath,
    BinaryMainMissionPartialPath)."""
    for r in range(rounds):
        before = len(store.names)
        for p in list(store.names.values()):
            if not p.endswith(".bytes") or ".layout." in p:
                continue
            store.offer(insert_tag(p, "layout"), "client_layout_path")
            if ".partial." not in p:
                q = insert_tag(p, "partial")
                store.offer(q, "client_partial_path")
                store.offer(insert_tag(q, "layout"), "client_partial_path")
        log(f"transforms round {r}: +{len(store.names) - before}")
        if len(store.names) == before:
            break


SEG = re.compile(r"(\d+)")


def _num_variants(width, lo, hi):
    for nv in range(max(lo, 0), hi + 1):
        s1 = str(nv)
        yield s1
        if len(s1) < width:
            yield s1.zfill(width)


def interp_candidates(a, b, reach=40, cap=5000):
    da, fa = a.rsplit("/", 1)
    sa = SEG.split(fa)
    for i in range(1, len(sa), 2):
        v = int(sa[i])
        for s_val in _num_variants(len(sa[i]), v - reach, v + reach):
            s2 = list(sa)
            s2[i] = s_val
            yield da + "/" + "".join(s2)
    if b:
        db, fb = b.rsplit("/", 1)
        sb = SEG.split(fb)
        if db == da and len(sa) == len(sb) and all(sa[j] == sb[j] for j in range(0, len(sa), 2)):
            for i in [j for j in range(1, len(sa), 2) if sa[j] != sb[j]]:
                lo, hi = sorted((int(sa[i]), int(sb[i])))
                if hi - lo <= cap:
                    for base in (sa, sb):
                        for s_val in _num_variants(len(base[i]), lo, hi):
                            s2 = list(base)
                            s2[i] = s_val
                            yield da + "/" + "".join(s2)


def interpolation(store, label="interpolation", rounds=4):
    for r in range(rounds):
        before = len(store.names)
        for prev, nxt, k in list(store.gaps()):
            if prev:
                for c in interp_candidates(prev, nxt):
                    store.offer(c, label)
            if nxt:
                for c in interp_candidates(nxt, None):
                    store.offer(c, label)
        log(f"{label} round {r}: +{len(store.names) - before} total={len(store.names)}")
        if len(store.names) == before:
            break
