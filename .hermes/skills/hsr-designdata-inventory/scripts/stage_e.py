"""Stage E: self-naming. Tokens found inside unnamed entries (and their neighbours)
are tried as file names in the neighbouring directories and known subdirectories.
Stage subdirectory and suffix names come from the client's stage path helper
(GENNHNMPKBF: Blocks/, BlockExternals/, Alias/, SharedAlias/, Culling/, Cells/,
.volume/.region/.VoxelData/.IRIFBXLodSize/.PVSMeta/.stage/.auto.stage).
"""
import collections
import os
import re

import lib

st = lib.Store()
STAGE_SUBDIRS = ["Blocks", "BlockExternals", "Alias", "SharedAlias", "Culling", "Cells"]
STAGE_EXTS = [".volume.bytes", ".region.bytes", ".VoxelData.bytes", ".IRIFBXLodSize.bytes", ".PVSMeta.bytes",
              ".stage.bytes", ".auto.stage.bytes", ".block.bytes", ".bytes", ".json"]
RX = re.compile(rb"[A-Za-z0-9_\-\. ()]{3,160}")

handles = {}


def read(snap, fno, off, size):
    key = (snap["name"], fno)
    f = handles.get(key)
    if f is None:
        f = handles[key] = open(snap["files"][fno]["path"], "rb")
    f.seek(off)
    return f.read(size)


def tokens_of(blob, cap=6000):
    out = set()
    for m in RX.finditer(blob):
        s = m.group().decode("ascii").strip(" .")
        for t in {s, s[1:], s[2:]}:
            t = t.strip(" .")
            if len(t) < 2:
                continue
            for part in t.split("/"):
                part = part.strip(" .")
                if len(part) >= 2:
                    out.add(part)
                    for e in (".bytes", ".json"):
                        if part.endswith(e):
                            out.add(part[: -len(e)])
        if len(out) > cap:
            break
    return out


def split_ext(fname):
    i = fname.find(".")
    return (fname, "") if i < 0 else (fname[:i], fname[i:])


def run():
    subdirs = collections.defaultdict(set)
    exts_by_dir = collections.defaultdict(set)
    for p in st.names.values():
        d, f = p.rsplit("/", 1)
        exts_by_dir[d].add(split_ext(f)[1])
        if "/" in d:
            parent, sub = d.rsplit("/", 1)
            subdirs[parent].add(sub)
    gained_before = len(st.names)
    for snap in (st.P, st.S):
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
                prev = st.names.get(ents[i - 1][2]) if i > 0 else None
                nxt = st.names.get(ents[j][2]) if j < len(ents) else None
                toks = set()
                for off, size, h in ents[i:j]:
                    toks |= tokens_of(read(snap, fno, off, min(size, 2_000_000)))
                dirs = set()
                for p in (prev, nxt):
                    if not p:
                        continue
                    d = p.rsplit("/", 1)[0]
                    dirs.add(d)
                    dirs.update(f"{d}/{s}" for s in subdirs.get(d, ()))
                    if "/" in d:
                        parent = d.rsplit("/", 1)[0]
                        dirs.add(parent)
                    if "/Stages/" in p or "/BattleAreaStages/" in p:
                        dirs.update(f"{d}/{s}" for s in STAGE_SUBDIRS)
                for d in dirs:
                    exts = exts_by_dir.get(d, set()) | {".bytes"}
                    if "/Stages/" in d or "/BattleAreaStages/" in d:
                        exts |= set(STAGE_EXTS)
                    alias = d.endswith("Alias")
                    for t in toks:
                        for e in exts:
                            st.offer(f"{d}/{t}{e}", "self_token")
                        if alias:
                            st.offer(f"{d}/{t}_Alias.bytes", "self_token")
                i = j
    lib.log(f"self_token: +{len(st.names) - gained_before} total={len(st.names)}")
    return len(st.names) - gained_before


for r in range(3):
    if not run():
        break
    lib.transforms(st)
    lib.interpolation(st)
st.save()
