"""Recover logical names for DesignData index entries by hashing candidate strings.

Writes:
  candidates_<source>.txt  raw candidate strings per source (deduped)
  named.json               hash -> {path, sources}
"""
import collections
import json
import os
import re
import sys
import time

import xxhash

import designindex as di

OUT = os.environ.get("HSR_INV_WORK", os.getcwd())
LOG = os.path.join(os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta"), "hsr-owner.log")
EXCEL_PATHS = os.path.join(os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta"), "DUMP/excel_paths.json")
METADATA = os.path.join(os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta"), "StarRail_Data/il2cpp_data/Metadata/global-metadata.dat")
LANGS = ["en", "cn", "jp", "kr", "chs", "cht", "de", "es", "fr", "ru", "th", "vi", "pt", "id"]

PATH_RUN = re.compile(rb"[A-Za-z0-9_\-\.\(\) ]*/[A-Za-z0-9_\-\./\(\) ]+")
ROOT_HINT = re.compile(r"(BakedConfig/|Config/|Story/|ExcelOutput)")


def h64(s):
    return xxhash.xxh64_intdigest(s.encode("utf-8"), 0)


def logical_variants(s):
    s = s.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    s = s.lstrip("/")
    if not s or len(s) > 400:
        return
    if s.startswith("BakedConfig/"):
        yield s
        if s.endswith(".json"):
            yield s[:-5] + ".bytes"
        return
    if s.endswith(".json"):
        yield "BakedConfig/" + s[:-5] + ".bytes"
        yield "BakedConfig/" + s
        yield s
    elif s.endswith(".bytes"):
        yield "BakedConfig/" + s
        yield s
    else:
        yield "BakedConfig/" + s + ".bytes"
        yield "BakedConfig/" + s + ".json"


def run_starts(run):
    """Candidate start offsets inside a printable run (drop possible length prefix bytes)."""
    starts = {0, 1, 2}
    for m in ROOT_HINT.finditer(run):
        starts.add(m.start())
    return [run[i:] for i in sorted(starts) if i < len(run)]


class Namer:
    def __init__(self, entry_hashes):
        self.entry_hashes = entry_hashes
        self.named = {}  # hash -> path
        self.sources = collections.defaultdict(set)  # hash -> sources
        self.stats = collections.Counter()

    def offer(self, raw, source):
        hit = False
        for logical in logical_variants(raw):
            h = h64(logical)
            if h in self.entry_hashes:
                old = self.named.get(h)
                if old is not None and old != logical:
                    self.stats[f"{source}:collision"] += 1
                    continue
                if old is None:
                    self.stats[f"{source}:new"] += 1
                self.named[h] = logical
                self.sources[h].add(source)
                hit = True
        self.stats[f"{source}:{'hit' if hit else 'miss'}"] += 1
        return hit


def strings_from_bytes(data):
    out = set()
    for m in PATH_RUN.finditer(data):
        run = m.group().decode("ascii", "replace").strip()
        if len(run) < 4:
            continue
        for s in run_starts(run):
            s = s.strip(" .")
            if "/" in s and len(s) >= 4:
                out.add(s)
                # also cut at the first extension boundary if trailing junk follows
                for ext in (".json", ".bytes"):
                    i = s.find(ext)
                    if i > 0:
                        out.add(s[: i + len(ext)])
    return out


def main():
    t0 = time.time()
    snaps = {name: di.open_snapshot(name) for name in di.ROOTS}
    entry_hashes = {}
    for name, s in snaps.items():
        for h in s["entries"]:
            entry_hashes.setdefault(h, set()).add(name)
    print(f"index hashes: {len(entry_hashes)} (P={len(snaps['Persistent']['entries'])}, "
          f"S={len(snaps['StreamingAssets']['entries'])})", flush=True)
    namer = Namer(entry_hashes)

    # S1: runtime excel_paths.json
    excel = json.load(open(EXCEL_PATHS, encoding="utf-8-sig"))
    for paths in excel.values():
        for p in paths:
            namer.offer(p, "excel_paths.json")
    # S2: TextMap names used by the client
    for lang in LANGS:
        for stem in ("Textmap", "TextmapMain"):
            namer.offer(f"BakedConfig/ExcelOutput/{stem}_{lang}.bytes", "textmap_template")
    namer.offer("BakedConfig/ConfigManifest.json", "manifest_name")
    print("after excel/textmap:", len(namer.named), flush=True)

    # S3: ConfigManifest.json payload
    mh = h64("BakedConfig/ConfigManifest.json")
    snap = snaps["Persistent"]
    fno, off, size = snap["entries"][mh]
    with open(snap["files"][fno]["path"], "rb") as f:
        f.seek(off)
        manifest = json.loads(f.read(size))
    mstrings = set()

    def walk(v):
        if isinstance(v, str):
            mstrings.add(v)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, dict):
            for k, x in v.items():
                mstrings.add(k)
                walk(x)

    walk(manifest)
    for s in mstrings:
        namer.offer(s, "ConfigManifest")
    print("after manifest:", len(namer.named), "manifest strings", len(mstrings), flush=True)

    # S4: runtime Resources log (JSON-domain paths attempted by HSR-OWNER)
    log_paths = set()
    pat = re.compile(r"Config: (?:exists|skip absent path|load \w+ path=)\s*(\S+)")
    with open(LOG, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "Config: " in line:
                m = pat.search(line)
                if m:
                    log_paths.add(m.group(1))
    for s in log_paths:
        namer.offer(s, "hsr-owner.log")
    print("after log:", len(namer.named), "log paths", len(log_paths), flush=True)

    # S5: strings inside every indexed payload (scan whole physical chunk files)
    payload_strings = set()
    seen_files = set()
    for name, s in snaps.items():
        for fi in s["files"]:
            if not fi["path"] or fi["path"] in seen_files:
                continue
            seen_files.add(fi["path"])
            with open(fi["path"], "rb") as f:
                data = f.read()
            got = strings_from_bytes(data)
            payload_strings |= got
            print(f"  scanned {os.path.basename(fi['path'])} {len(data)}B -> {len(got)} strings", flush=True)
    for s in payload_strings:
        namer.offer(s, "payload_strings")
    print("after payload strings:", len(namer.named), "strings", len(payload_strings), flush=True)

    # S6: global-metadata.dat strings (works only if string literals are plaintext)
    with open(METADATA, "rb") as f:
        meta = f.read()
    meta_strings = strings_from_bytes(meta)
    for s in meta_strings:
        namer.offer(s, "global-metadata")
    print("after metadata:", len(namer.named), "strings", len(meta_strings), flush=True)

    for label, coll in (("manifest", mstrings), ("log", log_paths), ("payload", payload_strings),
                        ("metadata", meta_strings)):
        with open(os.path.join(OUT, f"candidates_{label}.txt"), "w", encoding="utf-8") as f:
            for s in sorted(coll):
                f.write(s + "\n")
    with open(os.path.join(OUT, "named.json"), "w", encoding="utf-8") as f:
        json.dump({f"{h:016x}": {"path": p, "sources": sorted(namer.sources[h]),
                                 "snapshots": sorted(entry_hashes[h])}
                   for h, p in namer.named.items()}, f, ensure_ascii=False)
    print(json.dumps(dict(sorted(namer.stats.items())), indent=1))
    print(f"named {len(namer.named)} / {len(entry_hashes)}  elapsed {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
