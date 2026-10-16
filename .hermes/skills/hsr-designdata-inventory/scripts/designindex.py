"""Strict read-only parser for StarRail DesignData v4 (M_DesignV.bytes + DesignV_<md5>.bytes).

Mirrors HSR-Offline crates/resource-data/src/offline/index.rs::parse_index.
"""
import hashlib
import json
import os
import struct
import sys

GAME = os.path.join(os.environ.get("HSR_CLIENT", r"D:/StarRail_Beta"), "StarRail_Data")
ROOTS = {
    "Persistent": os.path.join(GAME, "Persistent/DesignData/Windows"),
    "StreamingAssets": os.path.join(GAME, "StreamingAssets/DesignData/Windows"),
}


def read_mini(root):
    with open(os.path.join(root, "M_DesignV.bytes"), "rb") as f:
        mini = f.read()
    assert len(mini) >= 52, f"mini truncated {len(mini)}"
    assert mini[:4] == b"SRMI", "no SRMI signature"
    revision = struct.unpack_from("<I", mini, 24)[0]
    d = bytearray(mini[28:44])
    for i in range(0, 16, 4):
        d[i:i + 4] = d[i:i + 4][::-1]
    digest = d.hex()
    index_size = struct.unpack_from("<Q", mini, 44)[0]
    return revision, digest, index_size, len(mini)


def parse_index(data):
    pos = 0
    n = len(data)

    def take(k):
        nonlocal pos
        if pos + k > n:
            raise ValueError(f"truncated at {pos} need {k}")
        b = data[pos:pos + k]
        pos += k
        return b

    magic, version, file_count, entry_count = struct.unpack(">IIII", take(16))
    if (magic, version) != (255, 4):
        raise ValueError(f"unsupported header magic={magic} version={version}")
    if file_count * 37 + entry_count * 16 > n - pos:
        raise ValueError("counts cannot fit")
    files, entries = [], {}
    actual = 0
    for fno in range(file_count):
        path_hash, = struct.unpack(">Q", take(8))
        digest = take(16).hex()
        fsize, = struct.unpack(">Q", take(8))
        cnt, = struct.unpack(">i", take(4))
        if cnt < 0 or cnt > entry_count - actual:
            raise ValueError(f"file {fno}: bad count {cnt}")
        ents = []
        for eno in range(cnt):
            h, size, off = struct.unpack(">QII", take(16))
            if off + size > fsize:
                raise ValueError(f"file {fno} entry {eno} out of range")
            if h in entries:
                raise ValueError(f"duplicate hash {h:016x}")
            entries[h] = (fno, off, size)
            ents.append(h)
        marker = take(1)[0]
        if marker == 0x80:
            tag = None
        elif marker == 0:
            ln = take(1)[0]
            tag = take(ln).decode("utf-8")
            if take(1)[0] != 0x80:
                raise ValueError(f"file {fno}: bad tag terminator")
        else:
            raise ValueError(f"file {fno}: bad tag marker {marker:#x}")
        files.append({"path_hash": path_hash, "digest": digest, "size": fsize,
                      "count": cnt, "tag": tag})
        actual += cnt
    if actual != entry_count:
        raise ValueError(f"entry count mismatch {actual} != {entry_count}")
    if pos != n:
        raise ValueError(f"{n - pos} trailing bytes")
    return files, entries


def open_snapshot(name):
    root = ROOTS[name]
    revision, digest, index_size, mini_len = read_mini(root)
    ipath = os.path.join(root, f"DesignV_{digest}.bytes")
    with open(ipath, "rb") as f:
        data = f.read()
    assert len(data) == index_size, f"index size {len(data)} != {index_size}"
    assert hashlib.md5(data).hexdigest() == digest, "index md5 mismatch"
    files, entries = parse_index(data)
    # resolve physical files: root/<digest>.bytes, then root/<tag>/<digest>.bytes, then other root
    for fi in files:
        cands = [os.path.join(root, fi["digest"] + ".bytes")]
        if fi["tag"]:
            cands.append(os.path.join(root, fi["tag"], fi["digest"] + ".bytes"))
        other = [r for k, r in ROOTS.items() if k != name][0]
        cands.append(os.path.join(other, fi["digest"] + ".bytes"))
        if fi["tag"]:
            cands.append(os.path.join(other, fi["tag"], fi["digest"] + ".bytes"))
        fi["path"] = next((c for c in cands if os.path.isfile(c)), None)
        fi["physical_size"] = os.path.getsize(fi["path"]) if fi["path"] else None
    return {"name": name, "root": root, "revision": revision, "index_digest": digest,
            "index_size": index_size, "files": files, "entries": entries,
            "index_mtime": os.path.getmtime(ipath)}


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    import datetime
    for name in ROOTS:
        s = open_snapshot(name)
        print(f"== {name}: revision={s['revision']} index=DesignV_{s['index_digest']} "
              f"size={s['index_size']} mtime={datetime.datetime.fromtimestamp(s['index_mtime'])}")
        print(f"   files={len(s['files'])} entries={len(s['entries'])}")
        for i, fi in enumerate(s["files"]):
            ok = None
            if fi["path"] and fi["physical_size"] == fi["size"]:
                ok = md5_file(fi["path"]) == fi["digest"]
            loc = os.path.relpath(fi["path"], GAME) if fi["path"] else "MISSING"
            print(f"   [{i}] {fi['digest']} tag={fi['tag']!s:6} entries={fi['count']:6} size={fi['size']:10} md5_ok={ok} at {loc}")
