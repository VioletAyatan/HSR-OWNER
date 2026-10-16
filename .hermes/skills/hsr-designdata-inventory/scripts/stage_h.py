"""Stage H: client string literals that are path prefixes (concatenated with an ID
or name at runtime, e.g. "Config/AssetPreload/CharacterEffect/CharacterEffect_")
are completed with every number and identifier token in the corpus."""
import os
import re

import lib

st = lib.Store()
W = lib.W
literals = open(os.path.join(W, "script_strings.txt"), encoding="utf-8").read().splitlines()
payload_tokens = open(os.path.join(W, "tokens_payload.txt"), encoding="utf-8").read().split("\n")

prefixes = sorted({s for s in literals
                   if re.match(r"(Config|Story|BakedConfig|Stages)/", s) and not s.endswith((".json", ".bytes"))
                   and "{" not in s and len(s) < 160})
lib.log("prefix literals", len(prefixes))
for p in prefixes[:80]:
    print("   ", p)

fill = set(re.findall(r"\d{1,12}", "\n".join(payload_tokens + literals + list(st.names.values()))))
fill.update(t for t in payload_tokens if re.fullmatch(r"[A-Za-z0-9_\-]{2,80}", t))
fill.update(t for t in literals if re.fullmatch(r"[A-Za-z0-9_\-]{2,80}", t))
for p in st.names.values():
    stem = p.rsplit("/", 1)[1].split(".")[0]
    fill.add(stem)
    fill.update(stem.split("_"))
lib.log("fill values", len(fill))


def variants(s):
    if s.startswith("BakedConfig/"):
        yield s + ".bytes"
    else:
        yield "BakedConfig/" + s + ".bytes"


before = len(st.names)
for p in prefixes:
    for v in fill:
        for c in variants(p + v):
            st.offer(c, "literal_prefix")
        if p.endswith("/"):
            # directory prefix: also <dir>/<v>/<v>.json style
            for c in variants(p + v + "/" + v):
                st.offer(c, "literal_prefix")
    lib.log(f"prefix {p!r}: total +{len(st.names) - before}")
lib.transforms(st)
lib.interpolation(st)
st.save()
