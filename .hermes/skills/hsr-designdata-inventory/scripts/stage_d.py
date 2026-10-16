"""Stage D: client path transforms + interpolation until fixpoint."""
import lib

st = lib.Store()
for r in range(3):
    before = len(st.names)
    lib.transforms(st)
    lib.interpolation(st)
    lib.log(f"stage_d pass {r}: +{len(st.names) - before}")
    if len(st.names) == before:
        break
st.save()
