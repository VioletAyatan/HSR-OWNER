"""Disassemble functions in GameAssembly.dll with symbolized calls and literals.

Usage: python disasm.py <rva_hex> [max_bytes]
Annotates call targets with ScriptMethod names and RIP-relative loads with
ScriptString literals / method-slot names (via script-mini.json addresses).
"""
import bisect
import struct
import sys

import capstone

import xref

data, secs = xref.load_pe(xref.GA)
idx = xref.load_script_index()
methods = idx["methods"]
starts = [m[0] for m in methods]
names_at = {a: n for a, n in methods}
strings = {int(k): v for k, v in idx["strings"].items()}


def rva_to_off(rva):
    for name, va, vsize, raw, rsize, chars in secs:
        if va <= rva < va + max(vsize, rsize):
            return raw + (rva - va)


def func_end(rva):
    i = bisect.bisect_right(starts, rva)
    return starts[i] if i < len(starts) else rva + 0x400


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
for arg in sys.argv[1:2]:
    start = int(arg, 16)
    limit = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    end = start + limit if limit else func_end(start)
    off = rva_to_off(start)
    code = data[off:off + (end - start)]
    print(f"== 0x{start:X} {names_at.get(start, '?')} size=0x{end - start:X}")
    for ins in md.disasm(code, start):
        note = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            t = int(ins.op_str, 16)
            note = names_at.get(t, "")
        if "rip" in ins.op_str:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp
                    if t in strings:
                        note = f"literal {strings[t]!r}"
                    else:
                        note = f"[0x{t:X}]"
        print(f"  {ins.address:08X}: {ins.mnemonic:6} {ins.op_str:40} {note}")
