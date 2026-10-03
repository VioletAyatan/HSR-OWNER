//! Normal-return proofs are bound to the current PE, not to method names or RVAs.
//! Unknown calls, unwind formats and language handlers keep the old CFG.
use super::native_pe::{Pe, RuntimeFunction};
use anyhow::{Context, Result, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

#[derive(Clone, Copy)]
pub(super) enum Binding {
    /// Explicitly offline: imports describe the original loader binding only.
    #[cfg(test)]
    DeclaredDisk,
    /// The current IAT must equal the OS-resolved, forwarded API address.
    Loaded(usize),
}

#[derive(Default, Debug, Serialize)]
pub(super) struct Plan {
    pub terminal_calls: BTreeSet<usize>,
    pub exceptional_edges: BTreeMap<usize, Vec<usize>>,
    pub switch_edges: BTreeMap<usize, Vec<usize>>,
    pub catch_funclets: BTreeMap<usize, usize>,
    pub try_blocks: usize,
    pub catch_handlers: usize,
    pub code_bytes: Option<usize>,
    pub funcinfo_rva: Option<usize>,
    pub handler_rva: Option<usize>,
}

#[derive(Default, Serialize)]
pub(super) struct Statistics {
    pub runtime_functions: usize,
    pub functions_examined: usize,
    pub proven_functions: usize,
    pub cache_hits: usize,
    pub terminal_calls: usize,
    pub exceptional_edges: usize,
    pub switch_dispatches: usize,
    pub switch_targets: usize,
    pub planned_callers: usize,
    pub unsupported_callers: usize,
}

pub(super) struct Resolver<'a> {
    pe: Pe<'a>,
    binding: Binding,
    cache: HashMap<usize, bool>,
    proof_bytes: BTreeMap<usize, (RuntimeFunction, Vec<u8>, Vec<u8>)>,
    pub stats: Statistics,
}

fn decode(code: &[u8], rva: usize) -> Result<Vec<Instruction>> {
    rva.checked_add(code.len())
        .context("native body overflow")?;
    let mut decoder = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE);
    let mut out = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        ensure!(
            !instruction.is_invalid(),
            "invalid native instruction at 0x{:X}",
            instruction.ip()
        );
        out.push(instruction);
    }
    ensure!(!out.is_empty(), "empty native function");
    Ok(out)
}

fn is_call(i: &Instruction) -> bool {
    matches!(
        i.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    )
}
fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
    )
}
fn direct(i: &Instruction) -> Option<usize> {
    matches!(
        i.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| i.near_branch_target() as usize)
}

struct Graph {
    code: Vec<u8>,
    ins: Vec<Instruction>,
    edges: Vec<Vec<usize>>,
    incomplete: Vec<bool>,
    reachable: Vec<bool>,
    anchors: HashSet<usize>,
}

impl Graph {
    fn new(ins: Vec<Instruction>) -> Self {
        let positions: HashMap<_, _> = ins
            .iter()
            .enumerate()
            .map(|(n, i)| (i.ip() as usize, n))
            .collect();
        let mut edges = vec![Vec::new(); ins.len()];
        let mut incomplete = vec![false; ins.len()];
        for (n, i) in ins.iter().enumerate() {
            if matches!(
                i.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) {
                if let Some(target) = direct(i).and_then(|rva| positions.get(&rva)).copied() {
                    edges[n].push(target);
                } else {
                    incomplete[n] = true;
                }
            }
            if matches!(
                i.flow_control(),
                FlowControl::Next
                    | FlowControl::Call
                    | FlowControl::IndirectCall
                    | FlowControl::ConditionalBranch
            ) {
                if ins.get(n + 1).is_some_and(|next| next.ip() == i.next_ip()) {
                    edges[n].push(n + 1);
                } else {
                    incomplete[n] = true;
                }
            }
            if matches!(
                i.flow_control(),
                FlowControl::IndirectBranch
                    | FlowControl::Interrupt
                    | FlowControl::Exception
                    | FlowControl::Return
            ) {
                incomplete[n] = true;
            }
        }
        let mut reachable = vec![false; ins.len()];
        let mut pending = vec![0];
        while let Some(n) = pending.pop() {
            if std::mem::replace(&mut reachable[n], true) {
                continue;
            }
            pending.extend(edges[n].iter().copied());
        }
        Self {
            code: Vec::new(),
            ins,
            edges,
            incomplete,
            reachable,
            anchors: HashSet::new(),
        }
    }

    fn good(&self, proven: impl Fn(usize) -> bool) -> Vec<bool> {
        // A least fixed point: a cycle, trap or unknown exit is never itself
        // evidence of a noncontinuable exception. Each positive path reaches
        // a validated anchor, possibly through another proved function.
        let mut good = vec![false; self.ins.len()];
        loop {
            let mut changed = false;
            for n in (0..self.ins.len()).rev() {
                let value = self.anchors.contains(&n)
                    || (is_call(&self.ins[n]) && direct(&self.ins[n]).is_some_and(&proven))
                    || (!self.incomplete[n]
                        && !self.edges[n].is_empty()
                        && self.edges[n].iter().all(|&next| good[next]));
                if value && !good[n] {
                    good[n] = true;
                    changed = true;
                }
            }
            if !changed {
                return good;
            }
        }
    }

    fn terminal_dependencies(
        &self,
        good: &[bool],
        explored: impl Fn(usize) -> bool,
    ) -> BTreeSet<usize> {
        let mut backwards = vec![Vec::new(); self.ins.len()];
        for (n, edges) in self.edges.iter().enumerate() {
            for &next in edges {
                backwards[next].push(n);
            }
        }
        let mut pending: Vec<_> = self
            .incomplete
            .iter()
            .enumerate()
            .filter_map(|(n, &bad)| (bad && self.reachable[n] && !good[n]).then_some(n))
            .collect();
        let mut seen = vec![false; self.ins.len()];
        let mut out = BTreeSet::new();
        while let Some(n) = pending.pop() {
            if good[n] || std::mem::replace(&mut seen[n], true) {
                continue;
            }
            if is_call(&self.ins[n]) {
                if let Some(target) = direct(&self.ins[n]).filter(|&target| !explored(target)) {
                    out.insert(target);
                    continue;
                }
            }
            pending.extend(backwards[n].iter().copied().filter(|&n| self.reachable[n]));
        }
        out
    }
}

type Constants = BTreeMap<Register, u64>;
fn constants(graph: &Graph) -> Vec<Option<Constants>> {
    let mut states = vec![None; graph.ins.len()];
    states[0] = Some(Constants::new());
    let mut pending = VecDeque::from([0]);
    let mut queued = vec![false; graph.ins.len()];
    queued[0] = true;
    let mut factory = InstructionInfoFactory::new();
    while let Some(n) = pending.pop_front() {
        queued[n] = false;
        let i = &graph.ins[n];
        let before = states[n].as_ref().unwrap();
        let assigned = if i.mnemonic() == Mnemonic::Mov
            && i.op0_kind() == OpKind::Register
            && matches!(i.op0_register().size(), 4 | 8)
        {
            let value = match i.op1_kind() {
                OpKind::Register => before.get(&i.op1_register().full_register()).copied(),
                OpKind::Immediate32 => Some(u64::from(i.immediate32())),
                OpKind::Immediate64 => Some(i.immediate64()),
                OpKind::Immediate32to64 => Some(i.immediate32to64() as u64),
                _ => None,
            };
            value.map(|value| {
                if i.op0_register().size() == 4 {
                    value & 0xffff_ffff
                } else {
                    value
                }
            })
        } else if i.mnemonic() == Mnemonic::Xor
            && i.op0_kind() == OpKind::Register
            && i.op1_kind() == OpKind::Register
            && i.op0_register() == i.op1_register()
            && matches!(i.op0_register().size(), 4 | 8)
        {
            Some(0)
        } else {
            None
        };
        let mut after = before.clone();
        for r in factory.info(i).used_registers() {
            if writes(r.access()) {
                after.remove(&r.register().full_register());
            }
        }
        if let Some(value) = assigned {
            after.insert(i.op0_register().full_register(), value);
        }
        if is_call(i) {
            for r in [
                Register::RAX,
                Register::RCX,
                Register::RDX,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ] {
                after.remove(&r);
            }
        }
        for &next in &graph.edges[n] {
            let changed = if let Some(current) = &mut states[next] {
                let old = current.len();
                current.retain(|r, v| after.get(r) == Some(v));
                current.len() != old
            } else {
                states[next] = Some(after.clone());
                true
            };
            if changed && !queued[next] {
                queued[next] = true;
                pending.push_back(next);
            }
        }
    }
    states
}

pub(super) struct Unwind {
    pub flags: u8,
    pub data: usize,
    pub prolog_size: usize,
    pub local_size: usize,
    pub frame_register: Option<Register>,
    pub frame_offset: usize,
    pub pushed_nonvolatile: Vec<Register>,
    pub saved_ranges: Vec<(usize, usize)>,
    pub operations: Vec<UnwindCode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UnwindCode {
    pub code_offset: usize,
    pub operation: UnwindOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UnwindOperation {
    PushNonvolatile(Register),
    Allocate(usize),
    SetFrameRegister,
    SaveXmm128 { register: u8, offset: usize },
}

fn unwind_register(number: u8) -> Result<Register> {
    Ok(match number {
        0 => Register::RAX,
        1 => Register::RCX,
        2 => Register::RDX,
        3 => Register::RBX,
        4 => Register::RSP,
        5 => Register::RBP,
        6 => Register::RSI,
        7 => Register::RDI,
        8 => Register::R8,
        9 => Register::R9,
        10 => Register::R10,
        11 => Register::R11,
        12 => Register::R12,
        13 => Register::R13,
        14 => Register::R14,
        15 => Register::R15,
        _ => anyhow::bail!("invalid unwind register"),
    })
}
impl<'a> Resolver<'a> {
    pub(super) fn new(pe: Pe<'a>, binding: Binding) -> Self {
        let runtime_functions = pe.function_count();
        Self {
            pe,
            binding,
            cache: HashMap::new(),
            proof_bytes: BTreeMap::new(),
            stats: Statistics {
                runtime_functions,
                ..Statistics::default()
            },
        }
    }

    fn proof_snapshot(&self, rva: usize) -> Result<(RuntimeFunction, Vec<u8>, Vec<u8>)> {
        let f = self.pe.function(rva)?;
        ensure!(
            self.unwind(f)?.flags == 0,
            "cached callee EH profile changed"
        );
        let head = self.pe.bytes(f.unwind, 4)?;
        let unwind = self
            .pe
            .bytes(f.unwind, 4 + (usize::from(head[2]) + 1) / 2 * 4)?;
        Ok((
            f,
            self.pe.bytes(f.start, f.end - f.start)?.to_vec(),
            unwind.to_vec(),
        ))
    }

    fn validate_proof_cache(&mut self) -> Result<()> {
        let valid = (|| -> Result<()> {
            match self.binding {
                Binding::Loaded(expected) => {
                    for &slot in self.pe.raise_exception_iats() {
                        ensure!(
                            expected != 0 && self.pe.u64(slot)? as usize == expected,
                            "RaiseException IAT binding changed or was redirected"
                        );
                    }
                }
                #[cfg(test)]
                Binding::DeclaredDisk => {}
            }
            for (&rva, (saved, code, unwind)) in &self.proof_bytes {
                let f = self.pe.function(rva)?;
                ensure!(
                    f.start == saved.start
                        && f.end == saved.end
                        && f.unwind == saved.unwind
                        && self.pe.bytes(f.start, f.end - f.start)? == code
                        && self.pe.bytes(f.unwind, unwind.len())? == unwind,
                    "cached native exception proof changed at 0x{rva:X}"
                );
            }
            Ok(())
        })();
        if valid.is_err() {
            self.cache.clear();
            self.proof_bytes.clear();
        }
        valid
    }

    fn unwind(&self, f: RuntimeFunction) -> Result<Unwind> {
        let head = self.pe.bytes(f.unwind, 4)?;
        ensure!(head[0] & 7 == 1, "unsupported unwind version");
        let flags = head[0] >> 3;
        ensure!(flags & !3 == 0, "chained/unknown unwind flags");
        let count = usize::from(head[2]);
        let prolog_size = usize::from(head[1]);
        let codes = self.pe.bytes(
            f.unwind + 4,
            count.checked_mul(2).context("unwind codes overflow")?,
        )?;
        let mut local_size = 0;
        let mut saved_ranges = Vec::new();
        let mut saved_xmm = BTreeSet::new();
        let mut pushed_nonvolatile = Vec::new();
        let mut set_frame_register = false;
        let mut operations = Vec::new();
        let mut previous_code_offset = None;
        let mut index = 0;
        // Supported local-frame shape: register pushes, a single local
        // allocation, an optional frame pointer, and XMM save slots. Other
        // saved-register layouts and stack adjustments are rejected for EH.
        while index < count {
            let code_offset = codes[index * 2];
            ensure!(
                code_offset > 0 && usize::from(code_offset) <= prolog_size,
                "invalid unwind prolog code offset"
            );
            ensure!(
                previous_code_offset.is_none_or(|previous| code_offset < previous),
                "unwind operations are not in strict descending prolog order"
            );
            previous_code_offset = Some(code_offset);
            let op = codes[index * 2 + 1] & 15;
            let info = codes[index * 2 + 1] >> 4;
            match op {
                0 => {
                    let register = unwind_register(info)?;
                    ensure!(
                        matches!(
                            register,
                            Register::RBX
                                | Register::RBP
                                | Register::RSI
                                | Register::RDI
                                | Register::R12
                                | Register::R13
                                | Register::R14
                                | Register::R15
                        ) && !pushed_nonvolatile.contains(&register),
                        "invalid or duplicate pushed nonvolatile register"
                    );
                    pushed_nonvolatile.push(register);
                    operations.push(UnwindCode {
                        code_offset: usize::from(code_offset),
                        operation: UnwindOperation::PushNonvolatile(register),
                    });
                }
                3 => {
                    ensure!(
                        info == 0 && !set_frame_register,
                        "invalid or duplicate set-frame unwind operation"
                    );
                    set_frame_register = true;
                    operations.push(UnwindCode {
                        code_offset: usize::from(code_offset),
                        operation: UnwindOperation::SetFrameRegister,
                    });
                }
                2 => {
                    ensure!(local_size == 0, "multiple local allocations");
                    local_size = usize::from(info) * 8 + 8;
                    operations.push(UnwindCode {
                        code_offset: usize::from(code_offset),
                        operation: UnwindOperation::Allocate(local_size),
                    });
                }
                1 => {
                    ensure!(local_size == 0, "multiple local allocations");
                    if info == 0 {
                        ensure!(index + 1 < count, "truncated alloc-large");
                        let units = usize::from(u16::from_le_bytes(
                            codes[(index + 1) * 2..(index + 2) * 2].try_into()?,
                        ));
                        ensure!(units > 0, "zero-length alloc-large");
                        local_size = units * 8;
                        index += 1;
                    } else {
                        ensure!(info == 1 && index + 2 < count, "unsupported alloc-large");
                        local_size =
                            u32::from_le_bytes(codes[(index + 1) * 2..(index + 3) * 2].try_into()?)
                                as usize;
                        ensure!(
                            local_size > 0 && local_size % 8 == 0,
                            "invalid alloc-large size"
                        );
                        index += 2;
                    }
                    operations.push(UnwindCode {
                        code_offset: usize::from(code_offset),
                        operation: UnwindOperation::Allocate(local_size),
                    });
                }
                8 => {
                    ensure!(
                        (6..=15).contains(&info),
                        "save-xmm register is outside XMM6-XMM15"
                    );
                    ensure!(saved_xmm.insert(info), "duplicate save-xmm register");
                    ensure!(index + 1 < count, "truncated save-xmm128");
                    let offset = usize::from(u16::from_le_bytes(
                        codes[(index + 1) * 2..(index + 2) * 2].try_into()?,
                    ))
                    .checked_mul(16)
                    .context("save-xmm offset overflow")?;
                    let end = offset.checked_add(16).context("save-xmm range overflow")?;
                    saved_ranges.push((offset, end));
                    operations.push(UnwindCode {
                        code_offset: usize::from(code_offset),
                        operation: UnwindOperation::SaveXmm128 {
                            register: info,
                            offset,
                        },
                    });
                    index += 1;
                }
                _ => {
                    local_size = usize::MAX;
                    break;
                }
            }
            index += 1;
        }
        if local_size != usize::MAX {
            saved_ranges.sort_unstable();
            for (index, &(start, end)) in saved_ranges.iter().enumerate() {
                ensure!(
                    start < end && end <= local_size,
                    "save-xmm range is outside local allocation"
                );
                if index > 0 {
                    ensure!(
                        saved_ranges[index - 1].1 <= start,
                        "overlapping save-xmm ranges"
                    );
                }
            }
        }
        let declared_frame = head[3] & 15;
        let frame_offset = usize::from(head[3] >> 4) * 16;
        let frame_register = if set_frame_register {
            ensure!(
                declared_frame != 0,
                "set-frame operation has no declared register"
            );
            let register = unwind_register(declared_frame)?;
            ensure!(
                matches!(
                    register,
                    Register::RBX
                        | Register::RBP
                        | Register::RSI
                        | Register::RDI
                        | Register::R12
                        | Register::R13
                        | Register::R14
                        | Register::R15
                ) && frame_offset <= local_size,
                "invalid unwind frame register or offset"
            );
            Some(register)
        } else {
            ensure!(
                head[3] == 0,
                "declared unwind frame lacks set-frame operation"
            );
            None
        };
        let data = f
            .unwind
            .checked_add(4)
            .and_then(|r| r.checked_add((count + 1) / 2 * 4))
            .context("unwind data overflow")?;
        if flags != 0 {
            self.pe.bytes(data, 8)?;
        }
        Ok(Unwind {
            flags,
            data,
            prolog_size,
            local_size,
            frame_register,
            frame_offset,
            pushed_nonvolatile,
            saved_ranges,
            operations,
        })
    }

    pub(super) fn unwind_profile(&self, rva: usize) -> Result<Unwind> {
        self.unwind(self.pe.function(rva)?)
    }

    fn graph(&self, rva: usize) -> Result<Graph> {
        let f = self.pe.function(rva)?;
        ensure!(
            self.unwind(f)?.flags == 0,
            "callee has a local exception/termination handler"
        );
        let code = self.pe.bytes(f.start, f.end - f.start)?.to_vec();
        let mut graph = Graph::new(decode(&code, f.start)?);
        graph.code = code;
        let states = constants(&graph);
        for (n, i) in graph.ins.iter().enumerate() {
            if i.flow_control() != FlowControl::IndirectCall
                || !i.is_ip_rel_memory_operand()
                || i.has_segment_prefix()
                || i.memory_size().size() != 8
            {
                continue;
            }
            let slot = i.ip_rel_memory_address() as usize;
            if !self.pe.raise_exception_iats().contains(&slot) {
                continue;
            }
            let value = self.pe.u64(slot)? as usize;
            let bound = match self.binding {
                #[cfg(test)]
                Binding::DeclaredDisk => value < self.pe.image_len(),
                Binding::Loaded(expected) => expected != 0 && value == expected,
            };
            if bound
                && states[n]
                    .as_ref()
                    .and_then(|state| state.get(&Register::RDX))
                    .is_some_and(|flags| *flags == 1)
            {
                graph.anchors.insert(n);
            }
        }
        Ok(graph)
    }

    fn prove(&mut self, root: usize) -> bool {
        if let Some(&value) = self.cache.get(&root) {
            self.stats.cache_hits += 1;
            return value;
        }
        // Iterative dependency traversal prevents native recursion/stack
        // overflow. Explore the nearest unresolved call first. If it may
        // return, continue backwards on the next pass: an earlier throwing
        // call can still make a later return unreachable.
        let mut nodes = HashMap::new();
        let mut pending = vec![root];
        let mut seen = HashSet::new();
        let mut proven = HashSet::new();
        loop {
            while let Some(rva) = pending.pop() {
                if self.cache.contains_key(&rva) || !seen.insert(rva) {
                    continue;
                }
                if self.pe.function(rva).is_err() {
                    continue;
                }
                self.stats.functions_examined += 1;
                if let Ok(graph) = self.graph(rva) {
                    nodes.insert(rva, graph);
                } else {
                    self.cache.insert(rva, false);
                }
            }
            loop {
                let mut changed = false;
                for (&rva, node) in &nodes {
                    if !proven.contains(&rva)
                        && node.good(|target| {
                            proven.contains(&target) || self.cache.get(&target) == Some(&true)
                        })[0]
                    {
                        proven.insert(rva);
                        changed = true;
                    }
                }
                if !changed {
                    break;
                }
            }
            for node in nodes.values() {
                let good = node.good(|target| {
                    proven.contains(&target) || self.cache.get(&target) == Some(&true)
                });
                if !good[0] {
                    pending.extend(node.terminal_dependencies(&good, |target| {
                        seen.contains(&target)
                            || self.cache.contains_key(&target)
                            || self.pe.function(target).is_err()
                    }));
                }
            }
            if pending.is_empty() {
                break;
            }
        }
        for (rva, node) in &nodes {
            let positive = proven.contains(rva);
            if positive {
                match self.proof_snapshot(*rva) {
                    Ok(snapshot) if snapshot.1 == node.code => {
                        self.proof_bytes.insert(*rva, snapshot);
                    }
                    Ok(_) | Err(_) => {
                        // Failed evidence invalidates every dependent positive
                        // result from this traversal, not just this function.
                        self.cache.clear();
                        self.proof_bytes.clear();
                        return false;
                    }
                }
            }
            self.cache.insert(*rva, positive);
        }
        self.stats.proven_functions += proven.len();
        self.cache.get(&root) == Some(&true)
    }

    pub(super) fn plan(&mut self, rva: usize, code: &[u8]) -> Result<Plan> {
        self.validate_proof_cache()?;
        let decoded = super::native_switch::decode(code, rva)?;
        let ins = &decoded.instructions;
        let mut plan = Plan::default();
        plan.switch_edges = decoded.switch_edges;
        if !plan.switch_edges.is_empty() {
            plan.code_bytes = Some(decoded.code_bytes);
        }
        for i in ins {
            if is_call(i) && direct(i).is_some_and(|target| self.prove(target)) {
                plan.terminal_calls.insert(i.ip() as usize);
            }
        }
        if plan.terminal_calls.is_empty() && plan.switch_edges.is_empty() {
            return Ok(plan);
        }
        let result = self.caller_eh(rva, code, ins, &decoded.protected_ranges, &mut plan);
        if result.is_err() {
            self.stats.unsupported_callers += 1;
        }
        result?;
        self.stats.planned_callers += 1;
        self.stats.terminal_calls += plan.terminal_calls.len();
        self.stats.exceptional_edges +=
            plan.exceptional_edges.values().map(Vec::len).sum::<usize>();
        self.stats.switch_dispatches += plan.switch_edges.len();
        self.stats.switch_targets += plan.switch_edges.values().map(Vec::len).sum::<usize>();
        Ok(plan)
    }

    pub(super) fn exception_plan(&self, rva: usize, code: &[u8]) -> Result<Plan> {
        let decoded = super::native_switch::decode(code, rva)?;
        let mut plan = Plan {
            switch_edges: decoded.switch_edges,
            code_bytes: (!decoded.protected_ranges.is_empty()).then_some(decoded.code_bytes),
            ..Plan::default()
        };
        self.caller_eh(
            rva,
            code,
            &decoded.instructions,
            &decoded.protected_ranges,
            &mut plan,
        )?;
        ensure!(
            plan.funcinfo_rva.is_some() && plan.handler_rva.is_some(),
            "allocator wrapper has no proved exception handler"
        );
        Ok(plan)
    }

    fn caller_eh(
        &self,
        rva: usize,
        code: &[u8],
        ins: &[Instruction],
        protected_ranges: &[std::ops::Range<usize>],
        plan: &mut Plan,
    ) -> Result<()> {
        let f = self.pe.function(rva)?;
        ensure!(
            rva.checked_add(code.len()) == Some(f.end)
                && self.pe.bytes(f.start, f.end - f.start)? == code,
            "caller body differs from the complete current runtime function"
        );
        let unwind = self.unwind(f)?;
        if unwind.flags == 0 {
            return Ok(());
        }
        ensure!(
            unwind.local_size != usize::MAX,
            "unsupported EH stack frame"
        );
        let handler = self.pe.u32(unwind.data)? as usize;
        self.fh3_adapter(handler)?;
        let fi = self.pe.u32(unwind.data + 4)? as usize;
        self.pe.bytes(fi, 40)?;
        ensure!(
            self.pe.u32(fi)? == 0x19930522
                && self.pe.u32(fi + 36)? == 1
                && self.pe.u32(fi + 32)? == 0,
            "unsupported MSVC EH metadata version/flags"
        );
        let count = usize::try_from(self.pe.i32(fi + 4)?).context("negative unwind-map count")?;
        let unw = self.pe.u32(fi + 8)? as usize;
        self.pe
            .bytes(unw, count.checked_mul(8).context("unwind-map overflow")?)?;
        for index in 0..count {
            let state = self.pe.i32(unw + index * 8)?;
            ensure!(
                state >= -1 && state < (index as i32) && self.pe.u32(unw + index * 8 + 4)? == 0,
                "unsupported EH unwind action/state"
            );
        }
        let tries = self.pe.u32(fi + 12)? as usize;
        let try_map = self.pe.u32(fi + 16)? as usize;
        self.pe
            .bytes(try_map, tries.checked_mul(20).context("try-map overflow")?)?;
        let ip_count = self.pe.u32(fi + 20)? as usize;
        let ip_map = self.pe.u32(fi + 24)? as usize;
        ensure!(ip_count > 0, "empty EH IP map");
        self.pe
            .bytes(ip_map, ip_count.checked_mul(8).context("IP-map overflow")?)?;
        let mut ips = Vec::with_capacity(ip_count);
        let mut previous = 0;
        for n in 0..ip_count {
            let ip = self.pe.u32(ip_map + n * 8)? as usize;
            let state = self.pe.i32(ip_map + n * 8 + 4)?;
            ensure!(
                ip >= rva
                    && ip >= previous
                    && self.pe.executable(ip, 1)
                    && state >= -1
                    && (state < 0 || (state as usize) < count),
                "invalid EH IP/state entry"
            );
            if n == 0 {
                ensure!(ip == rva, "IP map does not start at caller entry");
            }
            previous = ip;
            ips.push((ip, state));
        }
        let mut handlers = Vec::new();
        plan.try_blocks = tries;
        for n in 0..tries {
            let at = try_map + n * 20;
            let low = self.pe.i32(at)?;
            let high = self.pe.i32(at + 4)?;
            let catch_high = self.pe.i32(at + 8)?;
            ensure!(
                low >= 0 && low <= high && high < catch_high && (catch_high as usize) < count,
                "invalid EH try state interval"
            );
            let catches = self.pe.u32(at + 12)? as usize;
            let map = self.pe.u32(at + 16)? as usize;
            ensure!(catches > 0, "empty catch map");
            self.pe
                .bytes(map, catches.checked_mul(20).context("catch-map overflow")?)?;
            let mut continuations = Vec::new();
            for h in 0..catches {
                plan.catch_handlers = plan
                    .catch_handlers
                    .checked_add(1)
                    .context("catch-handler count overflow")?;
                let at = map + h * 20;
                // Resumable/CLR filters have additional semantics. Current
                // ordinary by-reference typed catches use HT_IsReference=8.
                ensure!(
                    self.pe.u32(at)? & !0x0f == 0,
                    "unsupported catch adjectives"
                );
                let descriptor = self.pe.u32(at + 4)? as usize;
                if descriptor != 0 {
                    self.pe.bytes(descriptor, 16)?;
                }
                let funclet = self.pe.u32(at + 12)? as usize;
                let continuation =
                    self.funclet(funclet, unwind.local_size, &unwind.saved_ranges)?;
                if let Some(previous) = plan.catch_funclets.insert(funclet, continuation) {
                    ensure!(
                        previous == continuation,
                        "catch funclet has inconsistent continuations"
                    );
                }
                ensure!(
                    ins.iter().any(|i| i.ip() as usize == continuation)
                        && !protected_ranges
                            .iter()
                            .any(|range| range.contains(&continuation)),
                    "catch continuation outside caller instruction boundaries"
                );
                continuations.push(continuation);
            }
            continuations.sort_unstable();
            continuations.dedup();
            handlers.push((low, high, continuations));
        }
        // Include EH transitions for every possibly throwing call, including
        // ordinary indirect calls. Removing just the normal edge must never
        // hide a catch path and its later owner writes.
        for i in ins.iter().filter(|i| is_call(i)) {
            let site = i.ip() as usize;
            // Windows dispatch uses the call's return IP, with the return-IP
            // boundary interpreted as the immediately preceding byte.
            let dispatch = (i.next_ip() as usize)
                .checked_sub(1)
                .context("call IP overflow")?;
            let state = ips[ips
                .partition_point(|(ip, _)| *ip <= dispatch)
                .checked_sub(1)
                .context("call outside EH IP map")?]
            .1;
            let targets = plan.exceptional_edges.entry(site).or_default();
            for (low, high, continuations) in &handlers {
                if *low <= state && state <= *high {
                    targets.extend(continuations);
                }
            }
            targets.sort_unstable();
            targets.dedup();
        }
        plan.exceptional_edges
            .retain(|_, targets| !targets.is_empty());
        plan.funcinfo_rva = Some(fi);
        plan.handler_rva = Some(handler);
        Ok(())
    }

    fn fh3_adapter(&self, rva: usize) -> Result<()> {
        // Reviewed MSVC x64 FH3 dispatcher shim. Only the four rel32 call
        // operands vary; the metadata consumer/register/stack layout must
        // match. Other language-handler profiles retain the old CFG.
        const HEX: &str = "488bc4488958104889681848897020574883ec40498b5908498bf9498bf048895008488be9e80000000048895860488b5d38e80000000048895868e800000000488b4f384c8bcf4c8bc68b11488bcd4803506033c0884424384889442430894424284889542420488d542450e800000000488b5c2458488b6c2460488b7424684883c4405fc3";
        let expected: Vec<_> = (0..HEX.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&HEX[n..n + 2], 16).unwrap())
            .collect();
        let f = self.pe.function(rva)?;
        let code = self.pe.bytes(f.start, f.end - f.start)?;
        ensure!(
            code.len() == expected.len() && self.unwind(f)?.flags == 0,
            "unsupported C++ language-handler body"
        );
        let offsets = [0x26usize, 0x33, 0x3c, 0x6d];
        ensure!(
            code.iter()
                .zip(&expected)
                .enumerate()
                .all(
                    |(n, (a, b))| offsets.iter().any(|start| *start <= n && n < *start + 4)
                        || a == b
                ),
            "unsupported C++ language-handler profile"
        );
        let calls: Vec<_> = decode(code, rva)?
            .into_iter()
            .filter(|i| is_call(i))
            .collect();
        ensure!(calls.len() == 4, "invalid C++ dispatcher calls");
        ensure!(
            direct(&calls[0]) == direct(&calls[1]) && direct(&calls[1]) == direct(&calls[2]),
            "inconsistent dispatcher TLS helper"
        );
        let mut helpers = Vec::new();
        for i in calls {
            let target = direct(&i).context("indirect C++ dispatcher helper")?;
            let resolved = if self.pe.function(target).is_err() {
                // This reviewed dispatcher can call a leaf rel32 tail thunk.
                // Its entry must lie outside every runtime-function body;
                // its entire executed body is one JMP to an exact PE entry.
                ensure!(
                    self.pe.containing_function(target).is_none() && self.pe.executable(target, 5),
                    "dispatcher helper points inside another function"
                );
                let code = self.pe.bytes(target, 5)?;
                let jump = Decoder::with_ip(64, code, target as u64, DecoderOptions::NONE).decode();
                ensure!(
                    !jump.is_invalid()
                        && jump.len() == 5
                        && jump.flow_control() == FlowControl::UnconditionalBranch,
                    "unsupported dispatcher helper thunk"
                );
                let resolved = direct(&jump).context("indirect dispatcher thunk")?;
                self.pe.function(resolved)?;
                resolved
            } else {
                target
            };
            helpers.push(resolved);
        }
        self.fh3_runtime_helper(helpers[0], false)?;
        self.fh3_runtime_helper(helpers[3], true)?;
        Ok(())
    }

    fn fh3_runtime_helper(&self, rva: usize, consumer: bool) -> Result<()> {
        // Explicitly reviewed compiler-runtime profiles, not arbitrary PE
        // entries or method/RVA allowlists. Full bytes (including relative
        // calls) are intentional: another build requires a new review.
        // Standard MSVC runtime helper semantics remain the trust boundary;
        // this does not prove custom OS handlers or context modifications.
        const TLS: &str = "4883ec28e8130000004885c074054883c428c3e83c06ffffcc";
        const FH3: &str = "488bc44889580848896810488970184889782041564883ec50488bf9498bf1498bc84d8bf0488beae897e4ffffe8e2e1ffff488b9c2480000000b929000080ba26000080837840007538813f63736de07430390f7510837f180f750e48817f6020059319741c391774188b0325ffffff1f3d22059319720af64324010f858f010000f64704660f848e000000837b04000f847b01000083bc2488000000000f856d010000f6470420745d391775374c8b4620488bd6488bcbe847e4ffff83f8ff0f8c6b0100003b43040f8d62010000448bc8488bcd488bd64c8bc3e824ebffffe92c010000390f751e448b4f384183f9ff0f8c3a010000443b4b040f8d30010000488b4f28ebce4c8bc3488bd6488bcde82367fdffe9f7000000837b0c0075428b0325ffffff1f3d210593197214837b2000740ee85f6dfdff48634b204803c175208b0325ffffff1f3d220593190f82bd0000008b4324c1e802a8010f84af000000813f63736de0756e837f18037268817f2022059319765f488b4730837808007455e83c6dfdff488b4f304c8bd0486351084c03d274400fb68c24980000004c8bce8b8424880000004d8bc6894c2438488bd5488b8c249000000048894c2430488bcf89442428498bc248895c2420ff15daed1a07eb3e488b8424900000004c8bce48894424384d8bc68b842488000000488bd589442430488bcf8a8424980000008844242848895c2420e8bb020000b801000000488b5c2460488b6c2468488b742470488b7c24784883c450415ec3e832e6feffcc";
        let hex = if consumer { FH3 } else { TLS };
        let expected: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&hex[n..n + 2], 16).unwrap())
            .collect();
        let f = self.pe.function(rva)?;
        ensure!(
            self.unwind(f)?.flags == 0 && self.pe.bytes(f.start, f.end - f.start)? == expected,
            "unsupported MSVC FH3 {} helper profile",
            if consumer { "metadata consumer" } else { "TLS" }
        );
        decode(&expected, rva)?;
        Ok(())
    }

    fn funclet(
        &self,
        rva: usize,
        local_size: usize,
        saved_ranges: &[(usize, usize)],
    ) -> Result<usize> {
        let f = self.pe.function(rva)?;
        let ins = decode(self.pe.bytes(f.start, f.end - f.start)?, rva)?;
        let mut bases = BTreeMap::from([
            (Register::RSP, (false, 0i64)),
            (Register::RDX, (true, 0i64)),
        ]);
        let mut pushed = Vec::new();
        let mut allocations = Vec::<(i64, i64)>::new();
        let mut stack = 0i64;
        let mut continuation = None;
        let mut factory = InstructionInfoFactory::new();
        for (n, i) in ins.iter().enumerate() {
            ensure!(
                matches!(i.flow_control(), FlowControl::Next | FlowControl::Return),
                "catch funclet has calls/branches/unknown control flow"
            );
            ensure!(
                !i.has_rep_prefix() && !i.has_repne_prefix(),
                "catch has a repeated memory operation"
            );
            if i.flow_control() == FlowControl::Return {
                ensure!(
                    i.mnemonic() == Mnemonic::Ret
                        && i.op_count() == 0
                        && n + 1 == ins.len()
                        && stack == 0
                        && pushed.is_empty()
                        && allocations.is_empty(),
                    "catch funclet does not restore its stack/registers"
                );
                return continuation.context("unknown catch continuation");
            }
            let push = i.mnemonic() == Mnemonic::Push
                && i.op0_kind() == OpKind::Register
                && i.op0_register().size() == 8
                && i.op0_register() != Register::RSP;
            let pop = i.mnemonic() == Mnemonic::Pop
                && i.op0_kind() == OpKind::Register
                && i.op0_register().size() == 8
                && i.op0_register() != Register::RSP;
            let adjust = matches!(i.mnemonic(), Mnemonic::Sub | Mnemonic::Add)
                && i.op0_kind() == OpKind::Register
                && i.op0_register() == Register::RSP;
            for r in factory.info(i).used_registers() {
                ensure!(
                    !writes(r.access())
                        || r.register().full_register() != Register::RSP
                        || push
                        || pop
                        || adjust,
                    "catch has an unknown RSP modification"
                );
            }
            for memory in factory
                .info(i)
                .used_memory()
                .iter()
                .filter(|m| writes(m.access()))
            {
                let (parent, base) = bases
                    .get(&memory.base())
                    .copied()
                    .context("catch writes an unknown object")?;
                ensure!(
                    memory.index() == Register::None
                        && !matches!(memory.segment(), Register::FS | Register::GS)
                        && memory.memory_size().size() > 0,
                    "unknown catch write extent"
                );
                let start = base
                    .checked_add(memory.displacement() as i64)
                    .context("catch frame offset overflow")?;
                let end = start
                    .checked_add(memory.memory_size().size() as i64)
                    .context("catch write overflow")?;
                if parent {
                    let start = usize::try_from(start).context("negative parent frame write")?;
                    let end = usize::try_from(end).context("parent frame write overflow")?;
                    ensure!(
                        end <= local_size
                            && saved_ranges
                                .iter()
                                .all(|&(low, high)| end <= low || start >= high),
                        "catch writes outside parent locals or into saved registers"
                    );
                } else if !push {
                    ensure!(
                        (8 <= start && end <= 40)
                            || allocations
                                .iter()
                                .any(|&(low, high)| low <= start && end <= high),
                        "catch overwrites its saved registers or return address"
                    );
                }
            }
            let assigned = if i.mnemonic() == Mnemonic::Lea
                && i.op0_kind() == OpKind::Register
                && i.op0_register().size() == 8
                && i.memory_index() == Register::None
            {
                if i.is_ip_rel_memory_operand() {
                    if i.op0_register() == Register::RAX {
                        continuation = Some(i.ip_rel_memory_address() as usize);
                    }
                    None
                } else {
                    bases.get(&i.memory_base()).and_then(|(parent, offset)| {
                        offset
                            .checked_add(i.memory_displacement64() as i64)
                            .map(|offset| (*parent, offset))
                    })
                }
            } else if i.mnemonic() == Mnemonic::Mov
                && i.op0_kind() == OpKind::Register
                && i.op1_kind() == OpKind::Register
                && i.op0_register().size() == 8
            {
                bases.get(&i.op1_register()).copied()
            } else {
                None
            };
            if i.mnemonic() == Mnemonic::Push {
                ensure!(push, "unsupported catch push");
                stack = stack.checked_sub(8).context("catch stack overflow")?;
                pushed.push((i.op0_register(), stack));
            } else if i.mnemonic() == Mnemonic::Pop {
                ensure!(
                    pop && pushed.pop() == Some((i.op0_register(), stack)),
                    "catch nonvolatile restore mismatch"
                );
                stack = stack.checked_add(8).context("catch stack overflow")?;
            } else if adjust {
                let size = match i.op1_kind() {
                    OpKind::Immediate8to64 => i.immediate8to64(),
                    OpKind::Immediate32to64 => i.immediate32to64(),
                    _ => anyhow::bail!("unknown catch stack adjustment"),
                };
                ensure!(size > 0, "invalid catch stack adjustment");
                let next = if i.mnemonic() == Mnemonic::Sub {
                    let next = stack.checked_sub(size).context("catch stack overflow")?;
                    allocations.push((next, stack));
                    next
                } else {
                    let next = stack.checked_add(size).context("catch stack overflow")?;
                    ensure!(
                        allocations.pop() == Some((stack, next)),
                        "catch stack allocation restore mismatch"
                    );
                    next
                };
                stack = next;
            }
            let preserve_continuation = i.mnemonic() == Mnemonic::Lea
                && i.op0_register() == Register::RAX
                && i.is_ip_rel_memory_operand();
            for r in factory.info(i).used_registers() {
                if writes(r.access()) {
                    if matches!(
                        r.register().full_register(),
                        Register::RBX
                            | Register::RBP
                            | Register::RSI
                            | Register::RDI
                            | Register::R12
                            | Register::R13
                            | Register::R14
                            | Register::R15
                    ) && i.mnemonic() != Mnemonic::Pop
                    {
                        ensure!(
                            pushed
                                .iter()
                                .any(|&(register, _)| register == r.register().full_register()),
                            "catch changes an unsaved nonvolatile register"
                        );
                    }
                    bases.remove(&r.register().full_register());
                    if r.register().full_register() == Register::RAX && !preserve_continuation {
                        continuation = None;
                    }
                }
            }
            if let Some(base) = assigned {
                bases.insert(i.op0_register().full_register(), base);
            }
            bases.insert(Register::RSP, (false, stack));
        }
        anyhow::bail!("catch funclet has no normal return")
    }
}

#[cfg(test)]
#[path = "native_flow_replay.rs"]
mod native_flow_replay;

#[cfg(test)]
mod tests {
    use super::super::sync_scan::{self, Mode};
    use super::*;
    use std::{fs, path::PathBuf, time::Instant};

    fn readable(_: usize, _: usize) -> Result<()> {
        Ok(())
    }
    fn word(image: &mut [u8], at: usize, value: u32) {
        image[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture(code: &[u8]) -> Vec<u8> {
        let mut image = vec![0; 0x1000];
        image[..2].copy_from_slice(b"MZ");
        word(&mut image, 0x3c, 0x80);
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        let opt = 0x98;
        image[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[opt + 24..opt + 32].copy_from_slice(&0x180000000u64.to_le_bytes());
        word(&mut image, opt + 56, 0x1000);
        word(&mut image, opt + 60, 0x200);
        word(&mut image, opt + 108, 16);
        word(&mut image, opt + 120, 0x200);
        word(&mut image, opt + 124, 40);
        word(&mut image, opt + 136, 0x300);
        word(&mut image, opt + 140, 12);
        let section = opt + 240;
        word(&mut image, section + 8, 0xe00);
        word(&mut image, section + 12, 0x200);
        word(&mut image, section + 16, 0xe00);
        word(&mut image, section + 36, 0x60000020);
        word(&mut image, 0x200, 0x240);
        word(&mut image, 0x20c, 0x280);
        word(&mut image, 0x210, 0x260);
        image[0x240..0x248].copy_from_slice(&0x2b0u64.to_le_bytes());
        image[0x260..0x268].copy_from_slice(&0x2b0u64.to_le_bytes());
        image[0x280..0x28d].copy_from_slice(b"KERNEL32.dll\0");
        image[0x2b2..0x2c1].copy_from_slice(b"RaiseException\0");
        image[0x2e0] = 1;
        word(&mut image, 0x300, 0x800);
        word(&mut image, 0x304, 0x800 + code.len() as u32);
        word(&mut image, 0x308, 0x2e0);
        image[0x800..0x800 + code.len()].copy_from_slice(code);
        image
    }
    fn raise(mut prefix: Vec<u8>) -> Vec<u8> {
        let next = 0x800 + prefix.len() + 6;
        let displacement = (0x260i64 - next as i64) as i32;
        prefix.extend([0xff, 0x15]);
        prefix.extend(displacement.to_le_bytes());
        prefix.push(0xc3);
        prefix
    }
    fn proves(code: &[u8], binding: Binding) -> bool {
        let image = fixture(code);
        let pe = Pe::new(&image, readable).unwrap();
        Resolver::new(pe, binding).prove(0x800)
    }
    #[test]
    fn noncontinuable_argument_and_current_import_binding_are_both_required() {
        let noncontinuable = raise(vec![0xba, 1, 0, 0, 0]);
        assert!(proves(&noncontinuable, Binding::DeclaredDisk));
        assert!(!proves(&noncontinuable, Binding::Loaded(0x777777)));
        assert!(!proves(
            &raise(vec![0xba, 0, 0, 0, 0]),
            Binding::DeclaredDisk
        ));
        assert!(!proves(
            &raise(vec![0xba, 1, 0, 0, 0, 0x31, 0xd2]),
            Binding::DeclaredDisk
        ));
        assert!(!proves(
            &raise(vec![
                0x85, 0xc9, 0x74, 7, 0xba, 1, 0, 0, 0, 0xeb, 5, 0xba, 0, 0, 0, 0
            ]),
            Binding::DeclaredDisk
        ));
    }
    #[test]
    fn traps_cycles_and_a_literal_return_are_not_termination_proofs() {
        for code in [&[0xcc][..], &[0xeb, 0xfe][..], &[0xc3][..]] {
            assert!(!proves(code, Binding::DeclaredDisk));
        }
    }
    #[test]
    fn a_legal_pe_entry_is_not_an_fh3_consumer() {
        let image = fixture(&[0xc3]);
        let resolver = Resolver::new(Pe::new(&image, readable).unwrap(), Binding::DeclaredDisk);
        assert!(resolver.pe.function(0x800).is_ok());
        assert!(resolver.fh3_runtime_helper(0x800, true).is_err());
        assert!(resolver.fh3_runtime_helper(0x800, false).is_err());
    }
    #[test]
    fn changed_cached_code_or_api_binding_invalidates_all_proofs() {
        let code = raise(vec![0xba, 1, 0, 0, 0]);
        let image = fixture(&code);
        let mut resolver =
            Resolver::new(Pe::new(&image, readable).unwrap(), Binding::Loaded(0x2b0));
        assert!(resolver.prove(0x800));
        assert!(resolver.validate_proof_cache().is_ok());
        // Simulate disagreement with the captured bytes without mutating an
        // aliased Rust slice. Every positive dependency must be discarded.
        resolver.proof_bytes.get_mut(&0x800).unwrap().1[0] ^= 1;
        assert!(resolver.validate_proof_cache().is_err());
        assert!(resolver.cache.is_empty() && resolver.proof_bytes.is_empty());
        assert!(resolver.prove(0x800));
        resolver.binding = Binding::Loaded(0xdeadbeef);
        assert!(resolver.validate_proof_cache().is_err());
        assert!(resolver.cache.is_empty() && resolver.proof_bytes.is_empty());
    }
    fn relative(code: &mut Vec<u8>, rva: usize, opcode: &[u8], target: usize) {
        let next = rva + code.len() + opcode.len() + 4;
        code.extend(opcode);
        code.extend(((target as i64 - next as i64) as i32).to_le_bytes());
    }
    #[test]
    fn an_earlier_throw_is_found_after_a_later_may_return_call() {
        let mut root = Vec::new();
        relative(&mut root, 0x800, &[0xe8], 0x880);
        relative(&mut root, 0x800, &[0xe8], 0x900);
        root.push(0xc3);
        let mut throw = vec![0xba, 1, 0, 0, 0];
        relative(&mut throw, 0x880, &[0xff, 0x15], 0x260);
        throw.push(0xc3);
        let mut image = fixture(&root);
        word(&mut image, 0x98 + 140, 36);
        for (n, (rva, code)) in [(0x880, throw.as_slice()), (0x900, &[0xc3][..])]
            .into_iter()
            .enumerate()
        {
            let at = 0x30c + n * 12;
            word(&mut image, at, rva as u32);
            word(&mut image, at + 4, (rva + code.len()) as u32);
            word(&mut image, at + 8, 0x2e0);
            image[rva..rva + code.len()].copy_from_slice(code);
        }
        let mut resolver = Resolver::new(Pe::new(&image, readable).unwrap(), Binding::DeclaredDisk);
        assert!(resolver.prove(0x800));
        assert!(resolver.prove(0x880));
        assert!(!resolver.prove(0x900));
    }
    fn funclet_code(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut code = prefix.to_vec();
        relative(&mut code, 0x800, &[0x48, 0x8d, 0x05], 0x950);
        code.extend(suffix);
        code
    }
    #[test]
    fn catch_protects_saved_registers_return_address_and_rsp() {
        let good = funclet_code(
            &[0x56, 0x48, 0x83, 0xec, 0x20, 0xc7, 4, 0x24, 0, 0, 0, 0],
            &[0x48, 0x83, 0xc4, 0x20, 0x5e, 0xc3],
        );
        let image = fixture(&good);
        let resolver = Resolver::new(Pe::new(&image, readable).unwrap(), Binding::DeclaredDisk);
        assert_eq!(resolver.funclet(0x800, 104, &[]).unwrap(), 0x950);
        let cases = [
            // Overwrite the saved RSI, directly or through an alias.
            funclet_code(&[0x56, 0xc7, 4, 0x24, 0, 0, 0, 0], &[0x5e, 0xc3]),
            funclet_code(
                &[0x56, 0x48, 0x89, 0xe0, 0xc7, 0, 0, 0, 0, 0],
                &[0x5e, 0xc3],
            ),
            // Overwrite the return address; adjust RSP outside the model.
            funclet_code(&[0xc7, 4, 0x24, 0, 0, 0, 0], &[0xc3]),
            funclet_code(&[0x48, 0x8d, 0x64, 0x24, 8], &[0xc3]),
            funclet_code(&[], &[0xc2, 8, 0]),
            // REP writes have an unknown extent even with a known pointer.
            funclet_code(&[0x57, 0x48, 0x89, 0xd7, 0xf3, 0xab], &[0x5f, 0xc3]),
            // A pop cannot consume an allocated local slot.
            funclet_code(&[0x56, 0x48, 0x83, 0xec, 8], &[0x5e, 0xc3]),
        ];
        for code in cases {
            let image = fixture(&code);
            let resolver = Resolver::new(Pe::new(&image, readable).unwrap(), Binding::DeclaredDisk);
            assert!(
                resolver.funclet(0x800, 104, &[]).is_err(),
                "accepted unsafe catch: {code:02x?}"
            );
        }
    }
    fn unwind_fixture(
        code: &[u8],
        prolog_size: u8,
        slot_count: usize,
        frame: u8,
        slots: &[u8],
    ) -> Result<Unwind> {
        let mut image = fixture(code);
        word(&mut image, 0x308, 0x400);
        image[0x400] = 1;
        image[0x401] = prolog_size;
        image[0x402] = u8::try_from(slot_count)?;
        image[0x403] = frame;
        image[0x404..0x404 + slots.len()].copy_from_slice(slots);
        let pe = Pe::new(&image, readable)?;
        let function = pe.function(0x800)?;
        Resolver::new(pe, Binding::DeclaredDisk).unwind(function)
    }
    fn gridfight_unwind_slots() -> [u8; 36] {
        [
            0x19, 0x25, 0x0f, 0x85, 0x25, 0x68, 0x0d, 0x00, 0x20, 0x78, 0x0e, 0x00, 0x1b, 0x03,
            0x13, 0x01, 0x1f, 0x00, 0x0c, 0x30, 0x0b, 0x70, 0x0a, 0x60, 0x09, 0xc0, 0x07, 0xd0,
            0x05, 0xe0, 0x03, 0xf0, 0x01, 0x50, 0x00, 0x00,
        ]
    }
    #[test]
    fn gridfight_save_xmm128_unwind_and_parent_catch_write_are_supported() -> Result<()> {
        let record = gridfight_unwind_slots();
        let unwind = unwind_fixture(&[0xc3; 37], record[1], 15, record[3], &record[4..])?;
        assert_eq!(unwind.flags, 0);
        assert_eq!(unwind.local_size, 0xf8);
        assert_eq!(unwind.saved_ranges, [(0xd0, 0xe0), (0xe0, 0xf0)]);
        let wrapper_slots = [10, 0x03, 5, 0x52, 1, 0x50];
        let wrapper = unwind_fixture(&[0xc3; 37], 10, 3, 0x35, &wrapper_slots)?;
        assert_eq!(
            wrapper.operations,
            [
                UnwindCode {
                    code_offset: 10,
                    operation: UnwindOperation::SetFrameRegister,
                },
                UnwindCode {
                    code_offset: 5,
                    operation: UnwindOperation::Allocate(0x30),
                },
                UnwindCode {
                    code_offset: 1,
                    operation: UnwindOperation::PushNonvolatile(Register::RBP),
                },
            ]
        );
        assert!(unwind_fixture(&[0xc3; 37], 10, 3, 0x35, &[1, 0x50, 10, 0x03, 5, 0x52]).is_err());
        assert!(unwind_fixture(&[0xc3; 37], 10, 3, 0x31, &wrapper_slots).is_err());

        // Mirrors the GridFight funclet's RBP=RDX+0x80 parent-frame write.
        let catch = funclet_code(
            &[
                0x55, 0x48, 0x8d, 0xaa, 0x80, 0, 0, 0, 0x48, 0x89, 0x5d, 0x08,
            ],
            &[0x5d, 0xc3],
        );
        let image = fixture(&catch);
        let resolver = Resolver::new(Pe::new(&image, readable)?, Binding::DeclaredDisk);
        assert_eq!(
            resolver.funclet(0x800, unwind.local_size, &unwind.saved_ranges)?,
            0x950
        );
        Ok(())
    }
    #[test]
    fn save_xmm128_rejects_malformed_or_unsafe_unwind_slots() {
        let cases: &[(&str, &[u8])] = &[
            // UWOP_SAVE_XMM128 consumes the following 16-bit slot.
            ("truncated slots", &[5, 0x68]),
            // XMM5 is volatile and cannot use UWOP_SAVE_XMM128.
            ("invalid register", &[5, 0x58, 13, 0, 4, 1, 31, 0]),
            // CodeOffset must identify a completed operation within the prolog.
            ("code offset beyond prolog", &[6, 0x68, 13, 0, 4, 1, 31, 0]),
            // Offset 0xF0 plus the 16-byte save exceeds this 0xF8 allocation.
            ("outside local allocation", &[5, 0x68, 15, 0, 4, 1, 31, 0]),
            // The two distinct XMM registers claim the same saved bytes.
            (
                "overlapping ranges",
                &[5, 0x68, 13, 0, 4, 0x78, 13, 0, 3, 1, 31, 0],
            ),
        ];
        for (name, slots) in cases {
            assert!(
                unwind_fixture(&[0xc3; 16], 5, slots.len() / 2, 0, slots).is_err(),
                "accepted malformed save-xmm unwind: {name}"
            );
        }
    }
    #[test]
    fn catch_rejects_writes_that_overlap_saved_xmm_ranges_through_aliases() {
        let saved = [(0xd0, 0xe0), (0xe0, 0xf0)];
        let cases = [
            // An eight-byte write beginning at 0xCC crosses into the first slot.
            funclet_code(&[0x48, 0x8d, 0x42, 0xcc, 0x48, 0x89, 0x18], &[]),
            // Alias RDX through RAX, then write wholly inside the first slot.
            funclet_code(
                &[
                    0x48, 0x89, 0xd0, 0x48, 0x8d, 0x80, 0xd8, 0, 0, 0, 0x48, 0x89, 0x18,
                ],
                &[],
            ),
        ];
        for code in cases {
            let image = fixture(&code);
            let resolver = Resolver::new(Pe::new(&image, readable).unwrap(), Binding::DeclaredDisk);
            assert!(
                resolver.funclet(0x800, 0xf8, &saved).is_err(),
                "accepted catch write into saved XMM area: {code:02x?}"
            );
        }
    }
    #[test]
    fn terminal_call_keeps_catch_overwrites_and_rejects_stale_edges() {
        let code = [
            0x48, 0x89, 0xd7, 0x48, 0x89, 0xce, 0x8b, 0x47, 0x24, 0x89, 0x46, 0x20, 0xe8, 0, 0, 0,
            0, 0xc3, 0xc7, 0x46, 0x20, 0, 0, 0, 0, 0xc3,
        ];
        let terminals = BTreeSet::from([0x100c]);
        let edges = BTreeMap::from([(0x100c, vec![0x1012])]);
        assert!(
            sync_scan::scan_controlled(&code, 0x1000, Mode::Sync, &terminals, &edges)
                .copies
                .is_empty()
        );
        let stale = BTreeMap::from([(0x100c, vec![0x1013])]);
        assert!(
            sync_scan::scan_controlled(&code, 0x1000, Mode::Sync, &terminals, &stale).ambiguous
        );
    }
    fn mapped_disk(file: &[u8]) -> Result<Vec<u8>> {
        let read = |at: usize| -> Result<usize> {
            Ok(u32::from_le_bytes(
                file.get(at..at + 4)
                    .context("file header truncated")?
                    .try_into()?,
            ) as usize)
        };
        let pe = read(0x3c)?;
        let opt = pe + 24;
        let size = read(opt + 56)?;
        let headers = read(opt + 60)?;
        let mut image = vec![0; size];
        image
            .get_mut(..headers)
            .context("invalid headers")?
            .copy_from_slice(file.get(..headers).context("file header truncated")?);
        let count = u16::from_le_bytes(file[pe + 6..pe + 8].try_into()?) as usize;
        let table = opt + u16::from_le_bytes(file[pe + 20..pe + 22].try_into()?) as usize;
        for n in 0..count {
            let at = table + n * 40;
            let rva = read(at + 12)?;
            let raw_size = read(at + 16)?;
            let raw = read(at + 20)?;
            if raw_size > 0 {
                image
                    .get_mut(rva..rva.checked_add(raw_size).context("section overflow")?)
                    .context("section outside image")?
                    .copy_from_slice(
                        file.get(raw..raw.checked_add(raw_size).context("raw overflow")?)
                            .context("truncated raw section")?,
                    );
            }
        }
        Ok(image)
    }
    #[test]
    #[ignore = "requires explicit current DLL and output directory; disk-only, no game"]
    fn replay_current_pe_exception_flow() -> Result<()> {
        let dll = PathBuf::from(std::env::var("HSR_PROTO_FLOW_DLL")?);
        let out = PathBuf::from(std::env::var("HSR_PROTO_FLOW_OUT")?);
        let image = mapped_disk(&fs::read(&dll)?)?;
        let pe = Pe::new(&image, readable)?;
        let function_count = pe.function_count();
        let preferred_base = pe.preferred_base();
        let mut resolver = Resolver::new(pe, Binding::DeclaredDisk);
        // This is a regression sample, not a production RVA/name allowlist.
        let f = resolver.pe.function(0xcb98920)?;
        let code = resolver.pe.bytes(f.start, f.end - f.start)?;
        let timer = Instant::now();
        let plan = resolver.plan(f.start, code)?;
        let allocator = resolver.pe.function(0x3eac500)?;
        let allocator_code = resolver
            .pe
            .bytes(allocator.start, allocator.end - allocator.start)?;
        let allocator_plan = resolver.exception_plan(allocator.start, allocator_code)?;
        let allocator_unwind = resolver.unwind_profile(allocator.start)?;
        let catch_unwind = resolver.unwind_profile(0x3eac530)?;
        ensure!(
            allocator_plan.try_blocks == 1
                && allocator_plan.catch_handlers == 1
                && allocator_plan.catch_funclets.get(&0x3eac530) == Some(&0x3eac51b)
                && allocator_plan.exceptional_edges.get(&0x3eac512) == Some(&vec![0x3eac51b]),
            "current allocator FH3 wrapper proof changed"
        );
        ensure!(
            allocator_unwind.flags == 3
                && allocator_unwind.prolog_size == 10
                && allocator_unwind.local_size == 0x30
                && allocator_unwind.frame_register == Some(Register::RBP)
                && allocator_unwind.frame_offset == 0x30
                && allocator_unwind.pushed_nonvolatile == [Register::RBP]
                && catch_unwind.flags == 3
                && catch_unwind.prolog_size == 14
                && catch_unwind.local_size == 0x20
                && catch_unwind.frame_register.is_none()
                && catch_unwind.pushed_nonvolatile == [Register::RBP]
                && allocator_plan.handler_rva == Some(resolver.pe.u32(catch_unwind.data)? as usize)
                && allocator_plan.funcinfo_rva
                    == Some(resolver.pe.u32(catch_unwind.data + 4)? as usize),
            "current allocator/catch unwind frame proof changed"
        );
        let before = sync_scan::scan(code, f.start, Mode::Sync);
        let after = sync_scan::scan_controlled(
            code,
            f.start,
            Mode::Sync,
            &plan.terminal_calls,
            &plan.exceptional_edges,
        );
        let copies: Vec<_> = after
            .copies
            .iter()
            .map(|c| (c.proto_offset, c.business_offset))
            .collect();
        let report = serde_json::json!({"source_dll":dll,"binding":"declared-disk-only","preferred_base":preferred_base,"runtime_functions":function_count,"body_bytes":code.len(),"elapsed_ms":timer.elapsed().as_secs_f64()*1000.0,"plan":plan,"allocator_plan":allocator_plan,"statistics":resolver.stats,"before_copies":before.copies.iter().map(|c|(c.proto_offset,c.business_offset)).collect::<Vec<_>>(),"after_copies":copies,"boundary":"Current native code and supported MSVC FH3/EH metadata only; no runtime reflection, IAT, original-name or in-game verification."});
        fs::create_dir_all(&out)?;
        fs::write(
            out.join("active-flow-replay.json"),
            serde_json::to_vec_pretty(&report)?,
        )?;
        ensure!(
            copies.contains(&(36, 32)) && copies.contains(&(44, 56)) && copies.contains(&(48, 52)),
            "expected scalar/SSE copies missing; inspect replay report"
        );
        assert!(resolver.cache.len() <= function_count);
        Ok(())
    }
}
