//! Native-path evidence for exact scalar copies and accessors. The caller supplies
//! current function bounds and verifies the declared owners and field types.
use iced_x86::{
    Decoder, DecoderOptions, EncodingKind, FlowControl, Instruction, InstructionInfoFactory,
    Mnemonic, OpAccess, OpKind, Register,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Sync,
    Getter,
    Setter,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct CopyEvidence {
    pub proto_offset: u32,
    pub business_offset: u32,
    // One witnessed load that can reach this store. Joined load sites must
    // agree on the source offset; choosing a site never chooses a field.
    pub load_rva: usize,
    pub store_rva: usize,
}

#[derive(Debug, Default)]
pub(super) struct ScanResult {
    pub copies: Vec<CopyEvidence>,
    pub accessor_offset: Option<u32>,
    // Return sites for a getter, direct write sites for a setter.
    pub accessor_sites: Vec<usize>,
    pub decoded: usize,
    pub rejected_paths: usize,
    pub ambiguous: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    BusinessPtr,
    ProtoPtr,
    ProtoField { offset: u32, loads: BTreeSet<usize> },
    BusinessField(u32),
    SetterValue,
    Vector([Option<Lane>; 4]),
}
type State = BTreeMap<Register, Value>;

// A SIMD register contains four separate 32-bit lanes. Missing lanes include
// zeroed bits: those bits are not evidence for another wire field.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Lane {
    ProtoField { offset: u32, loads: BTreeSet<usize> },
    BusinessField(u32),
    SetterValue,
}

fn lane(value: Value) -> Option<Lane> {
    match value {
        Value::ProtoField { offset, loads } => Some(Lane::ProtoField { offset, loads }),
        Value::BusinessField(offset) => Some(Lane::BusinessField(offset)),
        Value::SetterValue => Some(Lane::SetterValue),
        _ => None,
    }
}

fn join_lane(current: &mut Option<Lane>, incoming: &Option<Lane>) {
    match (&mut *current, incoming) {
        (
            Some(Lane::ProtoField { offset, loads }),
            Some(Lane::ProtoField {
                offset: other_offset,
                loads: other_loads,
            }),
        ) if *offset == *other_offset => loads.extend(other_loads),
        (value, other) if value == other => {}
        _ => *current = None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteSource {
    ProtoField(u32),
    SetterValue,
}

struct BusinessWrite {
    start: i64,
    end: Option<i64>,
    source: Option<WriteSource>,
}

impl BusinessWrite {
    fn rejects(&self, offset: u32, expected: WriteSource, bytes: usize) -> bool {
        let start = i64::from(offset);
        let end = start + bytes as i64;
        let Some(write_end) = self.end else {
            // An unknown/repeated write extent cannot prove any destination
            // on this owner untouched.
            return true;
        };
        self.start < end
            && write_end > start
            && !(self.start == start && write_end == end && self.source == Some(expected))
    }
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn direct_offset_width(
    instruction: &Instruction,
    operand: u32,
    state: &State,
    bytes: usize,
) -> Option<(Value, u32)> {
    if instruction.op_kind(operand) != OpKind::Memory
        || instruction.has_segment_prefix()
        || instruction.memory_index() != Register::None
        || instruction.memory_base().size() != 8
        || instruction.memory_size().size() != bytes
    {
        return None;
    }
    let offset = u32::try_from(instruction.memory_displacement64()).ok()?;
    offset.checked_add(u32::try_from(bytes).ok()?)?;
    let owner = state.get(&instruction.memory_base())?;
    matches!(owner, Value::BusinessPtr | Value::ProtoPtr).then(|| (owner.clone(), offset))
}

fn direct_offset(
    instruction: &Instruction,
    operand: u32,
    state: &State,
    bytes: usize,
) -> Option<(Value, u32)> {
    direct_offset_width(instruction, operand, state, bytes)
}

fn vector_copy_width(instruction: &Instruction) -> Option<usize> {
    if instruction.encoding() != EncodingKind::Legacy || instruction.op_count() != 2 {
        return None;
    }
    match instruction.mnemonic() {
        Mnemonic::Movq => Some(8),
        Mnemonic::Movdqa | Mnemonic::Movdqu | Mnemonic::Movaps | Mnemonic::Movups => Some(16),
        _ => None,
    }
}

fn vector_operand(
    instruction: &Instruction,
    index: u32,
    bytes: usize,
    state: &State,
) -> Option<[Option<Lane>; 4]> {
    let mut lanes = match instruction.op_kind(index) {
        OpKind::Register if instruction.op_register(index).is_xmm() => {
            let Value::Vector(lanes) =
                state.get(&instruction.op_register(index).full_register())?
            else {
                return None;
            };
            lanes.clone()
        }
        OpKind::Memory => {
            let (owner, offset) = direct_offset_width(instruction, index, state, bytes)?;
            std::array::from_fn(|index| {
                if index >= bytes / 4 {
                    return None;
                }
                // The complete memory extent was checked above.
                let offset = offset + index as u32 * 4;
                match owner {
                    Value::ProtoPtr => Some(Lane::ProtoField {
                        offset,
                        loads: BTreeSet::from([instruction.ip() as usize]),
                    }),
                    Value::BusinessPtr => Some(Lane::BusinessField(offset)),
                    _ => None,
                }
            })
        }
        _ => return None,
    };
    for item in &mut lanes[bytes / 4..] {
        *item = None;
    }
    Some(lanes)
}

fn vector_assignment(instruction: &Instruction, state: &State) -> Option<Value> {
    if instruction.op0_kind() != OpKind::Register || !instruction.op0_register().is_xmm() {
        return None;
    }
    if let Some(bytes) = vector_copy_width(instruction) {
        return vector_operand(instruction, 1, bytes, state).map(Value::Vector);
    }
    if instruction.encoding() == EncodingKind::Legacy
        && instruction.mnemonic() == Mnemonic::Pshufd
        && instruction.op_count() == 3
        && instruction.op2_kind() == OpKind::Immediate8
    {
        let source = vector_operand(instruction, 1, 16, state)?;
        let order = instruction.immediate8();
        return Some(Value::Vector(std::array::from_fn(|index| {
            source[((order >> (index * 2)) & 3) as usize].clone()
        })));
    }
    None
}

fn known_stores(instruction: &Instruction, state: &State, bytes: usize) -> Vec<(u32, Lane)> {
    if instruction.mnemonic() == Mnemonic::Mov
        && instruction.op_count() == 2
        && instruction.op1_kind() == OpKind::Register
        && instruction.op1_register().size() == bytes
        && let Some((Value::BusinessPtr, offset)) = direct_offset(instruction, 0, state, bytes)
        && let Some(value) = operand(instruction, 1, state, bytes).and_then(lane)
    {
        return vec![(offset, value)];
    }
    if bytes == 4
        && let Some(vector_bytes) = vector_copy_width(instruction)
        && let Some((Value::BusinessPtr, offset)) =
            direct_offset_width(instruction, 0, state, vector_bytes)
        && let Some(lanes) = vector_operand(instruction, 1, vector_bytes, state)
    {
        return lanes
            .into_iter()
            .enumerate()
            .filter_map(|(index, value)| value.map(|value| (offset + index as u32 * 4, value)))
            .collect();
    }
    Vec::new()
}

fn operand(instruction: &Instruction, index: u32, state: &State, bytes: usize) -> Option<Value> {
    match instruction.op_kind(index) {
        OpKind::Register => {
            let register = instruction.op_register(index);
            let value = state.get(&register.full_register())?;
            let width = register.size();
            let valid = match value {
                Value::BusinessPtr | Value::ProtoPtr => width == 8,
                _ => match bytes {
                    1 => {
                        matches!(width, 1 | 4 | 8)
                            && !matches!(
                                register,
                                Register::AH | Register::BH | Register::CH | Register::DH
                            )
                    }
                    4 => matches!(width, 4 | 8),
                    8 => width == 8,
                    _ => false,
                },
            };
            valid.then(|| value.clone())
        }
        OpKind::Memory => {
            let (owner, offset) = direct_offset(instruction, index, state, bytes)?;
            match owner {
                Value::BusinessPtr => Some(Value::BusinessField(offset)),
                Value::ProtoPtr => Some(Value::ProtoField {
                    offset,
                    loads: BTreeSet::from([instruction.ip() as usize]),
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

fn business_writes(
    instruction: &Instruction,
    state: &State,
    factory: &mut InstructionInfoFactory,
    bytes: usize,
) -> Vec<BusinessWrite> {
    let known_stores = known_stores(instruction, state, bytes);
    factory
        .info(instruction)
        .used_memory()
        .iter()
        .filter(|memory| {
            writes(memory.access())
                && memory.base().size() == 8
                && !matches!(memory.segment(), Register::FS | Register::GS)
                && state.get(&memory.base()) == Some(&Value::BusinessPtr)
        })
        .flat_map(|memory| {
            let start = memory.displacement() as i64;
            let width = memory.memory_size().size();
            let end = if memory.index() != Register::None
                || width == 0
                || instruction.has_rep_prefix()
                || instruction.has_repne_prefix()
            {
                // A proved owner plus an unknown index can target any of
                // its fields. Rejecting indexed reads does not make this
                // write irrelevant to witnessed direct copies.
                None
            } else {
                i64::try_from(width)
                    .ok()
                    .and_then(|width| start.checked_add(width))
            };
            // Split only a recognized exact vector store. Unknown lanes still
            // write four bytes and must revoke any overlapping scalar proof.
            let split = vector_copy_width(instruction).filter(|vector_bytes| {
                bytes == 4
                    && *vector_bytes == width
                    && end == start.checked_add(*vector_bytes as i64)
                    && direct_offset_width(instruction, 0, state, *vector_bytes).is_some()
            });
            let count = split.map_or(1, |bytes| bytes / 4);
            (0..count)
                .map(|index| {
                    let lane_start = start + index as i64 * 4;
                    let lane_end = if split.is_some() {
                        Some(lane_start + 4)
                    } else {
                        end
                    };
                    let source = known_stores
                        .iter()
                        .find(|(offset, _)| {
                            i64::from(*offset) == lane_start
                                && lane_end == Some(lane_start + bytes as i64)
                        })
                        .and_then(|(_, value)| match value {
                            Lane::ProtoField { offset, .. } => {
                                Some(WriteSource::ProtoField(*offset))
                            }
                            Lane::SetterValue => Some(WriteSource::SetterValue),
                            _ => None,
                        });
                    BusinessWrite {
                        start: lane_start,
                        end: lane_end,
                        source,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn transfer(
    instruction: &Instruction,
    state: &State,
    factory: &mut InstructionInfoFactory,
    bytes: usize,
) -> State {
    // Evaluate the source while a destination register still holds its old
    // pointer, notably mov edi,[rdi+offset]. Arithmetic and conditional moves
    // intentionally produce no symbolic value.
    let assigned = if (instruction.mnemonic() == Mnemonic::Mov
        || (bytes == 1 && instruction.mnemonic() == Mnemonic::Movzx))
        && instruction.op_count() == 2
        && instruction.op0_kind() == OpKind::Register
        && match bytes {
            1 => {
                matches!(instruction.op0_register().size(), 1 | 4 | 8)
                    && !matches!(
                        instruction.op0_register(),
                        Register::AH | Register::BH | Register::CH | Register::DH
                    )
            }
            4 => matches!(instruction.op0_register().size(), 4 | 8),
            8 => instruction.op0_register().size() == 8,
            _ => false,
        } {
        operand(instruction, 1, state, bytes).filter(|value| {
            !matches!(value, Value::BusinessPtr | Value::ProtoPtr)
                || instruction.op0_register().size() == 8
        })
    } else if bytes == 4 {
        vector_assignment(instruction, state)
    } else {
        None
    };
    let mut next = state.clone();
    for register in factory.info(instruction).used_registers() {
        if writes(register.access()) {
            next.remove(&register.register().full_register());
        }
    }
    if let Some(value) = assigned {
        next.insert(instruction.op0_register().full_register(), value);
    }
    if matches!(
        instruction.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    ) {
        for register in [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
        ] {
            next.remove(&register);
        }
        // Conservatively discard all vector lanes across unknown calls. No
        // recovery depends on assuming a callee preserves SIMD registers.
        next.retain(|_, value| !matches!(value, Value::Vector(_)));
    }
    next
}

fn join(current: &mut State, incoming: &State) -> (bool, bool) {
    let old = current.clone();
    let mut field_conflict = false;
    current.retain(|register, value| {
        let Some(other) = incoming.get(register) else {
            return false;
        };
        match (&mut *value, other) {
            (Value::Vector(lanes), Value::Vector(other_lanes)) => {
                for (lane, other) in lanes.iter_mut().zip(other_lanes) {
                    join_lane(lane, other);
                }
                lanes.iter().any(Option::is_some)
            }
            (
                Value::ProtoField { offset, loads },
                Value::ProtoField {
                    offset: other_offset,
                    loads: other_loads,
                },
            ) if *offset == *other_offset => {
                loads.extend(other_loads);
                true
            }
            (Value::BusinessField(offset), Value::BusinessField(other_offset))
                if *offset != *other_offset =>
            {
                field_conflict = true;
                false
            }
            (value, other) => *value == *other,
        }
    });
    (*current != old, field_conflict)
}

fn successors(
    instruction: &Instruction,
    index: usize,
    instructions: &[Instruction],
    positions: &HashMap<u64, usize>,
    terminal_calls: &BTreeSet<usize>,
    exceptional_edges: &BTreeMap<usize, Vec<usize>>,
    switch_edges: &BTreeMap<usize, Vec<usize>>,
) -> (Vec<usize>, usize) {
    let mut next = Vec::with_capacity(2);
    let mut rejected = 0;
    let flow = instruction.flow_control();
    let call = matches!(flow, FlowControl::Call | FlowControl::IndirectCall);
    if matches!(
        flow,
        FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
    ) {
        let target = matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
        .then(|| positions.get(&instruction.near_branch_target()).copied())
        .flatten();
        if let Some(target) = target {
            next.push(target);
        } else {
            rejected += 1;
        }
    }
    if call && let Some(targets) = exceptional_edges.get(&(instruction.ip() as usize)) {
        next.extend(
            targets
                .iter()
                .filter_map(|rva| positions.get(&(*rva as u64)))
                .copied(),
        );
    }
    let switch = flow == FlowControl::IndirectBranch
        && switch_edges.contains_key(&(instruction.ip() as usize));
    if switch {
        next.extend(
            switch_edges[&(instruction.ip() as usize)]
                .iter()
                .filter_map(|target| positions.get(&(*target as u64)))
                .copied(),
        );
    }
    if !(call && terminal_calls.contains(&(instruction.ip() as usize)))
        && matches!(
            flow,
            FlowControl::Next
                | FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::ConditionalBranch
        )
    {
        if instructions
            .get(index + 1)
            .is_some_and(|next| next.ip() == instruction.next_ip())
        {
            next.push(index + 1);
        } else {
            rejected += 1;
        }
    } else if !switch
        && matches!(
            flow,
            FlowControl::IndirectBranch | FlowControl::Interrupt | FlowControl::Exception
        )
    {
        rejected += 1;
    }
    next.sort_unstable();
    next.dedup();
    (next, rejected)
}

fn remove_copy_conflicts(result: &mut ScanResult) {
    let mut sources = BTreeMap::<u32, BTreeSet<u32>>::new();
    let mut destinations = BTreeMap::<u32, BTreeSet<u32>>::new();
    for copy in &result.copies {
        sources
            .entry(copy.proto_offset)
            .or_default()
            .insert(copy.business_offset);
        destinations
            .entry(copy.business_offset)
            .or_default()
            .insert(copy.proto_offset);
    }
    let count = result.copies.len();
    result.copies.retain(|copy| {
        sources[&copy.proto_offset].len() == 1 && destinations[&copy.business_offset].len() == 1
    });
    result.ambiguous |= count != result.copies.len();
}

pub(super) fn scan(code: &[u8], rva: usize, mode: Mode) -> ScanResult {
    scan_controlled(code, rva, mode, &BTreeSet::new(), &BTreeMap::new())
}

pub(super) fn scan_typed(code: &[u8], rva: usize, mode: Mode, bytes: usize) -> ScanResult {
    scan_controlled_typed(code, rva, mode, &BTreeSet::new(), &BTreeMap::new(), bytes)
}

pub(super) fn scan_controlled(
    code: &[u8],
    rva: usize,
    mode: Mode,
    terminal_calls: &BTreeSet<usize>,
    exceptional_edges: &BTreeMap<usize, Vec<usize>>,
) -> ScanResult {
    scan_controlled_typed(code, rva, mode, terminal_calls, exceptional_edges, 4)
}

pub(super) fn scan_controlled_typed(
    code: &[u8],
    rva: usize,
    mode: Mode,
    terminal_calls: &BTreeSet<usize>,
    exceptional_edges: &BTreeMap<usize, Vec<usize>>,
    bytes: usize,
) -> ScanResult {
    scan_planned_typed(
        code,
        rva,
        mode,
        terminal_calls,
        exceptional_edges,
        &BTreeMap::new(),
        None,
        bytes,
    )
}

pub(super) fn scan_planned_typed(
    code: &[u8],
    rva: usize,
    mode: Mode,
    terminal_calls: &BTreeSet<usize>,
    exceptional_edges: &BTreeMap<usize, Vec<usize>>,
    switch_edges: &BTreeMap<usize, Vec<usize>>,
    code_bytes: Option<usize>,
    bytes: usize,
) -> ScanResult {
    let mut result = ScanResult::default();
    if !matches!(bytes, 1 | 4 | 8) || rva.checked_add(code.len()).is_none() {
        result.rejected_paths = 1;
        return result;
    }
    let code = if let Some(end) = code_bytes {
        let Some(prefix) = code.get(..end).filter(|prefix| {
            !prefix.is_empty() && prefix.len() < code.len() && !switch_edges.is_empty()
        }) else {
            result.rejected_paths = 1;
            result.ambiguous = true;
            return result;
        };
        prefix
    } else {
        code
    };
    let mut decoder = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        result.decoded += 1;
        if instruction.is_invalid() {
            if code_bytes.is_some() {
                result.rejected_paths = 1;
                result.ambiguous = true;
                return result;
            }
            break;
        }
        instructions.push(instruction);
    }
    if instructions.is_empty() {
        result.rejected_paths = 1;
        return result;
    }
    let positions: HashMap<_, _> = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.ip(), index))
        .collect();
    // A stale/partial EH plan is rejected as a whole. Silently dropping an
    // unresolved catch edge could otherwise hide a later owner overwrite.
    let valid_call = |site: &usize| {
        positions.get(&(*site as u64)).is_some_and(|&n| {
            matches!(
                instructions[n].flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            )
        })
    };
    if !terminal_calls.iter().all(valid_call)
        || !exceptional_edges.iter().all(|(site, targets)| {
            valid_call(site)
                && targets
                    .iter()
                    .all(|target| positions.contains_key(&(*target as u64)))
        })
        || !switch_edges.iter().all(|(site, targets)| {
            positions
                .get(&(*site as u64))
                .is_some_and(|&n| instructions[n].flow_control() == FlowControl::IndirectBranch)
                && !targets.is_empty()
                && targets
                    .iter()
                    .all(|target| positions.contains_key(&(*target as u64)))
        })
    {
        result.rejected_paths = 1;
        result.ambiguous = true;
        return result;
    }
    let edges: Vec<_> = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| {
            successors(
                instruction,
                index,
                &instructions,
                &positions,
                terminal_calls,
                exceptional_edges,
                switch_edges,
            )
        })
        .collect();
    // One joined state and one queued bit per actual instruction. Known values
    // only weaken; load provenance can grow only to this function's load sites.
    let mut states = vec![None; instructions.len()];
    let mut seed = State::from([(Register::RCX, Value::BusinessPtr)]);
    match mode {
        Mode::Sync => {
            seed.insert(Register::RDX, Value::ProtoPtr);
        }
        Mode::Setter => {
            seed.insert(Register::RDX, Value::SetterValue);
        }
        Mode::Getter => {}
    }
    states[0] = Some(seed);
    let mut pending = VecDeque::from([0]);
    let mut queued = vec![false; instructions.len()];
    queued[0] = true;
    let mut factory = InstructionInfoFactory::new();
    let mut getter_join_conflict = false;
    while let Some(index) = pending.pop_front() {
        queued[index] = false;
        let out = transfer(
            &instructions[index],
            states[index].as_ref().unwrap(),
            &mut factory,
            bytes,
        );
        for &target in &edges[index].0 {
            let changed = if let Some(state) = &mut states[target] {
                let (changed, conflict) = join(state, &out);
                getter_join_conflict |= conflict;
                changed
            } else {
                states[target] = Some(out.clone());
                true
            };
            if changed && !queued[target] {
                pending.push_back(target);
                queued[target] = true;
            }
        }
    }
    let mut accessor_sites = BTreeMap::<u32, BTreeSet<usize>>::new();
    // Collect every reachable, proved direct write to this owner, including
    // immediate, transformed, conditional, and SIMD writes. A writer remains
    // relevant regardless of instruction order or which native branch takes it.
    let mut destination_writes = Vec::new();
    for (index, instruction) in instructions.iter().enumerate() {
        let Some(state) = &states[index] else {
            continue;
        };
        result.rejected_paths += edges[index].1;
        destination_writes.extend(business_writes(instruction, state, &mut factory, bytes));
        if mode == Mode::Getter && instruction.flow_control() == FlowControl::Return {
            if let Some(Value::BusinessField(offset)) = state.get(&Register::RAX) {
                accessor_sites
                    .entry(*offset)
                    .or_default()
                    .insert(instruction.ip() as usize);
            }
        }
        for (destination, value) in known_stores(instruction, state, bytes) {
            match (mode, value) {
                (Mode::Sync, Lane::ProtoField { offset, loads }) => {
                    if let Some(&load_rva) = loads.first() {
                        result.copies.push(CopyEvidence {
                            proto_offset: offset,
                            business_offset: destination,
                            load_rva,
                            store_rva: instruction.ip() as usize,
                        });
                    }
                }
                (Mode::Setter, Lane::SetterValue) => {
                    accessor_sites
                        .entry(destination)
                        .or_default()
                        .insert(instruction.ip() as usize);
                }
                _ => {}
            }
        }
    }
    let count = result.copies.len();
    result.copies.retain(|copy| {
        !destination_writes.iter().any(|write| {
            write.rejects(
                copy.business_offset,
                WriteSource::ProtoField(copy.proto_offset),
                bytes,
            )
        })
    });
    result.ambiguous |= count != result.copies.len();
    remove_copy_conflicts(&mut result);
    if accessor_sites.len() == 1 && !(mode == Mode::Getter && getter_join_conflict) {
        let (offset, sites) = accessor_sites.into_iter().next().unwrap();
        if mode == Mode::Setter
            && destination_writes
                .iter()
                .any(|write| write.rejects(offset, WriteSource::SetterValue, bytes))
        {
            result.ambiguous = true;
        } else {
            result.accessor_offset = Some(offset);
            result.accessor_sites = sites.into_iter().collect();
        }
    } else {
        result.ambiguous |=
            accessor_sites.len() > 1 || (mode == Mode::Getter && getter_join_conflict);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    const RVA: usize = 0x1000;
    fn offsets(result: &ScanResult) -> Vec<(u32, u32)> {
        result
            .copies
            .iter()
            .map(|copy| (copy.proto_offset, copy.business_offset))
            .collect()
    }
    fn sync_prefix() -> Vec<u8> {
        vec![0x48, 0x89, 0xd7, 0x48, 0x89, 0xce]
    }

    #[test]
    fn bool_copy_and_accessors_keep_only_the_low_byte() {
        let code = [0x0f, 0xb6, 0x42, 0x18, 0x88, 0x41, 0x34, 0xc3];
        assert_eq!(offsets(&scan_typed(&code, RVA, Mode::Sync, 1)), [(24, 52)]);
        assert!(scan(&code, RVA, Mode::Sync).copies.is_empty());
        assert_eq!(
            scan_typed(&[0x0f, 0xb6, 0x41, 0x34, 0xc3], RVA, Mode::Getter, 1).accessor_offset,
            Some(52)
        );
        assert_eq!(
            scan_typed(&[0x88, 0x51, 0x34, 0xc3], RVA, Mode::Setter, 1).accessor_offset,
            Some(52)
        );
        // AH is not the low byte represented by the full RAX key.
        for code in [
            &[0x8a, 0x62, 0x18, 0x88, 0x61, 0x34, 0xc3][..],
            &[0x0f, 0xb6, 0x42, 0x18, 0x88, 0x61, 0x34, 0xc3][..],
        ] {
            assert!(scan_typed(code, RVA, Mode::Sync, 1).copies.is_empty());
        }
    }

    #[test]
    fn qword_copy_rejects_truncation_and_partial_destination_overwrite() {
        let copy = [0x48, 0x8b, 0x42, 0x28, 0x48, 0x89, 0x41, 0x20];
        let mut code = copy.to_vec();
        code.push(0xc3);
        assert_eq!(offsets(&scan_typed(&code, RVA, Mode::Sync, 8)), [(40, 32)]);
        assert_eq!(
            scan_typed(&[0x48, 0x8b, 0x41, 0x20, 0xc3], RVA, Mode::Getter, 8).accessor_offset,
            Some(32)
        );
        assert_eq!(
            scan_typed(&[0x48, 0x89, 0x51, 0x20, 0xc3], RVA, Mode::Setter, 8).accessor_offset,
            Some(32)
        );
        let mut overlap = copy.to_vec();
        overlap.extend_from_slice(&[0xc7, 0x41, 0x24, 0, 0, 0, 0, 0xc3]);
        assert!(scan_typed(&overlap, RVA, Mode::Sync, 8).copies.is_empty());
        let truncated = [
            0x48, 0x8b, 0x42, 0x28, 0x89, 0xc0, 0x48, 0x89, 0x41, 0x20, 0xc3,
        ];
        assert!(scan_typed(&truncated, RVA, Mode::Sync, 8).copies.is_empty());
    }

    #[test]
    fn observed_aliasing_load_changes_proto_pointer_into_a_value() {
        let mut code = sync_prefix();
        code.extend_from_slice(&[
            0x8b, 0x7f, 0x24, 0x89, 0x7e, 0x4c, 0x8b, 0x47, 0x28, 0x89, 0x46, 0x50, 0xc3,
        ]);
        let result = scan(&code, RVA, Mode::Sync);
        assert_eq!(offsets(&result), [(36, 76)]);
        assert_eq!(result.copies[0].load_rva, RVA + 6);
        assert_eq!(result.copies[0].store_rva, RVA + 9);
    }

    #[test]
    fn calls_kill_volatile_sources_and_keep_nonvolatile_owner_and_value() {
        for (load, store, expected) in [
            (&[0x8b, 0x47, 0x24][..], &[0x89, 0x46, 0x4c][..], vec![]),
            (
                &[0x8b, 0x5f, 0x24][..],
                &[0x89, 0x5e, 0x4c][..],
                vec![(36, 76)],
            ),
        ] {
            let mut code = sync_prefix();
            code.extend_from_slice(load);
            code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
            code.extend_from_slice(store);
            code.push(0xc3);
            assert_eq!(offsets(&scan(&code, RVA, Mode::Sync)), expected);
        }
        assert!(
            scan(
                &[0xe8, 0, 0, 0, 0, 0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c, 0xc3],
                RVA,
                Mode::Sync
            )
            .copies
            .is_empty()
        );
    }

    #[test]
    fn joins_accept_the_same_field_loaded_on_two_paths_and_reject_conflicting_fields() {
        for second_offset in [0x24, 0x28] {
            let mut code = sync_prefix();
            // test eax,eax; je second-load; load ebx; jmp join; second-load; store
            code.extend_from_slice(&[
                0x85,
                0xc0,
                0x74,
                0x05,
                0x8b,
                0x5f,
                0x24,
                0xeb,
                0x03,
                0x8b,
                0x5f,
                second_offset,
                0x89,
                0x5e,
                0x4c,
                0xc3,
            ]);
            let expected = if second_offset == 0x24 {
                vec![(36, 76)]
            } else {
                vec![]
            };
            assert_eq!(offsets(&scan(&code, RVA, Mode::Sync)), expected);
        }
    }

    #[test]
    fn evidence_is_collected_after_a_calling_branch_has_weakened_the_join() {
        for (load, store, expected) in [
            (&[0x8b, 0x47, 0x24][..], &[0x89, 0x46, 0x4c][..], vec![]),
            (
                &[0x8b, 0x5f, 0x24][..],
                &[0x89, 0x5e, 0x4c][..],
                vec![(36, 76)],
            ),
        ] {
            let mut code = sync_prefix();
            code.extend_from_slice(load);
            // One branch reaches the store first; the other calls unknown code.
            code.extend_from_slice(&[0x85, 0xc9, 0x74, 0x05, 0xe8, 0, 0, 0, 0]);
            code.extend_from_slice(store);
            code.push(0xc3);
            assert_eq!(offsets(&scan(&code, RVA, Mode::Sync)), expected);
        }
    }

    #[test]
    fn getter_returns_and_setter_sources_require_provenance_and_unique_offsets() {
        assert_eq!(
            scan(
                &[0x48, 0x89, 0xce, 0x8b, 0x46, 0x4c, 0xc3],
                RVA,
                Mode::Getter
            )
            .accessor_offset,
            Some(76)
        );
        assert_eq!(
            scan(
                &[0x89, 0xd6, 0x48, 0x89, 0xcf, 0x89, 0x77, 0x4c, 0xc3],
                RVA,
                Mode::Setter
            )
            .accessor_offset,
            Some(76)
        );
        assert_eq!(
            scan(
                &[0x8b, 0x41, 0x20, 0x89, 0x41, 0x4c, 0xc3],
                RVA,
                Mode::Setter
            )
            .accessor_offset,
            None
        );
        let getter = scan(
            &[
                0x85, 0xd2, 0x74, 0x04, 0x8b, 0x41, 0x20, 0xc3, 0x8b, 0x41, 0x24, 0xc3,
            ],
            RVA,
            Mode::Getter,
        );
        assert!(getter.ambiguous);
        assert_eq!(getter.accessor_offset, None);
        let setter = scan(
            &[0x89, 0x51, 0x20, 0x89, 0x51, 0x24, 0xc3],
            RVA,
            Mode::Setter,
        );
        assert!(setter.ambiguous);
        assert_eq!(setter.accessor_offset, None);
        let joined_getter = scan(
            &[
                0x85, 0xd2, 0x74, 0x05, 0x8b, 0x41, 0x20, 0xeb, 0x03, 0x8b, 0x41, 0x24, 0xc3,
            ],
            RVA,
            Mode::Getter,
        );
        assert!(joined_getter.ambiguous);
        assert_eq!(joined_getter.accessor_offset, None);
    }

    #[test]
    fn partial_register_writes_destroy_the_original_scalar_proof() {
        assert_eq!(
            scan(&[0x8b, 0x41, 0x20, 0x30, 0xc0, 0xc3], RVA, Mode::Getter).accessor_offset,
            None
        );
        assert_eq!(
            scan(
                &[0x80, 0xc2, 0x01, 0x89, 0x51, 0x20, 0xc3],
                RVA,
                Mode::Setter
            )
            .accessor_offset,
            None
        );
    }

    #[test]
    fn indexed_reads_and_arithmetic_are_not_copies() {
        for code in [
            &[0x8b, 0x44, 0x8a, 0x24, 0x89, 0x41, 0x4c, 0xc3][..],
            &[0x8b, 0x42, 0x24, 0x83, 0xc0, 0x01, 0x89, 0x41, 0x4c, 0xc3],
        ] {
            assert!(scan(code, RVA, Mode::Sync).copies.is_empty());
        }
    }

    #[test]
    fn observed_movq_shuffle_swaps_two_independent_integer_lanes() {
        let result = scan(
            &[
                0xf3, 0x0f, 0x7e, 0x42, 0x2c, // movq xmm0,[rdx+44]
                0x66, 0x0f, 0x70, 0xc0, 0xe1, // pshufd xmm0,xmm0,E1
                0x66, 0x0f, 0xd6, 0x41, 0x34, // movq [rcx+52],xmm0
                0xc3,
            ],
            RVA,
            Mode::Sync,
        );
        assert_eq!(offsets(&result), [(48, 52), (44, 56)]);
        assert!(
            result
                .copies
                .iter()
                .all(|copy| copy.load_rva == RVA && copy.store_rva == RVA + 10)
        );
    }

    #[test]
    fn four_lane_shuffle_and_register_copy_preserve_exact_lane_order() {
        let result = scan(
            &[
                0xf3, 0x0f, 0x6f, 0x42, 0x20, // movdqu xmm0,[rdx+32]
                0x66, 0x0f, 0x70, 0xc8, 0x93, // pshufd xmm1,xmm0,93 -> 3,0,1,2
                0x0f, 0x28, 0xd1, // movaps xmm2,xmm1
                0xf3, 0x0f, 0x7f, 0x51, 0x30, // movdqu [rcx+48],xmm2
                0xc3,
            ],
            RVA,
            Mode::Sync,
        );
        assert_eq!(offsets(&result), [(44, 48), (32, 52), (36, 56), (40, 60)]);
    }

    #[test]
    fn vector_joins_keep_only_lanes_with_the_same_source_on_every_path() {
        let result = scan(
            &[
                0xf3, 0x0f, 0x7e, 0x42, 0x20, // two known lanes
                0x85, 0xc0, 0x74, 0x05, // one path swaps the low lanes
                0x66, 0x0f, 0x70, 0xc0, 0xe1, 0xf3, 0x0f, 0x7f, 0x41,
                0x30, // conflicting low lanes; high lanes unknown
                0xc3,
            ],
            RVA,
            Mode::Sync,
        );
        assert!(result.copies.is_empty());
        let result = scan(
            &[
                0xf3, 0x0f, 0x6f, 0x42, 0x20, // four known lanes
                0x85, 0xc0, 0x74, 0x05, 0x66, 0x0f, 0x70, 0xc0, 0xe1, // only low two differ
                0xf3, 0x0f, 0x7f, 0x41, 0x30, 0xc3,
            ],
            RVA,
            Mode::Sync,
        );
        assert_eq!(offsets(&result), [(40, 56), (44, 60)]);
    }

    #[test]
    fn unknown_lanes_are_writers_and_known_vector_writes_can_agree_with_scalar_copies() {
        let result = scan(
            &[
                0x8b, 0x42, 0x28, 0x89, 0x41, 0x38, // scalar 40 -> 56
                0xf3, 0x0f, 0x7e, 0x42, 0x20, // only low two known
                0xf3, 0x0f, 0x7f, 0x41, 0x30, // high unknown lanes overwrite 56/60
                0xc3,
            ],
            RVA,
            Mode::Sync,
        );
        assert!(result.ambiguous);
        assert_eq!(offsets(&result), [(32, 48), (36, 52)]);
        let result = scan(
            &[
                0x8b, 0x42, 0x20, 0x89, 0x41, 0x30, // scalar agrees with vector lane0
                0xf3, 0x0f, 0x6f, 0x42, 0x20, 0xf3, 0x0f, 0x7f, 0x41, 0x30, 0xc3,
            ],
            RVA,
            Mode::Sync,
        );
        assert!(!result.ambiguous);
        assert!(offsets(&result).contains(&(32, 48)));
        assert!(offsets(&result).contains(&(44, 60)));
    }

    #[test]
    fn vector_proofs_do_not_survive_calls_arithmetic_or_unsupported_widths() {
        for destroy in [
            &[0xe8, 0, 0, 0, 0][..],   // unknown call
            &[0x66, 0x0f, 0xfe, 0xc0], // paddd xmm0,xmm0
            &[0xc5, 0xfd, 0x6f, 0xc0], // vmovdqa ymm0,ymm0 (upper/lower alias)
        ] {
            let mut code = sync_prefix();
            code.extend_from_slice(&[0xf3, 0x0f, 0x6f, 0x47, 0x20]);
            code.extend_from_slice(destroy);
            code.extend_from_slice(&[0xf3, 0x0f, 0x7f, 0x46, 0x30, 0xc3]);
            assert!(scan(&code, RVA, Mode::Sync).copies.is_empty());
        }
        for code in [
            &[
                0xf3, 0x0f, 0x6f, 0x44, 0x82, 0x20, 0xf3, 0x0f, 0x7f, 0x41, 0x30, 0xc3,
            ][..], // indexed load
            &[
                0xf3, 0x0f, 0x6f, 0x82, 0xf8, 0xff, 0xff, 0xff, 0xf3, 0x0f, 0x7f, 0x41, 0x30, 0xc3,
            ], // negative source offset
            &[0x0f, 0x6f, 0x42, 0x20, 0x0f, 0x7f, 0x41, 0x30, 0xc3], // MMX, not XMM
        ] {
            assert!(scan(code, RVA, Mode::Sync).copies.is_empty());
        }
    }

    #[test]
    fn branches_must_land_on_instruction_boundaries_and_loops_reach_a_fixed_point() {
        let wrong_target = scan(
            &[0xeb, 0x01, 0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c, 0xc3],
            RVA,
            Mode::Sync,
        );
        assert!(wrong_target.copies.is_empty());
        assert_eq!(wrong_target.rejected_paths, 1);
        let looped = scan(&[0xeb, 0xfe], RVA, Mode::Sync);
        assert!(looped.copies.is_empty());
        assert_eq!(looped.decoded, 1);
        assert!(
            scan(
                &[0xeb, 0x7f, 0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c, 0xc3],
                RVA,
                Mode::Sync
            )
            .copies
            .is_empty()
        );
    }

    #[test]
    fn conflicting_copy_destinations_are_removed_without_dropping_independent_evidence() {
        let result = scan(
            &[
                0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c, 0x89, 0x41, 0x50, 0x8b, 0x42, 0x28, 0x89, 0x41,
                0x54, 0xc3,
            ],
            RVA,
            Mode::Sync,
        );
        assert!(result.ambiguous);
        assert_eq!(offsets(&result), [(40, 84)]);
    }

    #[test]
    fn immediate_overwrite_blocks_a_copy_even_when_the_known_store_occurs_last() {
        let known = [0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c];
        let overwrite = [0xc7, 0x41, 0x4c, 0, 0, 0, 0];
        for (first, second) in [(&known[..], &overwrite[..]), (&overwrite[..], &known[..])] {
            let mut code = first.to_vec();
            code.extend_from_slice(second);
            code.push(0xc3);
            let result = scan(&code, RVA, Mode::Sync);
            assert!(result.copies.is_empty());
            assert!(result.ambiguous);
        }
    }

    #[test]
    fn reachable_branch_overwrites_block_but_unreachable_writers_do_not() {
        let known = [0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c];
        let overwrite = [0xc7, 0x41, 0x4c, 0, 0, 0, 0, 0xc3];
        let mut conditional = known.to_vec();
        conditional.extend_from_slice(&[0x85, 0xd2, 0x74, 0x07]);
        conditional.extend_from_slice(&overwrite);
        let result = scan(&conditional, RVA, Mode::Sync);
        assert!(result.copies.is_empty());
        assert!(result.ambiguous);
        let mut unreachable = known.to_vec();
        unreachable.extend_from_slice(&[0xeb, 0x07]);
        unreachable.extend_from_slice(&overwrite);
        assert_eq!(offsets(&scan(&unreachable, RVA, Mode::Sync)), [(36, 76)]);
    }

    #[test]
    fn partial_overlaps_unknown_sources_and_transformed_writes_revoke_the_proof() {
        for overwrite in [
            &[0xc6, 0x41, 0x4f, 0][..],      // byte write to the scalar's last byte
            &[0x66, 0xc7, 0x41, 0x4b, 0, 0], // word straddles the scalar's first byte
            &[0x48, 0xc7, 0x41, 0x48, 0, 0, 0, 0], // qword overlaps from below
            &[0xf3, 0x0f, 0x7f, 0x41, 0x48], // unknown 16-byte SIMD store
            &[0x83, 0x41, 0x4c, 0x01],       // read/write arithmetic on the destination
            &[0x89, 0x59, 0x4c],             // unknown EBX source
            &[0x83, 0xc0, 0x01, 0x89, 0x41, 0x4c], // transformed proto value
        ] {
            let mut code = vec![0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c];
            code.extend_from_slice(overwrite);
            code.push(0xc3);
            let result = scan(&code, RVA, Mode::Sync);
            assert!(result.copies.is_empty(), "overwrite={overwrite:x?}");
            assert!(result.ambiguous);
        }
        let overlapping_known = scan(
            &[
                0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c, 0x8b, 0x42, 0x28, 0x89, 0x41, 0x4e, 0xc3,
            ],
            RVA,
            Mode::Sync,
        );
        assert!(overlapping_known.copies.is_empty());
        assert!(overlapping_known.ambiguous);
    }

    #[test]
    fn rejecting_an_overwritten_destination_keeps_independent_scalar_copies() {
        for overwrite in [
            &[0xc7, 0x41, 0x4c, 0, 0, 0, 0][..],
            &[0xf3, 0x0f, 0x7f, 0x41, 0x48],
        ] {
            let mut code = vec![
                0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c, 0x8b, 0x42, 0x28, 0x89, 0x41, 0x60,
            ];
            code.extend_from_slice(overwrite);
            code.push(0xc3);
            let result = scan(&code, RVA, Mode::Sync);
            assert!(result.ambiguous);
            assert_eq!(offsets(&result), [(40, 96)]);
        }
    }

    #[test]
    fn setters_reject_overlaps_without_blocking_writes_to_other_fields() {
        for overwrite in [
            &[0xc7, 0x41, 0x4c, 0, 0, 0, 0][..],
            &[0xc6, 0x41, 0x4f, 0],
            &[0xff, 0x41, 0x4c], // inc dword destination
        ] {
            let mut code = vec![0x89, 0x51, 0x4c];
            code.extend_from_slice(overwrite);
            code.push(0xc3);
            let result = scan(&code, RVA, Mode::Setter);
            assert_eq!(result.accessor_offset, None);
            assert!(result.accessor_sites.is_empty());
            assert!(result.ambiguous);
        }
        let independent = scan(
            &[0x89, 0x51, 0x4c, 0xc7, 0x41, 0x54, 0, 0, 0, 0, 0xc3],
            RVA,
            Mode::Setter,
        );
        assert_eq!(independent.accessor_offset, Some(76));
        assert!(!independent.ambiguous);
    }

    #[test]
    fn indexed_owner_writes_revoke_both_scalar_and_vector_copy_proofs() {
        for known in [
            &[0x8b, 0x42, 0x20, 0x89, 0x41, 0x30][..],
            &[0xf3, 0x0f, 0x7e, 0x42, 0x20, 0x66, 0x0f, 0xd6, 0x41, 0x30],
        ] {
            let mut code = known.to_vec();
            // movq [rcx+rax*4+48],xmm1. An unknown index may be zero.
            code.extend_from_slice(&[0x66, 0x0f, 0xd6, 0x4c, 0x81, 0x30, 0xc3]);
            let result = scan(&code, RVA, Mode::Sync);
            assert!(result.copies.is_empty());
            assert!(result.ambiguous);
        }
        let setter = scan(
            &[0x89, 0x51, 0x30, 0x89, 0x5c, 0x81, 0x30, 0xc3],
            RVA,
            Mode::Setter,
        );
        assert_eq!(setter.accessor_offset, None);
        assert!(setter.ambiguous);
    }

    #[test]
    fn planned_switch_cases_expose_overwrites_and_reject_stale_targets() {
        let mut code = vec![
            0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c, 0xff, 0xe0, 0xc7, 0x41, 0x4c, 0, 0, 0, 0, 0xc3,
            0xc3,
        ];
        code.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // proven table data
        let empty_calls = BTreeSet::new();
        let empty_edges = BTreeMap::new();
        let cases = BTreeMap::from([(RVA + 6, vec![RVA + 8, RVA + 16])]);
        let result = scan_planned_typed(
            &code,
            RVA,
            Mode::Sync,
            &empty_calls,
            &empty_edges,
            &cases,
            Some(17),
            4,
        );
        assert!(result.copies.is_empty());
        assert!(result.ambiguous);
        code[10] = 0x54; // independent case write permits the original copy
        assert_eq!(
            offsets(&scan_planned_typed(
                &code,
                RVA,
                Mode::Sync,
                &empty_calls,
                &empty_edges,
                &cases,
                Some(17),
                4
            )),
            [(36, 76)]
        );
        let stale = BTreeMap::from([(RVA + 6, vec![RVA + 9])]);
        let rejected = scan_planned_typed(
            &code,
            RVA,
            Mode::Sync,
            &empty_calls,
            &empty_edges,
            &stale,
            Some(17),
            4,
        );
        assert!(rejected.copies.is_empty() && rejected.ambiguous);
    }
}
