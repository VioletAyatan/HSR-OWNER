//! Strict decoding for functions with a compiler-style signed-relative switch
//! table at the end of the body. Unknown indirect control flow is left to the
//! caller's existing rejection rules.
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use std::{collections::BTreeMap, ops::Range};

pub(super) struct Decoded {
    pub instructions: Vec<Instruction>,
    pub code_bytes: usize,
    pub switch_edges: BTreeMap<usize, Vec<usize>>,
    pub protected_ranges: Vec<Range<usize>>,
}

#[derive(Clone)]
struct Switch {
    table_start: usize,
    table_end: usize,
    protected: Range<usize>,
    jump_ip: usize,
    default_target: usize,
    targets: Vec<usize>,
}

fn decode_prefix(code: &[u8], rva: usize) -> (Vec<Instruction>, Option<usize>) {
    let mut decoder = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return (instructions, usize::try_from(instruction.ip()).ok());
        }
        instructions.push(instruction);
    }
    (instructions, None)
}

fn address(value: u64, context: &str) -> Result<usize> {
    usize::try_from(value).with_context(|| format!("{context} exceeds address width"))
}

fn add_signed(base: usize, displacement: i64, context: &str) -> Result<usize> {
    if displacement >= 0 {
        base.checked_add(usize::try_from(displacement)?)
    } else {
        base.checked_sub(usize::try_from(displacement.unsigned_abs())?)
    }
    .with_context(|| format!("{context} address overflow"))
}

fn gpr(reg: Register, size: usize) -> bool {
    if reg.size() != size {
        return false;
    }
    matches!(
        reg.full_register(),
        Register::RAX
            | Register::RBX
            | Register::RCX
            | Register::RDX
            | Register::RSP
            | Register::RBP
            | Register::RSI
            | Register::RDI
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    )
}

fn ordinary(instruction: &Instruction) -> bool {
    !instruction.has_lock_prefix()
        && !instruction.has_rep_prefix()
        && !instruction.has_repe_prefix()
        && !instruction.has_repne_prefix()
        && !instruction.has_segment_prefix()
}

fn index_seed(instruction: &Instruction, index: Register) -> bool {
    if instruction.op_count() != 2
        || instruction.op0_kind() != OpKind::Register
        || instruction.op0_register() != index
        || !ordinary(instruction)
    {
        return false;
    }
    if instruction.mnemonic() == Mnemonic::Lea {
        return instruction.op1_kind() == OpKind::Memory
            && instruction.memory_base() != Register::RIP
            && gpr(instruction.memory_base(), 8)
            && instruction.memory_index() == Register::None;
    }
    if instruction.mnemonic() != Mnemonic::Mov {
        return false;
    }
    match instruction.op1_kind() {
        OpKind::Register => gpr(instruction.op1_register(), 4),
        OpKind::Memory => instruction.memory_size().size() == 4,
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate32 => true,
        _ => false,
    }
}

fn index_update(instruction: &Instruction, index: Register) -> bool {
    if !ordinary(instruction)
        || instruction.op_count() == 0
        || instruction.op0_kind() != OpKind::Register
        || instruction.op0_register() != index
    {
        return false;
    }
    match instruction.mnemonic() {
        Mnemonic::Inc | Mnemonic::Dec => instruction.op_count() == 1,
        Mnemonic::Add | Mnemonic::Sub => {
            instruction.op_count() == 2
                && matches!(
                    instruction.op1_kind(),
                    OpKind::Register
                        | OpKind::Memory
                        | OpKind::Immediate8
                        | OpKind::Immediate8to16
                        | OpKind::Immediate8to32
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                )
        }
        _ => false,
    }
}

fn immediate_nonnegative(instruction: &Instruction) -> Option<usize> {
    match instruction.op1_kind() {
        OpKind::Immediate8 => Some(usize::from(instruction.immediate8())),
        OpKind::Immediate8to16 => usize::try_from(instruction.immediate8to16()).ok(),
        OpKind::Immediate8to32 => usize::try_from(instruction.immediate8to32()).ok(),
        OpKind::Immediate16 => Some(usize::from(instruction.immediate16())),
        OpKind::Immediate32 => Some(instruction.immediate32() as usize),
        _ => None,
    }
}

fn indexed_dispatch(
    instructions: &[Instruction],
    jump: usize,
) -> Option<(Register, Register, Register, usize)> {
    let sequence = instructions.get(jump.checked_sub(3)?..=jump)?;
    let lea = &sequence[0];
    let load = &sequence[1];
    let add = &sequence[2];
    let branch = &sequence[3];
    if branch.mnemonic() != Mnemonic::Jmp
        || branch.flow_control() != FlowControl::IndirectBranch
        || branch.op_count() != 1
        || branch.op0_kind() != OpKind::Register
        || !ordinary(branch)
        || lea.mnemonic() != Mnemonic::Lea
        || lea.op_count() != 2
        || lea.op0_kind() != OpKind::Register
        || lea.op1_kind() != OpKind::Memory
        || lea.memory_base() != Register::RIP
        || lea.memory_index() != Register::None
        || lea.has_segment_prefix()
        || load.mnemonic() != Mnemonic::Movsxd
        || load.op_count() != 2
        || load.op0_kind() != OpKind::Register
        || load.op1_kind() != OpKind::Memory
        || load.memory_size().size() != 4
        || load.memory_displacement64() != 0
        || load.has_segment_prefix()
        || add.mnemonic() != Mnemonic::Add
        || add.op_count() != 2
        || add.op0_kind() != OpKind::Register
        || add.op1_kind() != OpKind::Register
        || !ordinary(lea)
        || !ordinary(load)
        || !ordinary(add)
    {
        return None;
    }

    let base = lea.op0_register();
    let destination = load.op0_register();
    let index64 = load.memory_index();
    let jump_reg = branch.op0_register();
    if !gpr(base, 8)
        || !gpr(destination, 8)
        || !gpr(index64, 8)
        || destination == base
        || base == index64
        || load.memory_base() != base
        || index64 != index64.full_register()
        || load.memory_index_scale() != 4
        || !gpr(lea.op0_register(), 8)
        || add.op0_register() != destination
        || add.op1_register() != base
        || jump_reg != destination
    {
        return None;
    }
    let table_start = address(lea.ip_rel_memory_address(), "switch table").ok()?;
    Some((base, index64, destination, table_start))
}

fn analyze_switch(
    code: &[u8],
    rva: usize,
    body_end: usize,
    instructions: &[Instruction],
    jump_index: usize,
) -> Result<Option<Switch>> {
    let Some((base, index64, destination, table_start)) =
        indexed_dispatch(instructions, jump_index)
    else {
        return Ok(None);
    };
    let lea_index = jump_index.checked_sub(3).context("switch LEA underflow")?;
    let copy_guard_index = lea_index.checked_sub(1).filter(|index| {
        let instruction = &instructions[*index];
        instruction.mnemonic() == Mnemonic::Mov
            && instruction.op_count() == 2
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && gpr(instruction.op0_register(), 4)
            && gpr(instruction.op1_register(), 4)
            && instruction.op0_register().full_register() == index64
            && ordinary(instruction)
    });
    let branch_index = if copy_guard_index.is_some() {
        copy_guard_index
            .and_then(|index| index.checked_sub(1))
            .context("switch dispatch has no guard branch")?
    } else {
        lea_index
            .checked_sub(1)
            .context("switch dispatch has no guard branch")?
    };
    let Some(cmp_index) = branch_index.checked_sub(1) else {
        anyhow::bail!("switch dispatch has no compare");
    };
    let branch = &instructions[branch_index];
    let cmp = &instructions[cmp_index];
    ensure!(
        matches!(branch.mnemonic(), Mnemonic::Ja | Mnemonic::Jae)
            && branch.flow_control() == FlowControl::ConditionalBranch
            && branch.op_count() == 1
            && ordinary(branch),
        "switch dispatch lacks JA/JAE bounds guard"
    );
    ensure!(
        cmp.mnemonic() == Mnemonic::Cmp
            && cmp.op_count() == 2
            && cmp.op0_kind() == OpKind::Register
            && gpr(cmp.op0_register(), 4)
            && ordinary(cmp),
        "switch bounds compare has no 32-bit index"
    );
    let compare_index = cmp.op0_register();
    if let Some(copy_index) = copy_guard_index {
        let copy = &instructions[copy_index];
        ensure!(
            copy.op1_register() == compare_index,
            "switch guard copy source differs from compared register"
        );
        for instruction in &instructions[cmp_index + 2..copy_index] {
            ensure!(
                !writes_register(instruction, compare_index),
                "switch compare source changes before its guarded copy"
            );
        }
    } else {
        ensure!(
            compare_index.full_register() == index64,
            "switch bounds compare does not use the prepared index"
        );
        let _ = find_prep(instructions, cmp_index, compare_index)?;
    }
    let immediate =
        immediate_nonnegative(cmp).context("switch bound is not nonnegative immediate")?;
    let count = match branch.mnemonic() {
        Mnemonic::Ja => immediate.checked_add(1).context("switch count overflow")?,
        Mnemonic::Jae => immediate,
        _ => unreachable!(),
    };
    ensure!(count > 0, "empty switch table");
    let table_bytes = count.checked_mul(4).context("switch table size overflow")?;
    let table_end = table_start
        .checked_add(table_bytes)
        .context("switch table end overflow")?;
    ensure!(
        table_start >= rva
            && table_start >= address(instructions[jump_index].next_ip(), "switch JMP next IP")?
            && table_end <= body_end,
        "switch table is outside function bytes"
    );
    let table_offset = table_start
        .checked_sub(rva)
        .context("switch table precedes function")?;
    ensure!(
        table_offset <= code.len() && table_bytes <= code.len() - table_offset,
        "truncated switch table"
    );

    let default_target = near_target(branch).context("switch guard has no direct target")?;
    let mut targets = Vec::with_capacity(count);
    for index in 0..count {
        let item_rva = table_start
            .checked_add(index.checked_mul(4).context("switch item overflow")?)
            .context("switch item address overflow")?;
        let item_offset = item_rva
            .checked_sub(rva)
            .context("switch item before body")?;
        let displacement = i32::from_le_bytes(
            code[item_offset..item_offset + 4]
                .try_into()
                .context("truncated signed switch offset")?,
        );
        let target = add_signed(table_start, i64::from(displacement), "switch target")?;
        ensure!(
            target >= rva && target < table_start,
            "switch target is outside code prefix"
        );
        targets.push(target);
    }
    targets.sort_unstable();
    targets.dedup();

    // Keep the table base check tied to the exact LEA consumed by the load.
    ensure!(
        instructions[jump_index - 1].op0_register() == destination
            && instructions[jump_index - 1].op1_register() == base,
        "switch address calculation changed"
    );
    Ok(Some(Switch {
        table_start,
        table_end,
        protected: address(instructions[cmp_index].ip(), "switch CMP IP")?
            ..address(instructions[jump_index].next_ip(), "switch JMP end")?,
        jump_ip: address(instructions[jump_index].ip(), "switch JMP IP")?,
        default_target,
        targets,
    }))
}

fn writes_register(instruction: &Instruction, register: Register) -> bool {
    if instruction.op_count() == 0 || instruction.op0_kind() != OpKind::Register {
        return false;
    }
    instruction.op0_register().full_register() == register.full_register()
}

fn find_prep(instructions: &[Instruction], cmp_index: usize, index: Register) -> Result<usize> {
    let mut cursor = cmp_index;
    while cursor > 0 && index_update(&instructions[cursor - 1], index) {
        cursor -= 1;
    }
    if cursor < cmp_index {
        if cursor > 0 && index_seed(&instructions[cursor - 1], index) {
            cursor -= 1;
        }
        return Ok(address(
            instructions[cursor].ip(),
            "switch index preparation IP",
        )?);
    }
    ensure!(cursor > 0, "switch index has no 32-bit preparation");
    let seed = cursor - 1;
    ensure!(
        index_seed(&instructions[seed], index),
        "switch index has no 32-bit preparation"
    );
    Ok(address(
        instructions[seed].ip(),
        "switch index preparation IP",
    )?)
}

fn near_target(instruction: &Instruction) -> Option<usize> {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| usize::try_from(instruction.near_branch_target()).ok())
    .flatten()
}

pub(super) fn decode(code: &[u8], rva: usize) -> Result<Decoded> {
    let body_end = rva
        .checked_add(code.len())
        .context("native body overflow")?;
    ensure!(!code.is_empty(), "empty native function");
    let (linear, invalid_ip) = decode_prefix(code, rva);
    let mut switches = Vec::new();
    let mut candidate_errors = Vec::new();
    for jump_index in 0..linear.len() {
        if linear[jump_index].flow_control() != FlowControl::IndirectBranch {
            continue;
        }
        match analyze_switch(code, rva, body_end, &linear, jump_index) {
            Ok(Some(switch)) => switches.push(switch),
            Ok(None) => {}
            Err(error) => candidate_errors.push(error),
        }
    }

    if switches.is_empty() {
        if let Some(error) = candidate_errors.into_iter().next() {
            return Err(error).context("invalid guarded switch candidate");
        }
        if let Some(invalid) = invalid_ip {
            anyhow::bail!("invalid native instruction at 0x{invalid:X}");
        }
        return Ok(Decoded {
            instructions: linear,
            code_bytes: code.len(),
            switch_edges: BTreeMap::new(),
            protected_ranges: Vec::new(),
        });
    }

    // A compiler can emit several guarded tables in one contiguous function
    // tail. Enumerate complete, nonoverlapping tail chains first so tables do
    // not get decoded as a second function prefix.
    let mut ranges: Vec<_> = switches
        .iter()
        .map(|switch| (switch.table_start, switch.table_end))
        .collect();
    ranges.sort_unstable();
    ranges.dedup();
    let mut chains = Vec::new();
    for &(start, end) in ranges.iter().filter(|(_, end)| *end == body_end) {
        let mut chain = vec![(start, end)];
        let mut cursor = start;
        while let Some(&(prior_start, prior_end)) =
            ranges.iter().find(|(_, prior_end)| *prior_end == cursor)
        {
            if prior_end <= prior_start {
                break;
            }
            chain.push((prior_start, prior_end));
            cursor = prior_start;
        }
        chain.sort_unstable();
        if chain.windows(2).all(|window| window[0].1 == window[1].0) {
            chains.push(chain);
        }
    }
    chains.sort();
    chains.dedup();

    let mut valid = Vec::new();
    for chain in chains {
        let prefix_end = chain[0].0;
        let selected: Vec<_> = switches
            .iter()
            .filter(|switch| {
                chain.contains(&(switch.table_start, switch.table_end))
                    && switch.jump_ip < prefix_end
            })
            .cloned()
            .collect();
        if selected.is_empty()
            || chain.iter().any(|range| {
                !selected
                    .iter()
                    .any(|switch| (switch.table_start, switch.table_end) == *range)
            })
        {
            continue;
        }
        let code_bytes = match prefix_end.checked_sub(rva) {
            Some(value) if value <= code.len() => value,
            _ => continue,
        };
        let mut prefix = Vec::new();
        let mut decoder =
            Decoder::with_ip(64, &code[..code_bytes], rva as u64, DecoderOptions::NONE);
        let mut decode_failed = false;
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                decode_failed = true;
                break;
            }
            prefix.push(instruction);
        }
        if decode_failed || address(decoder.ip(), "switch prefix end").ok() != Some(prefix_end) {
            continue;
        }
        if invalid_ip.is_some_and(|invalid| invalid < prefix_end) {
            continue;
        }
        let starts: std::collections::BTreeSet<_> = prefix
            .iter()
            .map(|instruction| instruction.ip() as usize)
            .collect();
        if selected.iter().any(|switch| {
            !starts.contains(&switch.jump_ip)
                || !starts.contains(&switch.default_target)
                || switch.targets.iter().any(|target| !starts.contains(target))
        }) {
            continue;
        }
        let mut selected = selected;
        selected.sort_by_key(|switch| (switch.protected.start, switch.protected.end));
        if selected
            .windows(2)
            .any(|pair| pair[0].protected.end > pair[1].protected.start)
        {
            continue;
        }
        let targets = selected.iter().flat_map(|switch| {
            switch
                .targets
                .iter()
                .copied()
                .chain([switch.default_target])
        });
        if targets.into_iter().any(|target| {
            selected
                .iter()
                .any(|switch| target >= switch.protected.start && target < switch.protected.end)
        }) {
            continue;
        }
        let recognized_jumps: std::collections::BTreeSet<_> =
            selected.iter().map(|switch| switch.jump_ip).collect();
        let mut rejected = false;
        for instruction in &prefix {
            if matches!(
                instruction.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) {
                if let Some(target) = near_target(instruction) {
                    if selected.iter().any(|switch| {
                        target >= switch.protected.start && target < switch.protected.end
                    }) || chain
                        .iter()
                        .any(|(start, end)| target >= *start && target < *end)
                    {
                        rejected = true;
                        break;
                    }
                }
            }
            if instruction.flow_control() == FlowControl::IndirectBranch
                && !recognized_jumps.contains(&(instruction.ip() as usize))
            {
                rejected = true;
                break;
            }
        }
        if rejected {
            continue;
        }
        valid.push((prefix, code_bytes, selected));
    }
    ensure!(
        valid.len() == 1,
        if valid.is_empty() {
            "no complete guarded switch-table chain covers the function tail"
        } else {
            "ambiguous guarded switch-table tail chains"
        }
    );
    let (prefix, code_bytes, switches) = valid.pop().unwrap();
    let mut switch_edges = BTreeMap::new();
    let mut protected_ranges = Vec::new();
    for switch in switches {
        switch_edges.insert(switch.jump_ip, switch.targets);
        protected_ranges.push(switch.protected);
    }
    protected_ranges.sort_by_key(|range| (range.start, range.end));
    protected_ranges.dedup();
    Ok(Decoded {
        instructions: prefix,
        code_bytes,
        switch_edges,
        protected_ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sample {
        code: Vec<u8>,
        rva: usize,
        table_start: usize,
        case0: usize,
        case1: usize,
        cmp: usize,
        guard_entry: usize,
    }

    fn sample(jcc: Option<u8>, immediate: u8, seed: &[u8]) -> Sample {
        let rva = 0x1000;
        let mut code = Vec::new();
        if let Some(jcc) = jcc {
            code.extend_from_slice(seed);
            let cmp = rva + code.len();
            code.extend([0x83, 0xf8, immediate]);
            let guard_entry = rva + code.len();
            code.extend([0x0f, jcc, 0, 0, 0, 0]);
            let lea = rva + code.len();
            code.extend([0x48, 0x8d, 0x0d, 0, 0, 0, 0]);
            code.extend([0x48, 0x63, 0x04, 0x81]);
            code.extend([0x48, 0x01, 0xc8]);
            code.extend([0xff, 0xe0]);

            let case0 = rva + code.len();
            code.extend([0x48, 0x89, 0xc0, 0xc3]);
            let case1 = rva + code.len();
            code.extend([0x48, 0x89, 0xc0, 0xc3]);
            let default = rva + code.len();
            code.push(0xc3);
            let table_start = rva + code.len();
            let branch_end = guard_entry + 6;
            code[guard_entry + 2 - rva..guard_entry + 6 - rva]
                .copy_from_slice(&((default as i64 - branch_end as i64) as i32).to_le_bytes());
            code[lea + 3 - rva..lea + 7 - rva]
                .copy_from_slice(&((table_start as i64 - (lea + 7) as i64) as i32).to_le_bytes());
            code.extend(((case0 as i64 - table_start as i64) as i32).to_le_bytes());
            code.extend(((case1 as i64 - table_start as i64) as i32).to_le_bytes());
            Sample {
                code,
                rva,
                table_start,
                case0,
                case1,
                cmp,
                guard_entry,
            }
        } else {
            let lea = rva + code.len();
            code.extend([0x48, 0x8d, 0x0d, 0, 0, 0, 0]);
            code.extend([0x48, 0x63, 0x04, 0x81]);
            code.extend([0x48, 0x01, 0xc8]);
            code.extend([0xff, 0xe0]);
            let case0 = rva + code.len();
            code.extend([0x48, 0x89, 0xc0, 0xc3]);
            let case1 = rva + code.len();
            code.extend([0x48, 0x89, 0xc0, 0xc3]);
            code.push(0xc3);
            let table_start = rva + code.len();
            code[lea + 3 - rva..lea + 7 - rva]
                .copy_from_slice(&((table_start as i64 - (lea + 7) as i64) as i32).to_le_bytes());
            code.extend(((case0 as i64 - table_start as i64) as i32).to_le_bytes());
            code.extend(((case1 as i64 - table_start as i64) as i32).to_le_bytes());
            Sample {
                code,
                rva,
                table_start,
                case0,
                case1,
                cmp: rva,
                guard_entry: rva,
            }
        }
    }

    fn insert_before_table(sample: &mut Sample, bytes: &[u8]) {
        let old_table = sample.table_start;
        let offset = old_table - sample.rva;
        sample.code.splice(offset..offset, bytes.iter().copied());
        sample.table_start = old_table + bytes.len();
        let lea = sample
            .code
            .windows(3)
            .position(|window| window == [0x48, 0x8d, 0x0d])
            .expect("synthetic table LEA")
            + sample.rva;
        sample.code[lea + 3 - sample.rva..lea + 7 - sample.rva].copy_from_slice(
            &((sample.table_start as i64 - (lea as i64 + 7)) as i32).to_le_bytes(),
        );
        let table_offset = sample.table_start - sample.rva;
        for (index, target) in [sample.case0, sample.case1].into_iter().enumerate() {
            let start = table_offset + index * 4;
            sample.code[start..start + 4].copy_from_slice(
                &((target as i64 - sample.table_start as i64) as i32).to_le_bytes(),
            );
        }
    }

    #[test]
    fn ja_and_jae_decode_negative_signed_table_offsets() -> Result<()> {
        for (jcc, immediate) in [(0x87, 1), (0x83, 2)] {
            let sample = sample(Some(jcc), immediate, &[0x8b, 0x01]);
            let decoded = decode(&sample.code, sample.rva)?;
            assert_eq!(decoded.code_bytes, sample.table_start - sample.rva);
            assert_eq!(
                decoded.instructions.last().unwrap().flow_control(),
                FlowControl::Return
            );
            assert_eq!(decoded.switch_edges.len(), 1);
            let targets = decoded.switch_edges.values().next().unwrap();
            assert_eq!(targets, &[sample.case0, sample.case1]);
            assert_eq!(
                decoded.protected_ranges,
                [sample.cmp..sample.guard_entry + 22]
            );
        }
        Ok(())
    }

    #[test]
    fn a_32_bit_index_update_can_follow_an_unrelated_store() -> Result<()> {
        let seed = [0x8b, 0x01, 0x89, 0x46, 0x10, 0xff, 0xc8];
        let sample = sample(Some(0x87), 1, &seed);
        let decoded = decode(&sample.code, sample.rva)?;
        assert_eq!(
            decoded.protected_ranges,
            [sample.cmp..sample.guard_entry + 22]
        );
        Ok(())
    }

    #[test]
    fn no_switch_keeps_strict_full_linear_decode() -> Result<()> {
        let code = [0x48, 0x89, 0xc0, 0xc3];
        let decoded = decode(&code, 0x2000)?;
        assert_eq!(decoded.code_bytes, code.len());
        assert!(decoded.switch_edges.is_empty());
        assert!(decoded.protected_ranges.is_empty());
        assert_eq!(decoded.instructions.len(), 2);
        Ok(())
    }

    #[test]
    fn malformed_or_unbounded_switches_are_rejected() {
        let mut cases = Vec::new();

        // No CMP/JA guard in an otherwise matching indexed dispatch.
        cases.push(sample(None, 0, &[]).code);

        // A 64-bit source copy does not establish the required zero-extended index.
        cases.push(sample(Some(0x87), 1, &[0x48, 0x89, 0xc8]).code);

        // The bound implies three entries while only two tail entries exist.
        cases.push(sample(Some(0x87), 2, &[0x8b, 0x01]).code);

        // Overwriting the guarded index with the table base invalidates the
        // bound even though the LEA/load/add/jump shape still matches.
        let mut clobbered = sample(Some(0x87), 1, &[0x8b, 0x01]);
        let lea = clobbered.guard_entry + 6 - clobbered.rva;
        clobbered.code[lea + 2] = 0x05; // LEA rax,[rip+table]
        clobbered.code[lea + 10] = 0x80; // MOVSXD rax,[rax+rax*4]
        clobbered.code[lea + 13] = 0xc0; // ADD rax,rax
        cases.push(clobbered.code);

        // The table target is not an instruction boundary.
        let mut interior = sample(Some(0x87), 1, &[0x8b, 0x01]);
        let displacement = (interior.case0 as i64 + 1 - interior.table_start as i64) as i32;
        let offset = interior.table_start - interior.rva;
        interior.code[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
        cases.push(interior.code);

        // The second table item is truncated.
        let mut truncated = sample(Some(0x87), 1, &[0x8b, 0x01]);
        truncated.code.pop();
        cases.push(truncated.code);

        // A signed entry that resolves outside the decoded code prefix.
        let mut outside = sample(Some(0x87), 1, &[0x8b, 0x01]);
        let offset = outside.table_start - outside.rva;
        outside.code[offset..offset + 4].copy_from_slice(&0x100i32.to_le_bytes());
        cases.push(outside.code);

        // Add a direct branch from the body into CMP, bypassing index preparation.
        let mut jump_in = sample(Some(0x87), 1, &[0x8b, 0x01]);
        let site = jump_in.table_start;
        let mut branch = vec![0xe9];
        branch.extend(((jump_in.cmp as i64 - (site as i64 + 5)) as i32).to_le_bytes());
        insert_before_table(&mut jump_in, &branch);
        cases.push(jump_in.code);

        // Add an unrelated indirect jump in the decoded prefix.
        let mut indirect = sample(Some(0x87), 1, &[0x8b, 0x01]);
        insert_before_table(&mut indirect, &[0xff, 0xe1]);
        cases.push(indirect.code);

        for code in cases {
            assert!(decode(&code, 0x1000).is_err(), "accepted: {code:02x?}");
        }
    }

    #[test]
    fn checked_address_arithmetic_rejects_overflow() {
        let sample = sample(Some(0x87), 1, &[0x8b, 0x01]);
        assert!(decode(&sample.code, usize::MAX - sample.code.len() + 1).is_err());
    }

    fn two_switches(gap: usize, first_bound: u8, second_bound: u8, shared_table: bool) -> Vec<u8> {
        let rva = 0x3000usize;
        let mut code = Vec::new();
        let mut guards = Vec::new();
        let mut leas = Vec::new();
        for (bound, table_index) in [(first_bound, 0usize), (second_bound, 1usize)] {
            code.extend([0xb8, 0, 0, 0, 0]); // MOV EAX,0: a 32-bit seed.
            code.extend([0x83, 0xf8, bound]); // CMP EAX,bound.
            let guard = rva + code.len();
            code.extend([0x0f, 0x87, 0, 0, 0, 0]); // JA default.
            guards.push(guard);
            let lea = rva + code.len();
            code.extend([0x48, 0x8d, 0x0d, 0, 0, 0, 0]); // LEA RCX,[table].
            leas.push((lea, table_index));
            code.extend([0x48, 0x63, 0x04, 0x81]);
            code.extend([0x48, 0x01, 0xc8]);
            code.extend([0xff, 0xe0]);
        }
        let case0 = rva + code.len();
        code.extend([0x90, 0xc3]);
        let case1 = rva + code.len();
        code.extend([0x90, 0xc3]);
        let default0 = rva + code.len();
        code.push(0xc3);
        let default1 = rva + code.len();
        code.push(0xc3);
        let table1 = rva + code.len();
        let first_count = usize::from(first_bound) + 1;
        let second_count = usize::from(second_bound) + 1;
        let table2 = if shared_table {
            table1
        } else {
            table1 + first_count * 4 + gap
        };
        for (index, target) in [default0, default1].into_iter().enumerate() {
            let branch = guards[index];
            code[branch + 2 - rva..branch + 6 - rva]
                .copy_from_slice(&((target as i64 - (branch as i64 + 6)) as i32).to_le_bytes());
        }
        for (lea, table_index) in leas {
            let table = if shared_table || table_index == 0 {
                table1
            } else {
                table2
            };
            code[lea + 3 - rva..lea + 7 - rva]
                .copy_from_slice(&((table as i64 - (lea as i64 + 7)) as i32).to_le_bytes());
        }
        let first_table_count = if shared_table {
            first_count.max(second_count)
        } else {
            first_count
        };
        for index in 0..first_table_count {
            let target = if index % 2 == 0 { case0 } else { case1 };
            code.extend(((target as i64 - table1 as i64) as i32).to_le_bytes());
        }
        if !shared_table {
            code.resize(code.len() + gap, 0x90);
            for index in 0..second_count {
                let target = if index % 2 == 0 { case0 } else { case1 };
                code.extend(((target as i64 - table2 as i64) as i32).to_le_bytes());
            }
        }
        code
    }

    fn guard_copy_sample(copy_source: u8) -> Vec<u8> {
        let rva = 0x4000usize;
        let mut code = vec![0x83, 0xfe, 0x01]; // CMP ESI,1.
        let branch = rva + code.len();
        code.extend([0x0f, 0x87, 0, 0, 0, 0]); // JA default.
        code.extend([0x89, 0xc0 | (copy_source << 3)]); // MOV EAX,ESI or EDX.
        let lea = rva + code.len();
        code.extend([0x48, 0x8d, 0x0d, 0, 0, 0, 0]);
        code.extend([0x48, 0x63, 0x04, 0x81]);
        code.extend([0x48, 0x01, 0xc8]);
        code.extend([0xff, 0xe0]);
        let case0 = rva + code.len();
        code.extend([0x90, 0xc3]);
        let case1 = rva + code.len();
        code.extend([0x90, 0xc3]);
        let default = rva + code.len();
        code.push(0xc3);
        let table = rva + code.len();
        code[branch + 2 - rva..branch + 6 - rva]
            .copy_from_slice(&((default as i64 - (branch as i64 + 6)) as i32).to_le_bytes());
        code[lea + 3 - rva..lea + 7 - rva]
            .copy_from_slice(&((table as i64 - (lea as i64 + 7)) as i32).to_le_bytes());
        for target in [case0, case1] {
            code.extend(((target as i64 - table as i64) as i32).to_le_bytes());
        }
        code
    }

    #[test]
    fn accepts_guarded_lea32_index_and_post_guard_copy() -> Result<()> {
        let lea_index = sample(Some(0x87), 1, &[0x8d, 0x41, 0xfe]);
        assert_eq!(
            decode(&lea_index.code, lea_index.rva)?.switch_edges.len(),
            1
        );

        let copied = guard_copy_sample(6); // ESI -> EAX.
        let decoded = decode(&copied, 0x4000)?;
        assert_eq!(decoded.switch_edges.len(), 1);
        assert_eq!(decoded.protected_ranges.len(), 1);
        Ok(())
    }

    #[test]
    fn accepts_adjacent_guarded_tables_as_a_complete_tail() -> Result<()> {
        let code = two_switches(0, 1, 1, false);
        let decoded = decode(&code, 0x3000)?;
        assert_eq!(decoded.switch_edges.len(), 2);
        assert_eq!(decoded.code_bytes, code.len() - 16);
        assert_eq!(decoded.protected_ranges.len(), 2);
        Ok(())
    }

    #[test]
    fn rejects_noncontiguous_or_overlapping_tail_tables_and_extra_tail_bytes() {
        assert!(decode(&two_switches(1, 1, 1, false), 0x3000).is_err());
        assert!(decode(&two_switches(0, 1, 2, true), 0x3000).is_err());
        let mut extra = sample(Some(0x87), 1, &[0x8b, 0x01]).code;
        extra.push(0x90);
        assert!(decode(&extra, 0x1000).is_err());

        let mut enters_other_guard = two_switches(0, 1, 1, false);
        let first_table = 0x3000 + enters_other_guard.len() - 16;
        let second_cmp = 0x3000 + 30 + 5;
        let at = first_table - 0x3000;
        enters_other_guard[at..at + 4]
            .copy_from_slice(&((second_cmp as i64 - first_table as i64) as i32).to_le_bytes());
        assert!(decode(&enters_other_guard, 0x3000).is_err());
    }

    #[test]
    fn rejects_guard_copy_from_wrong_register_and_lea64_seed() {
        assert!(decode(&guard_copy_sample(2), 0x4000).is_err()); // EDX != CMP source ESI.
        let invalid_lea = sample(Some(0x87), 1, &[0x48, 0x8d, 0x41, 0xfe]).code;
        assert!(decode(&invalid_lea, 0x1000).is_err());
    }
}
