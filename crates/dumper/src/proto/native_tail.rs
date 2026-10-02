//! Narrow proof for managed tail exits that restore the caller's frame first.
//! This proves only the machine-level exit shape; callers still bind the target
//! to current PE ownership and method metadata.
use anyhow::{Context, Result, ensure};
use iced_x86::{
    CodeSize, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};
use serde::Serialize;
use std::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct FrameAlias {
    pub register: String,
    pub allocation_offset: usize,
    pub established_at: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct TailExit {
    pub site: usize,
    pub target: usize,
    pub frame_size: usize,
    pub saved_registers: Vec<String>,
    pub epilogue_start: usize,
    pub epilogue_end: usize,
    pub matching_return_sites: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Proof {
    pub start: usize,
    pub end: usize,
    pub exits: Vec<TailExit>,
    pub matching_return_sites: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_alias: Option<FrameAlias>,
}

fn decode(code: &[u8], rva: usize) -> Result<Vec<Instruction>> {
    rva.checked_add(code.len())
        .context("tail body range overflow")?;
    let mut decoder = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        ensure!(
            !instruction.is_invalid(),
            "invalid instruction at 0x{:X}",
            instruction.ip()
        );
        instructions.push(instruction);
    }
    ensure!(!instructions.is_empty(), "empty tail body");
    Ok(instructions)
}

fn nonvolatile(reg: Register) -> bool {
    matches!(
        reg,
        Register::RBX
            | Register::RBP
            | Register::RSI
            | Register::RDI
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    )
}

fn imm(i: &Instruction) -> Option<usize> {
    let value = match i.op1_kind() {
        OpKind::Immediate8 => i.immediate8() as u64,
        OpKind::Immediate8to64 => u64::try_from(i.immediate8to64()).ok()?,
        OpKind::Immediate32 => i.immediate32() as u64,
        OpKind::Immediate32to64 => u64::try_from(i.immediate32to64()).ok()?,
        _ => return None,
    };
    usize::try_from(value).ok()
}

#[derive(Clone)]
struct Frame {
    regs: Vec<Register>,
    allocation: usize,
    frame_size: usize,
    prologue_end: usize,
    alias: Option<FrameAlias>,
}

fn frame(ins: &[Instruction], rva: usize) -> Result<Frame> {
    let mut index = 0;
    let mut regs = Vec::new();
    while index < ins.len() && ins[index].mnemonic() == Mnemonic::Push {
        let i = &ins[index];
        ensure!(
            i.op0_kind() == OpKind::Register
                && i.op0_register().size() == 8
                && nonvolatile(i.op0_register()),
            "unsupported saved register in prologue"
        );
        ensure!(
            !regs.contains(&i.op0_register()),
            "duplicate saved register"
        );
        regs.push(i.op0_register());
        index += 1;
    }
    ensure!(!regs.is_empty(), "no nonvolatile-register prologue");
    let allocation = if index < ins.len() && ins[index].mnemonic() == Mnemonic::Sub {
        let i = &ins[index];
        ensure!(
            i.op0_kind() == OpKind::Register && i.op0_register() == Register::RSP,
            "unsupported stack allocation"
        );
        let amount = imm(i).context("invalid stack allocation immediate")?;
        ensure!(amount > 0 && amount % 8 == 0, "unaligned stack allocation");
        index += 1;
        amount
    } else {
        0
    };
    let frame_size = regs
        .len()
        .checked_mul(8)
        .and_then(|n| n.checked_add(allocation))
        .context("frame size overflow")?;
    // Windows AMD64 calls require 16-byte alignment at the call site; entry RSP is 8 mod 16.
    ensure!(
        (8usize.wrapping_sub(frame_size) & 15) == 0,
        "prologue does not align call stack"
    );
    ensure!(index > 0, "empty prologue");
    let alias = if index < ins.len()
        && ins[index].mnemonic() == Mnemonic::Lea
        && ins[index].op0_kind() == OpKind::Register
        && ins[index].op0_register() == Register::RBP
    {
        let i = &ins[index];
        ensure!(
            regs.contains(&Register::RBP),
            "canonical frame alias requires saved RBP"
        );
        ensure!(
            i.op_count() == 2
                && i.op0_kind() == OpKind::Register
                && i.op0_register() == Register::RBP
                && i.op1_kind() == OpKind::Memory
                && i.memory_base() == Register::RSP
                && i.memory_index() == Register::None
                && i.memory_index_scale() == 1
                && matches!(i.memory_segment(), Register::None | Register::SS),
            "unsupported RBP frame alias"
        );
        let displacement = i.memory_displacement64() as i64;
        ensure!(
            displacement >= 0
                && usize::try_from(displacement).is_ok_and(|offset| offset <= allocation),
            "RBP frame alias is outside local allocation"
        );
        let alias = FrameAlias {
            register: "RBP".to_owned(),
            allocation_offset: displacement as usize,
            established_at: i.ip() as usize,
        };
        index += 1;
        Some(alias)
    } else {
        None
    };
    let end =
        usize::try_from(ins[index - 1].next_ip() as u64).context("prologue address overflow")?;
    ensure!(end > rva, "bad prologue end");
    Ok(Frame {
        regs,
        allocation,
        frame_size,
        prologue_end: end,
        alias,
    })
}

fn rbp_memory_range(
    instruction: &Instruction,
    memory: &iced_x86::UsedMemory,
    alias: &FrameAlias,
    allocation: usize,
) -> Result<()> {
    ensure!(
        memory.address_size() == CodeSize::Code64
            && memory.base() == Register::RBP
            && memory.index() == Register::None
            && matches!(memory.segment(), Register::None | Register::SS)
            && memory.memory_size().size() > 0,
        "unknown RBP-relative access extent at 0x{:X}",
        instruction.ip()
    );
    let base = i64::try_from(alias.allocation_offset).context("RBP alias offset overflow")?;
    let displacement = instruction.memory_displacement64() as i64;
    let start = base
        .checked_add(displacement)
        .context("RBP-relative access start overflow")?;
    let end = start
        .checked_add(i64::try_from(memory.memory_size().size())?)
        .context("RBP-relative access end overflow")?;
    ensure!(
        start >= 0 && usize::try_from(end).is_ok_and(|end| end <= allocation),
        "RBP-relative access escapes local allocation at 0x{:X}",
        instruction.ip()
    );
    Ok(())
}

fn epilogue_len(ins: &[Instruction], end: usize, f: &Frame) -> Option<usize> {
    let mut index = end;
    if f.allocation != 0 {
        let i = ins.get(index)?;
        if i.mnemonic() != Mnemonic::Add
            || i.op0_kind() != OpKind::Register
            || i.op0_register() != Register::RSP
            || imm(i)? != f.allocation
        {
            return None;
        }
        index += 1;
    }
    for reg in f.regs.iter().rev() {
        let i = ins.get(index)?;
        if i.mnemonic() != Mnemonic::Pop
            || i.op0_kind() != OpKind::Register
            || i.op0_register() != *reg
        {
            return None;
        }
        index += 1;
    }
    Some(index - end)
}

fn epilogue_start(ins: &[Instruction], end: usize, f: &Frame) -> Option<usize> {
    (0..end)
        .rev()
        .find(|&start| epilogue_len(ins, start, f).is_some_and(|n| start + n == end))
}

fn is_explicit_rsp_write(i: &Instruction, factory: &mut InstructionInfoFactory) -> bool {
    if matches!(
        i.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall | FlowControl::Return
    ) {
        return false;
    }
    factory.info(i).used_registers().iter().any(|r| {
        r.register().full_register() == Register::RSP
            && matches!(
                r.access(),
                OpAccess::Write
                    | OpAccess::ReadWrite
                    | OpAccess::CondWrite
                    | OpAccess::ReadCondWrite
            )
    })
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
    )
}

/// Prove direct external jumps only when they use the function's exact normal
/// epilogue. `own_pe_range` must be the full current-PE runtime-function range.
pub(super) fn exits(
    code: &[u8],
    rva: usize,
    own_pe_range: Option<Range<usize>>,
    mut is_declared_entry: impl FnMut(usize) -> bool,
) -> Result<Proof> {
    let end = rva
        .checked_add(code.len())
        .context("tail body range overflow")?;
    ensure!(
        own_pe_range
            .as_ref()
            .is_some_and(|range| range.start == rva && range.end == end),
        "body does not equal complete PE function range"
    );
    let ins = decode(code, rva)?;
    ensure!(
        usize::try_from(ins.last().unwrap().next_ip() as u64)? == end,
        "decoder did not consume full body"
    );
    let f = frame(&ins, rva)?;
    let mut returns = Vec::new();
    let mut epilogues: Vec<(usize, usize)> = Vec::new();
    let mut exits = Vec::new();
    for (index, i) in ins.iter().enumerate() {
        if i.flow_control() == FlowControl::Return {
            ensure!(
                i.mnemonic() == Mnemonic::Ret && i.op_count() == 0,
                "unsupported return form at 0x{:X}",
                i.ip()
            );
            if let Some(start) = epilogue_start(&ins, index, &f) {
                returns.push(i.ip() as usize);
                epilogues.push((start, index + 1));
            } else {
                anyhow::bail!("return lacks exact frame restoration at 0x{:X}", i.ip());
            }
        }
        if i.flow_control() == FlowControl::UnconditionalBranch
            && matches!(
                i.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            let target = i.near_branch_target() as usize;
            if target >= rva && target < end {
                continue;
            }
            let tail_start = epilogue_start(&ins, index, &f)
                .context("external jump lacks exact frame restoration")?;
            ensure!(
                target != rva && (target < rva || target >= end),
                "tail target is inside current function"
            );
            ensure!(
                is_declared_entry(target),
                "tail target is not a declared function entry"
            );
            epilogues.push((tail_start, index + 1));
            exits.push(TailExit {
                site: i.ip() as usize,
                target,
                frame_size: f.frame_size,
                saved_registers: f.regs.iter().map(|r| format!("{r:?}")).collect(),
                epilogue_start: ins[tail_start].ip() as usize,
                epilogue_end: i.ip() as usize,
                matching_return_sites: Vec::new(),
            });
        }
    }
    ensure!(!returns.is_empty(), "no normal RET with matching epilogue");
    ensure!(!exits.is_empty(), "no proven external tail exit");
    let mut factory = InstructionInfoFactory::new();
    for (index, i) in ins.iter().enumerate() {
        let is_frame_alias = f
            .alias
            .as_ref()
            .is_some_and(|alias| alias.established_at == i.ip() as usize);
        let is_saved_push = i.mnemonic() == Mnemonic::Push && index < f.regs.len();
        let is_matching_rbp_pop = i.mnemonic() == Mnemonic::Pop
            && i.op0_kind() == OpKind::Register
            && i.op0_register() == Register::RBP
            && epilogues
                .iter()
                .any(|(start, terminal)| index >= *start && index < *terminal);
        if is_explicit_rsp_write(i, &mut factory) {
            let in_prologue = (i.ip() as usize) < f.prologue_end
                && (is_saved_push
                    || (i.mnemonic() == Mnemonic::Sub
                        && i.op0_kind() == OpKind::Register
                        && i.op0_register() == Register::RSP
                        && f.allocation != 0
                        && imm(i) == Some(f.allocation)));
            let in_epilogue = epilogues
                .iter()
                .any(|(start, terminal)| index >= *start && index < *terminal)
                && (i.mnemonic() == Mnemonic::Pop
                    || (i.mnemonic() == Mnemonic::Add
                        && i.op0_kind() == OpKind::Register
                        && i.op0_register() == Register::RSP
                        && imm(i) == Some(f.allocation)));
            ensure!(
                in_prologue || in_epilogue,
                "unrecognized explicit RSP write at 0x{:X}",
                i.ip()
            );
        }
        for operand in 0..i.op_count() {
            if i.op_kind(operand) != OpKind::Register {
                continue;
            }
            let register = i.op_register(operand).full_register();
            if register == Register::RSP {
                ensure!(
                    (i.mnemonic() == Mnemonic::Sub || i.mnemonic() == Mnemonic::Add)
                        && operand == 0,
                    "RSP escapes through explicit register operand at 0x{:X}",
                    i.ip()
                );
            }
            if f.alias.is_some() && register == Register::RBP {
                ensure!(
                    (is_saved_push && operand == 0)
                        || (is_frame_alias && operand == 0)
                        || (is_matching_rbp_pop && operand == 0),
                    "RBP alias escapes through explicit register operand at 0x{:X}",
                    i.ip()
                );
            }
        }
        if i.mnemonic() == Mnemonic::Lea {
            if (i.memory_base().full_register() == Register::RSP
                || i.memory_index().full_register() == Register::RSP)
                && !is_frame_alias
            {
                anyhow::bail!("LEA escapes RSP as an address alias at 0x{:X}", i.ip());
            }
            if f.alias.is_some()
                && (i.memory_base().full_register() == Register::RBP
                    || i.memory_index().full_register() == Register::RBP)
            {
                anyhow::bail!("LEA escapes RBP frame alias at 0x{:X}", i.ip());
            }
        }
        let info = factory.info(i);
        for register in info.used_registers() {
            if f.alias.is_some()
                && register.register().full_register() == Register::RBP
                && writes(register.access())
            {
                ensure!(
                    is_frame_alias || is_matching_rbp_pop,
                    "RBP modified outside canonical prologue alias or matching POP at 0x{:X}",
                    i.ip()
                );
            }
        }
        if is_saved_push {
            continue;
        }
        let implicit_call_stack = matches!(
            i.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall | FlowControl::Return
        );
        for memory in info.used_memory() {
            ensure!(
                f.alias.is_none() || memory.index().full_register() != Register::RBP,
                "indexed RBP frame alias access at 0x{:X}",
                i.ip()
            );
            if memory.base().full_register() == Register::RBP
                && let Some(alias) = f.alias.as_ref()
            {
                rbp_memory_range(i, memory, alias, f.allocation)?;
                continue;
            }
            if !writes(memory.access()) || memory.base().full_register() != Register::RSP {
                continue;
            }
            if implicit_call_stack {
                continue;
            }
            ensure!(
                memory.address_size() == CodeSize::Code64
                    && memory.base() == Register::RSP
                    && memory.index() == Register::None
                    && matches!(memory.segment(), Register::None | Register::SS)
                    && memory.memory_size().size() > 0,
                "unknown RSP-relative write extent at 0x{:X}",
                i.ip()
            );
            let displacement = memory.displacement();
            let displacement = i64::try_from(displacement).with_context(|| {
                format!(
                    "negative or oversized RSP-relative displacement at 0x{:X}",
                    i.ip()
                )
            })?;
            ensure!(
                displacement >= 0,
                "negative RSP-relative write at 0x{:X}",
                i.ip()
            );
            let write_end = displacement
                .checked_add(i64::try_from(memory.memory_size().size())?)
                .context("RSP-relative write extent overflow")?;
            ensure!(
                usize::try_from(write_end).is_ok_and(|end| end <= f.allocation),
                "RSP-relative write overlaps saved registers or return address at 0x{:X}",
                i.ip()
            );
        }
    }
    // No direct control-flow entry may land after stack restoration has begun.
    for (index, i) in ins.iter().enumerate() {
        let is_direct_transfer = matches!(
            i.flow_control(),
            FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) && matches!(
            i.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        );
        if !is_direct_transfer {
            continue;
        }
        let target = i.near_branch_target() as usize;
        if target < rva || target >= end {
            continue;
        }
        let target_index = ins
            .iter()
            .position(|candidate| candidate.ip() as usize == target)
            .context("internal control transfer targets mid-instruction")?;
        ensure!(
            i.mnemonic() != Mnemonic::Call || target_index == 0,
            "internal CALL bypasses verified function prologue at 0x{:X}",
            i.ip()
        );
        ensure!(
            target_index == 0
                || target_index
                    >= ins
                        .iter()
                        .position(|candidate| candidate.ip() as usize == f.prologue_end)
                        .unwrap_or(usize::MAX),
            "control flow enters middle of verified prologue"
        );
        if i.mnemonic() != Mnemonic::Call && target_index == 0 {
            anyhow::bail!("branch re-enters function prologue at 0x{:X}", i.ip());
        }
        for (start, finish) in &epilogues {
            ensure!(
                target_index <= *start || target_index >= *finish,
                "control flow enters middle of verified epilogue"
            );
        }
        let _ = index;
    }
    let return_sites = returns.clone();
    for exit in &mut exits {
        exit.matching_return_sites = return_sites.clone();
    }
    Ok(Proof {
        start: rva,
        end,
        exits,
        matching_return_sites: returns,
        frame_alias: f.alias,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // push rbx; sub rsp,30h; add rsp,30h; pop rbx; ret;
    // add rsp,30h; pop rbx; jmp 2000h (with patched rel32)
    fn sample() -> Vec<u8> {
        let mut b = vec![
            0x53, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x83, 0xC4, 0x30, 0x5B, 0xC3, 0x48, 0x83, 0xC4,
            0x30, 0x5B, 0xE9, 0, 0, 0, 0,
        ];
        let site = 0x1000 + 16;
        let rel = 0x2000i32 - (site as i32 + 5);
        b[17..21].copy_from_slice(&rel.to_le_bytes());
        b
    }

    fn rbp_alias_sample(local_displacement: u8) -> Vec<u8> {
        let mut b = vec![
            0x55, // push rbp
            0x48,
            0x83,
            0xEC,
            0x30, // sub rsp,30h
            0x48,
            0x8D,
            0x6C,
            0x24,
            0x20, // lea rbp,[rsp+20h]
            0x89,
            0x45,
            local_displacement, // mov [rbp+disp8],eax
            0x48,
            0x83,
            0xC4,
            0x30,
            0x5D,
            0xC3, // normal epilogue
            0x48,
            0x83,
            0xC4,
            0x30,
            0x5D, // tail epilogue
            0xE9,
            0,
            0,
            0,
            0,
        ];
        let site = 0x1000i64 + 24;
        let relative = (0x2000i64 - (site + 5)) as i32;
        b[25..29].copy_from_slice(&relative.to_le_bytes());
        b
    }

    #[test]
    fn accepts_canonical_saved_rbp_alias_for_local_write_and_tail_exit() {
        let b = rbp_alias_sample(0xF8); // [rbp-8] maps to [rsp+18h]
        let proof = exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |target| {
            target == 0x2000
        })
        .unwrap();
        assert_eq!(
            proof.frame_alias,
            Some(FrameAlias {
                register: "RBP".to_owned(),
                allocation_offset: 0x20,
                established_at: 0x1005,
            })
        );
        assert_eq!(proof.exits[0].site, 0x1018);
        assert_eq!(proof.exits[0].target, 0x2000);
        assert_eq!(proof.matching_return_sites, [0x1012]);
    }

    #[test]
    fn preserves_tail_proof_for_prologue_followed_by_ordinary_rip_relative_lea() {
        let mut b = sample();
        b.splice(5..5, [0x48, 0x8D, 0x05, 0, 0, 0, 0]); // lea rax,[rip]
        let site = 0x1000i64 + 23;
        let relative = (0x2000i64 - (site + 5)) as i32;
        b[24..28].copy_from_slice(&relative.to_le_bytes());
        let proof = exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |target| {
            target == 0x2000
        })
        .unwrap();
        assert_eq!(proof.frame_alias, None);
        assert_eq!(proof.exits[0].site, 0x1017);
        assert_eq!(proof.exits[0].target, 0x2000);
    }

    #[test]
    fn preserves_non_alias_rbp_business_register_and_store() {
        let mut b = rbp_alias_sample(0x20);
        b.splice(5..10, [0x48, 0x89, 0xCD]); // mov rbp,rcx: business pointer, no stack alias
        let site = 0x1000i64 + 22;
        let relative = (0x2000i64 - (site + 5)) as i32;
        b[23..27].copy_from_slice(&relative.to_le_bytes());
        let proof = exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |target| {
            target == 0x2000
        })
        .unwrap();
        assert_eq!(proof.frame_alias, None);
        assert_eq!(proof.exits[0].target, 0x2000);
    }

    #[test]
    fn rejects_rbp_writes_outside_allocation_and_alias_escape_or_clobber() {
        let b = rbp_alias_sample(0x18); // [rsp+20h+18h, +4) exceeds 30h allocation
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());

        let mut b = rbp_alias_sample(0xF8);
        b.splice(13..13, [0x48, 0x89, 0xC5]); // mov rbp,rax
        let site = 0x1000i64 + 27;
        let relative = (0x2000i64 - (site + 5)) as i32;
        b[28..32].copy_from_slice(&relative.to_le_bytes());
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());

        let mut b = rbp_alias_sample(0xF8);
        b.splice(13..13, [0x48, 0x89, 0xE8]); // mov rax,rbp
        let site = 0x1000i64 + 27;
        let relative = (0x2000i64 - (site + 5)) as i32;
        b[28..32].copy_from_slice(&relative.to_le_bytes());
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());
    }

    #[test]
    fn rejects_rbp_alias_before_complete_frame_or_without_saved_rbp() {
        let mut b = vec![
            0x55, // push rbp
            0x48, 0x8D, 0x6C, 0x24, 0x20, // alias before allocation
            0x48, 0x83, 0xEC, 0x30, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0xC3, 0x48, 0x83, 0xC4, 0x30,
            0x5D, 0xE9, 0, 0, 0, 0,
        ];
        let site = 0x1000i64 + 21;
        let relative = (0x2000i64 - (site + 5)) as i32;
        b[22..26].copy_from_slice(&relative.to_le_bytes());
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());

        let mut b = rbp_alias_sample(0xF8);
        b[0] = 0x53; // push rbx, so RBP is not a saved register
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());
    }

    #[test]
    fn rejects_indexed_frame_alias_with_unknown_base_or_index() {
        for write in [&[0x89, 0x14, 0x28][..], &[0x89, 0x54, 0x05, 0][..]] {
            // mov [rax+rbp],edx; mov [rbp+rax],edx
            let mut b = rbp_alias_sample(0xF8);
            b.splice(13..13, write.iter().copied());
            let site = 0x1000i64 + 24 + write.len() as i64;
            let relative = (0x2000i64 - (site + 5)) as i32;
            let immediate = 25 + write.len();
            b[immediate..immediate + 4].copy_from_slice(&relative.to_le_bytes());
            let error = exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).unwrap_err();
            assert!(error.to_string().contains("RBP"));
        }
    }

    #[test]
    fn accepts_recursive_entry_call_and_rejects_call_into_epilogue() {
        for (target, accepted) in [(0x1000i64, true), (0x100Ai64, false)] {
            let mut b = sample();
            b.splice(5..5, [0xE8, 0, 0, 0, 0]);
            let call_relative = (target - 0x100A) as i32;
            b[6..10].copy_from_slice(&call_relative.to_le_bytes());
            let tail_relative = (0x2000i64 - (0x1015 + 5)) as i32;
            b[22..26].copy_from_slice(&tail_relative.to_le_bytes());
            let result = exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true);
            if accepted {
                assert!(result.is_ok());
            } else {
                assert!(result.unwrap_err().to_string().contains("internal CALL"));
            }
        }
    }

    #[test]
    fn proves_matching_restored_tail_exit() {
        let b = sample();
        let proof = exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |target| {
            target == 0x2000
        })
        .unwrap();
        assert_eq!(proof.exits[0].target, 0x2000);
        assert_eq!(proof.exits[0].saved_registers, ["RBX"]);
        assert_eq!(proof.matching_return_sites, [0x100A]);
    }

    #[test]
    fn rejects_missing_or_mismatched_frame_restore_and_unowned_target() {
        let mut b = sample();
        b[14] = 0x20; // tail path restores a different amount
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());
        let b = sample();
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| false).is_err());
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len() - 1), |_| true).is_err());
    }

    #[test]
    fn rejects_unknown_rsp_write() {
        let mut b = sample();
        b.splice(5..5, [0x48, 0x89, 0xE4]); // mov rsp,rsp
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());

        let mut b = sample();
        b.splice(5..5, [0x48, 0x89, 0xE0]); // mov rax,rsp: untracked stack alias
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());

        let mut b = sample();
        b.splice(5..5, [0x48, 0x8D, 0x04, 0x24]); // lea rax,[rsp]: untracked stack alias
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());
    }

    #[test]
    fn rejects_control_flow_into_restore_or_prologue_middle() {
        let mut b = sample();
        // Replace the first byte of the function with a short jump into POP RBX.
        // The destination is an instruction boundary but bypasses ADD RSP.
        b[0] = 0xEB;
        b[1] = 0x0E; // 0x1010, the tail path POP
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());

        let mut b = sample();
        // Jump from the body into the prologue SUB instruction.
        b[5] = 0xEB;
        b[6] = 0xF9; // 0x1000, first instruction (not middle); overridden below
        // Make a direct jump from the body target the SUB at 0x1001.
        b[5] = 0xEB;
        b[6] = 0xFA;
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());
    }

    #[test]
    fn rejects_extra_body_push_pop_and_ret_immediate() {
        let mut b = sample();
        b.splice(5..5, [0x50, 0x58]); // push rax; pop rax outside the declared frame
        let site = 0x1000i64 + 18;
        let rel = (0x2000i64 - (site + 5)) as i32;
        b[19..23].copy_from_slice(&rel.to_le_bytes());
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());

        let mut b = sample();
        b[10] = 0xC2; // ret 8
        b.splice(11..11, [0x08, 0x00]);
        let site = 0x1000i64 + 18;
        let rel = (0x2000i64 - (site + 5)) as i32;
        b[19..23].copy_from_slice(&rel.to_le_bytes());
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());
    }

    #[test]
    fn rejects_branch_reentering_function_entry() {
        let mut b = sample();
        b[5] = 0xEB;
        b[6] = 0xF9; // from 0x1005, branch back to entry 0x1000
        assert!(exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err());
    }

    fn insert_rsp_write(write: &[u8]) -> Vec<u8> {
        let mut b = sample();
        b.splice(5..5, write.iter().copied());
        let site = 0x1000i64 + 16 + write.len() as i64;
        let rel = (0x2000i64 - (site + 5)) as i32;
        let immediate = usize::try_from(site - 0x1000 + 1).unwrap();
        b[immediate..immediate + 4].copy_from_slice(&rel.to_le_bytes());
        b
    }

    #[test]
    fn accepts_only_local_rsp_writes_inside_allocation() {
        // mov [rsp+20h],rbx is wholly within the 30h allocated local area.
        let b = insert_rsp_write(&[0x48, 0x89, 0x5C, 0x24, 0x20]);
        assert!(
            exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |target| {
                target == 0x2000
            })
            .is_ok()
        );
    }

    #[test]
    fn accepts_standard_call_then_bounded_local_write() {
        let mut b = sample();
        // call 3000h; mov [rsp+20h],rbx; then the sample's normal return/tail paths.
        let mut insertion = vec![0xE8, 0, 0, 0, 0, 0x48, 0x89, 0x5C, 0x24, 0x20];
        let call_rel = 0x3000i32 - (0x1000i32 + 5 + 5);
        insertion[1..5].copy_from_slice(&call_rel.to_le_bytes());
        b.splice(5..5, insertion);
        let tail_site = 0x1000i32 + 16 + 10;
        let tail_rel = 0x2000i32 - (tail_site + 5);
        b[27..31].copy_from_slice(&tail_rel.to_le_bytes());
        assert!(
            exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |target| {
                target == 0x2000
            })
            .is_ok()
        );
    }

    #[test]
    fn rejects_saved_slot_return_slot_and_indexed_rsp_writes() {
        for write in [
            &[0x48, 0x89, 0x5C, 0x24, 0x30][..], // saved RBX slot
            &[0x48, 0x89, 0x5C, 0x24, 0x38][..], // return-address slot
            &[0x48, 0x89, 0x1C, 0xC4][..],       // [rsp+rax*8]
        ] {
            let b = insert_rsp_write(write);
            assert!(
                exits(&b, 0x1000, Some(0x1000..0x1000 + b.len()), |_| true).is_err(),
                "accepted invalid RSP write: {write:02X?}"
            );
        }
    }
}
