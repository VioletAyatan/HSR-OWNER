//! Response handler analysis uses code and declared TypeInfo slots only. It must
//! never dereference an address inferred from an arbitrary memory operand.

use super::asm_address::global_memory_rva;
use anyhow::{Context, Result, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use std::{
    collections::{BTreeMap, HashSet},
    ops::Range,
};

pub(super) struct FunctionTable<'a> {
    records: &'a [u8],
}

impl<'a> FunctionTable<'a> {
    pub fn from_pe(image: &'a [u8]) -> Result<Self> {
        fn word(image: &[u8], offset: usize) -> Result<usize> {
            let bytes = image
                .get(offset..offset.checked_add(4).context("PE address overflow")?)
                .context("truncated PE header")?;
            Ok(u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
        }
        ensure!(image.get(..2) == Some(b"MZ"), "missing DOS header");
        let pe = word(image, 0x3c)?;
        let optional = pe.checked_add(24).context("PE address overflow")?;
        ensure!(
            image
                .get(pe..optional)
                .is_some_and(|header| header.starts_with(b"PE\0\0")),
            "invalid PE header"
        );
        ensure!(
            image.get(optional..optional + 2) == Some(&[0x0b, 0x02]),
            "expected PE32+ image"
        );
        ensure!(
            word(image, optional + 108)? >= 4,
            "PE has no exception directory"
        );
        let rva = word(image, optional + 0x88)?;
        let size = word(image, optional + 0x8c)?;
        ensure!(
            rva != 0 && size != 0 && size % 12 == 0,
            "invalid runtime function table"
        );
        let records = image
            .get(rva..rva.checked_add(size).context("function table overflow")?)
            .context("runtime function table outside image")?;
        let table = Self { records };
        let mut previous = 0;
        for index in 0..records.len() / 12 {
            let range = table.record(index);
            ensure!(
                range.start >= previous && range.start < range.end && range.end <= image.len(),
                "invalid runtime function range {index}"
            );
            previous = range.start;
        }
        Ok(table)
    }

    fn record(&self, index: usize) -> Range<usize> {
        let bytes = &self.records[index * 12..index * 12 + 8];
        u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
            ..u32::from_le_bytes(bytes[4..].try_into().unwrap()) as usize
    }

    pub fn containing(&self, rva: usize) -> Option<Range<usize>> {
        let (mut low, mut high) = (0, self.records.len() / 12);
        while low < high {
            let middle = low + (high - low) / 2;
            if self.record(middle).start <= rva {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let range = self.record(low.checked_sub(1)?);
        (rva < range.end).then_some(rva..range.end)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Value {
    Object,
    Class,
    TypeInfo(usize),
}
type Registers = BTreeMap<Register, Value>;

pub(super) struct ScanResult {
    pub slot: Option<usize>,
    pub decoded: usize,
}

fn operand(
    instruction: &Instruction,
    index: u32,
    regs: &Registers,
    base: usize,
    image_len: usize,
    slots: &HashSet<usize>,
) -> Option<Value> {
    match instruction.op_kind(index) {
        OpKind::Register => regs.get(&instruction.op_register(index)).copied(),
        OpKind::Memory if instruction.memory_size().size() == size_of::<usize>() => {
            if let Some(rva) = global_memory_rva(instruction, index, base, image_len)
                && slots.contains(&rva)
            {
                return Some(Value::TypeInfo(rva));
            }
            (instruction.memory_displacement64() == 0
                && instruction.memory_index() == Register::None
                && regs.get(&instruction.memory_base()) == Some(&Value::Object))
            .then_some(Value::Class)
        }
        _ => None,
    }
}

pub(super) fn scan(
    code: &[u8],
    ip: u64,
    base: usize,
    image_len: usize,
    slots: &HashSet<usize>,
) -> ScanResult {
    let mut result = ScanResult {
        slot: None,
        decoded: 0,
    };
    let mut pending = vec![(0, BTreeMap::from([(Register::R8, Value::Object)]))];
    let mut visited = HashSet::new();
    let mut factory = InstructionInfoFactory::new();
    while let Some((offset, mut regs)) = pending.pop() {
        let Some(bytes) = code.get(offset..) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, ip + offset as u64, DecoderOptions::NONE);
        while decoder.can_decode() {
            let position = offset + decoder.position();
            if !visited.insert((position, regs.clone())) {
                break;
            }
            let instruction = decoder.decode();
            result.decoded += 1;
            if instruction.is_invalid() {
                break;
            }
            let left = operand(&instruction, 0, &regs, base, image_len, slots);
            let right = operand(&instruction, 1, &regs, base, image_len, slots);
            if instruction.mnemonic() == Mnemonic::Cmp {
                if let (Some(Value::Class), Some(Value::TypeInfo(rva)))
                | (Some(Value::TypeInfo(rva)), Some(Value::Class)) = (left, right)
                {
                    result.slot = Some(rva);
                    return result;
                }
            }
            let assigned = (instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().size() == 8)
                .then_some(right)
                .flatten();
            for reg in factory.info(&instruction).used_registers() {
                if matches!(
                    reg.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) {
                    regs.remove(&reg.register().full_register());
                }
            }
            if let Some(value) = assigned {
                regs.insert(instruction.op0_register(), value);
            }
            match instruction.flow_control() {
                FlowControl::Call | FlowControl::IndirectCall => {
                    for reg in [
                        Register::RAX,
                        Register::RCX,
                        Register::RDX,
                        Register::R8,
                        Register::R9,
                        Register::R10,
                        Register::R11,
                    ] {
                        regs.remove(&reg);
                    }
                }
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    if let Some(target) = instruction
                        .near_branch_target()
                        .checked_sub(ip)
                        .and_then(|value| usize::try_from(value).ok())
                        .filter(|&value| value < code.len())
                    {
                        pending.push((target, regs.clone()));
                    }
                    if instruction.flow_control() == FlowControl::UnconditionalBranch {
                        break;
                    }
                }
                FlowControl::Return
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::Exception => break,
                _ => {}
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: usize = 0x180000000;
    fn analyze(code: &[u8], slots: &[usize]) -> ScanResult {
        scan(
            code,
            BASE as u64,
            BASE,
            0x400,
            &slots.iter().copied().collect(),
        )
    }

    #[test]
    fn resolves_declared_global_type_without_dereferencing_it() {
        // mov rax,[r8]; cmp rax,[rip+0xF6] => TypeInfo slot 0x100
        let code = [0x49, 0x8b, 0x00, 0x48, 0x3b, 0x05, 0xf6, 0, 0, 0, 0xc3];
        assert_eq!(analyze(&code, &[0x100]).slot, Some(0x100));
        assert_eq!(analyze(&code, &[]).slot, None);
        // A register-relative, unaligned displacement must never be a pointer.
        assert_eq!(
            analyze(&[0x49, 0x8b, 0x00, 0x49, 0x3b, 0x47, 0x1c, 0xc3], &[0x1c]).slot,
            None
        );
    }

    #[test]
    fn respects_return_call_clobbers_and_register_overwrites() {
        let compare = [0x48, 0x3b, 0x05, 0, 0, 0, 0, 0xc3];
        for separator in [&[0xc3][..], &[0xff, 0xd0], &[0x31, 0xc0]] {
            let mut code = vec![0x49, 0x8b, 0x00];
            code.extend_from_slice(separator);
            code.extend_from_slice(&compare);
            assert_eq!(analyze(&code, &[3 + separator.len() + 7]).slot, None);
        }
    }

    #[test]
    fn follows_in_function_branches_and_finishes_loops() {
        let code = [
            0x49, 0x8b, 0x00, 0x75, 0x01, 0xc3, 0x48, 0x3b, 0x05, 0, 0, 0, 0, 0xc3,
        ];
        assert_eq!(analyze(&code, &[13]).slot, Some(13));
        let looped = analyze(&[0xeb, 0xfe], &[]);
        assert!(looped.slot.is_none() && looped.decoded == 1);
        assert_eq!(analyze(&[0xeb, 0x7f], &[]).slot, None);
    }

    #[test]
    fn function_bounds_follow_the_current_pe_and_reject_bad_records() {
        let mut image = vec![0u8; 0x400];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        image[0x40..0x44].copy_from_slice(b"PE\0\0");
        image[0x58..0x5a].copy_from_slice(&[0x0b, 0x02]);
        for (offset, value) in [
            (0xc4, 4u32),
            (0xe0, 0x180),
            (0xe4, 24),
            (0x180, 0x200),
            (0x184, 0x240),
            (0x18c, 0x280),
            (0x190, 0x300),
        ] {
            image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let table = FunctionTable::from_pe(&image).unwrap();
        assert_eq!(table.containing(0x210), Some(0x210..0x240));
        assert_eq!(table.containing(0x240), None);
        assert_eq!(table.containing(0), None);
        image[0x190..0x194].copy_from_slice(&0x401u32.to_le_bytes());
        assert!(FunctionTable::from_pe(&image).is_err());
    }
}
