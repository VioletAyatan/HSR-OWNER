//! Instruction operands are not interchangeable: an indirect branch has no
//! static target, and a register-relative displacement is not a module VA.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use std::collections::VecDeque;

pub(super) fn module_rva(va: usize, base: usize, image_len: usize) -> Option<usize> {
    va.checked_sub(base).filter(|&rva| rva < image_len)
}

pub(super) fn direct_branch_target(instruction: &Instruction) -> Option<usize> {
    (matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
        && matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ))
    .then(|| instruction.near_branch_target() as usize)
}

pub(super) fn direct_branch_rva(
    instruction: &Instruction,
    base: usize,
    image_len: usize,
) -> Option<usize> {
    module_rva(direct_branch_target(instruction)?, base, image_len)
}

pub(super) fn global_memory_rva(
    instruction: &Instruction,
    operand: u32,
    base: usize,
    image_len: usize,
) -> Option<usize> {
    if instruction.op_kind(operand) != OpKind::Memory || instruction.has_segment_prefix() {
        return None;
    }
    let va = if instruction.is_ip_rel_memory_operand() {
        instruction.ip_rel_memory_address()
    } else if instruction.memory_base() == Register::None
        && instruction.memory_index() == Register::None
    {
        instruction.memory_displacement64()
    } else {
        return None;
    };
    let rva = module_rva(va as usize, base, image_len)?;
    (rva.checked_add(size_of::<usize>())? <= image_len).then_some(rva)
}

pub(super) fn previous_type_load(
    instructions: &VecDeque<Instruction>,
    call_index: usize,
    base: usize,
    image_len: usize,
) -> Option<usize> {
    let load = instructions.get(call_index.checked_sub(1)?)?;
    if load.mnemonic() != Mnemonic::Mov || load.op0_register() != Register::RCX {
        return None;
    }
    global_memory_rva(load, 1, base, image_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    const BASE: usize = 0x180000000;
    fn decode(bytes: &[u8], ip: usize) -> Instruction {
        Decoder::with_ip(64, bytes, ip as u64, DecoderOptions::NONE).decode()
    }

    #[test]
    fn indirect_branches_have_no_static_target() {
        // call rax / call [rip+0x10] / jmp rax / jmp [rip+0x10]
        for bytes in [
            &[0xff, 0xd0][..],
            &[0xff, 0x15, 0x10, 0, 0, 0],
            &[0xff, 0xe0],
            &[0xff, 0x25, 0x10, 0, 0, 0],
        ] {
            let instruction = decode(bytes, BASE + 0x20);
            assert_eq!(direct_branch_target(&instruction), None);
            assert_eq!(direct_branch_rva(&instruction, BASE, 0x100), None);
        }
    }

    #[test]
    fn direct_targets_respect_module_bounds_without_wrapping() {
        let call = decode(&[0xe8, 0xdb, 0xff, 0xff, 0xff], BASE + 0x40);
        assert_eq!(direct_branch_rva(&call, BASE, 0x100), Some(0x20));
        let jump = decode(&[0xeb, 0xde], BASE + 0x40);
        assert_eq!(direct_branch_rva(&jump, BASE, 0x100), Some(0x20));
        assert_eq!(direct_branch_rva(&call, BASE + 0x21, 0x100), None);
        assert_eq!(direct_branch_rva(&call, BASE, 0x20), None);
        assert_eq!(module_rva(0, BASE, 0x100), None);
        assert_eq!(module_rva(BASE, BASE, 0x100), Some(0));
    }

    #[test]
    fn type_load_requires_a_global_pointer_and_a_preceding_instruction() {
        let load = decode(&[0x48, 0x8b, 0x0d, 0x19, 0, 0, 0], BASE);
        let instructions = VecDeque::from([load]);
        assert_eq!(previous_type_load(&instructions, 0, BASE, 0x100), None);
        assert_eq!(
            previous_type_load(&instructions, 1, BASE, 0x100),
            Some(0x20)
        );
        assert_eq!(previous_type_load(&instructions, 1, BASE, 0x27), None);
        for bytes in [
            &[0x48, 0x8b, 0x48, 0x20][..],
            &[0x48, 0x89, 0xc1],
            &[0x48, 0xc7, 0xc1, 0x20, 0, 0, 0],
            &[0x48, 0x8d, 0x0d, 0x19, 0, 0, 0],
        ] {
            let instructions = VecDeque::from([decode(bytes, BASE)]);
            assert_eq!(previous_type_load(&instructions, 1, BASE, 0x100), None);
        }
    }
}
