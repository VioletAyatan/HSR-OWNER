//! Bind the managed allocator to the current live API slot. An internal
//! implementation is accepted only through a complete, straight forwarding
//! wrapper that preserves the class argument and returned pointer.
use anyhow::{Context, Result, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, OpAccess, OpKind, Register,
};
use serde::Serialize;

use crate::proto::{asm_address::module_rva, native_pe::Pe};
use crate::script::memory;

#[derive(Serialize)]
pub(super) struct Proof {
    pub api_slot_rva: usize,
    pub api_rva: usize,
    pub allocator_rva: usize,
    pub wrapper_end: usize,
    pub forwarding_call_rva: usize,
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn forwarding_target(code: &[u8], rva: usize) -> Result<(usize, usize)> {
    rva.checked_add(code.len())
        .context("allocator wrapper range overflow")?;
    let mut decoder = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE);
    let mut info = InstructionInfoFactory::new();
    let mut call = None;
    let mut returned = false;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        ensure!(
            !instruction.is_invalid() && !returned,
            "invalid or unreachable allocator wrapper bytes"
        );
        match instruction.flow_control() {
            FlowControl::Call => {
                ensure!(
                    call.is_none() && instruction.op0_kind() == OpKind::NearBranch64,
                    "allocator API is not a single direct forwarding call"
                );
                call = Some((
                    instruction.ip() as usize,
                    instruction.near_branch_target() as usize,
                ));
            }
            FlowControl::Return => {
                ensure!(
                    call.is_some() && instruction.op_count() == 0,
                    "allocator wrapper has no ordinary forwarded return"
                );
                returned = true;
            }
            FlowControl::Next => {
                let protected = if call.is_some() {
                    Register::RAX
                } else {
                    Register::RCX
                };
                ensure!(
                    !info
                        .info(&instruction)
                        .used_registers()
                        .iter()
                        .any(|register| register.register().full_register() == protected
                            && writes(register.access())),
                    "allocator wrapper overwrites its class argument or return"
                );
                // No pointer rewrite, memory escape or hidden helper is inferred
                // from a prototype. Only stack frame housekeeping is supported.
                ensure!(
                    matches!(
                        instruction.mnemonic(),
                        iced_x86::Mnemonic::Push
                            | iced_x86::Mnemonic::Pop
                            | iced_x86::Mnemonic::Sub
                            | iced_x86::Mnemonic::Add
                            | iced_x86::Mnemonic::Nop
                    ) && info
                        .info(&instruction)
                        .used_memory()
                        .iter()
                        .all(|memory| memory.base() == Register::RSP
                            && memory.index() == Register::None),
                    "unsupported allocator forwarding instruction"
                );
            }
            _ => anyhow::bail!("allocator wrapper has unproved alternate control flow"),
        }
    }
    ensure!(returned, "allocator wrapper has no complete return");
    call.context("allocator wrapper has no forwarding call")
}

pub(super) fn bind(pe: &Pe<'_>) -> Result<Proof> {
    let api_slot_rva = (*il2cpp::API_BASE_PTR)
        .checked_add(130usize.checked_mul(8).context("API index overflow")?)
        .context("allocator API slot overflow")?;
    let up = utils::scanner::unity_player_slice();
    let up_pe = Pe::new(up, memory::readable)?;
    let address =
        usize::try_from(up_pe.u64(api_slot_rva)?).context("allocator API pointer overflow")?;
    let api_rva = module_rva(address, *il2cpp::GA_BASE, pe.image_len())
        .context("allocator API outside GameAssembly")?;
    let wrapper = pe.function(api_rva)?;
    ensure!(
        pe.executable(wrapper.start, wrapper.end - wrapper.start),
        "allocator wrapper is not executable"
    );
    let unwind = pe.bytes(wrapper.unwind, 4)?;
    ensure!(
        unwind[0] & 7 == 1 && unwind[0] >> 3 == 0,
        "allocator wrapper has unsupported unwind/handler"
    );
    let (forwarding_call_rva, allocator_rva) = forwarding_target(
        pe.bytes(wrapper.start, wrapper.end - wrapper.start)?,
        wrapper.start,
    )?;
    let target = pe.function(allocator_rva)?;
    ensure!(
        pe.executable(target.start, target.end - target.start),
        "allocator implementation is not executable"
    );
    Ok(Proof {
        api_slot_rva,
        api_rva,
        allocator_rva,
        wrapper_end: wrapper.end,
        forwarding_call_rva,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_forwarding_preserves_both_native_abi_values() {
        let code = [
            0x48, 0x83, 0xec, 0x28, 0xe8, 0x17, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        assert_eq!(forwarding_target(&code, 0x1000).unwrap(), (0x1004, 0x1020));
        let mut overwritten_argument = vec![0x31, 0xc9];
        overwritten_argument.extend(code);
        assert!(forwarding_target(&overwritten_argument, 0x1000).is_err());
        let mut overwritten_result = code[..9].to_vec();
        overwritten_result.extend([0x31, 0xc0]);
        overwritten_result.extend(&code[9..]);
        assert!(forwarding_target(&overwritten_result, 0x1000).is_err());
        assert!(forwarding_target(&[0xeb, 0, 0xc3], 0x1000).is_err());
        assert!(forwarding_target(&code[..13], 0x1000).is_err());
    }
}
