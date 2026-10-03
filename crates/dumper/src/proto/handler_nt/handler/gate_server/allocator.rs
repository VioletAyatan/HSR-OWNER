//! Bind the managed allocator to the current live API slot. An internal
//! implementation is accepted only through a complete, straight forwarding
//! wrapper that preserves the class argument and returned pointer.
use anyhow::{Context, Result, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::proto::{
    asm_address::module_rva,
    native_flow::{Binding, Resolver, UnwindCode, UnwindOperation},
    native_pe::{Pe, RuntimeFunction},
};
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

#[derive(Debug, PartialEq, Eq)]
struct SpilledForward {
    call_rva: usize,
    target_rva: usize,
    push_end: usize,
    allocation_end: usize,
    prolog_size: usize,
    frame_size: i64,
    result_disp: i64,
    continuation_rva: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct CatchFrame {
    push_end: usize,
    allocation_end: usize,
    prolog_size: usize,
    stack_size: i64,
}

fn immediate(i: &Instruction) -> Option<i64> {
    match i.op1_kind() {
        OpKind::Immediate8to64 => Some(i.immediate8to64()),
        OpKind::Immediate32to64 => Some(i.immediate32to64()),
        _ => None,
    }
}

fn input_memory(i: &Instruction, base: Register, bytes: usize) -> bool {
    i.op1_kind() == OpKind::Memory
        && i.memory_base() == base
        && i.memory_index() == Register::None
        && !i.has_segment_prefix()
        && i.memory_size().size() == bytes
}

fn output_memory(i: &Instruction, base: Register, bytes: usize) -> bool {
    i.op0_kind() == OpKind::Memory
        && i.memory_base() == base
        && i.memory_index() == Register::None
        && !i.has_segment_prefix()
        && i.memory_size().size() == bytes
}

fn address_memory(i: &Instruction, base: Register) -> bool {
    i.op1_kind() == OpKind::Memory
        && i.memory_base() == base
        && i.memory_index() == Register::None
        && !i.has_segment_prefix()
}

fn spilled_forwarding_target(code: &[u8], rva: usize) -> Result<SpilledForward> {
    let mut decoder = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE);
    let mut ins = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        ensure!(!i.is_invalid(), "invalid allocator wrapper instruction");
        ins.push(i);
    }
    ensure!(ins.len() == 10, "unsupported allocator wrapper body");
    ensure!(
        ins[0].mnemonic() == Mnemonic::Push && ins[0].op0_register() == Register::RBP,
        "allocator wrapper does not save RBP"
    );
    let frame_size = immediate(&ins[1]).context("unknown allocator frame size")?;
    ensure!(
        ins[1].mnemonic() == Mnemonic::Sub
            && ins[1].op0_register() == Register::RSP
            && frame_size > 0,
        "unsupported allocator stack allocation"
    );
    ensure!(
        ins[2].mnemonic() == Mnemonic::Lea
            && ins[2].op0_register() == Register::RBP
            && address_memory(&ins[2], Register::RSP)
            && ins[2].memory_displacement64() as i64 == frame_size,
        "allocator frame pointer does not cover its complete local frame"
    );
    ensure!(
        ins[3].mnemonic() == Mnemonic::Mov
            && output_memory(&ins[3], Register::RBP, 8)
            && ins[3].memory_displacement64() as i64 == -8
            && ins[3].op1_kind() == OpKind::Immediate32to64
            && ins[3].immediate32to64() == -2,
        "unsupported allocator EH state initialization"
    );
    ensure!(
        ins[4].flow_control() == FlowControl::Call && ins[4].op0_kind() == OpKind::NearBranch64,
        "allocator wrapper is not a single direct forwarding call"
    );
    let result_disp = ins[5].memory_displacement64() as i64;
    ensure!(
        ins[5].mnemonic() == Mnemonic::Mov
            && output_memory(&ins[5], Register::RBP, 8)
            && ins[5].op1_register() == Register::RAX
            && result_disp <= -16
            && result_disp % 8 == 0
            && result_disp >= -frame_size,
        "allocator result is not saved in an independent aligned local"
    );
    ensure!(
        ins[6].mnemonic() == Mnemonic::Mov
            && ins[6].op0_register() == Register::RAX
            && input_memory(&ins[6], Register::RBP, 8)
            && ins[6].memory_displacement64() as i64 == result_disp,
        "allocator result is not reloaded from the same local"
    );
    ensure!(
        ins[7].mnemonic() == Mnemonic::Add
            && ins[7].op0_register() == Register::RSP
            && immediate(&ins[7]) == Some(frame_size)
            && ins[8].mnemonic() == Mnemonic::Pop
            && ins[8].op0_register() == Register::RBP
            && ins[9].mnemonic() == Mnemonic::Ret
            && ins[9].op_count() == 0,
        "allocator wrapper has an unsupported epilogue"
    );
    Ok(SpilledForward {
        call_rva: ins[4].ip() as usize,
        target_rva: ins[4].near_branch_target() as usize,
        push_end: ins[0].next_ip() as usize - rva,
        allocation_end: ins[1].next_ip() as usize - rva,
        prolog_size: ins[2].next_ip() as usize - rva,
        frame_size,
        result_disp,
        continuation_rva: ins[6].ip() as usize,
    })
}

fn prove_null_catch(code: &[u8], rva: usize, forward: &SpilledForward) -> Result<CatchFrame> {
    let mut decoder = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE);
    let mut ins = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        ensure!(!i.is_invalid(), "invalid allocator catch instruction");
        ins.push(i);
    }
    ensure!(ins.len() == 10, "unsupported allocator catch body");
    ensure!(
        ins[0].mnemonic() == Mnemonic::Mov
            && output_memory(&ins[0], Register::RSP, 8)
            && ins[0].memory_displacement64() == 0x10
            && ins[0].op1_register() == Register::RDX,
        "allocator catch does not preserve its parent-frame argument"
    );
    ensure!(
        ins[1].mnemonic() == Mnemonic::Push
            && ins[1].op0_register() == Register::RBP
            && ins[2].mnemonic() == Mnemonic::Sub
            && ins[2].op0_register() == Register::RSP
            && immediate(&ins[2]).is_some_and(|size| size > 0),
        "unsupported allocator catch frame"
    );
    let catch_stack = immediate(&ins[2]).unwrap();
    ensure!(
        ins[3].mnemonic() == Mnemonic::Lea
            && ins[3].op0_register() == Register::RBP
            && address_memory(&ins[3], Register::RDX)
            && ins[3].memory_displacement64() as i64 == forward.frame_size,
        "allocator catch does not recover the exact parent frame"
    );
    ensure!(
        ins[4].mnemonic() == Mnemonic::Xor
            && ins[4].op0_register() == Register::EAX
            && ins[4].op1_register() == Register::EAX
            && ins[5].mnemonic() == Mnemonic::Mov
            && output_memory(&ins[5], Register::RBP, 8)
            && ins[5].memory_displacement64() as i64 == forward.result_disp
            && ins[5].op1_register() == Register::RAX,
        "allocator catch does not null the forwarded result local"
    );
    ensure!(
        ins[6].mnemonic() == Mnemonic::Lea
            && ins[6].op0_register() == Register::RAX
            && ins[6].is_ip_rel_memory_operand()
            && ins[6].ip_rel_memory_address() as usize == forward.continuation_rva,
        "allocator catch resumes outside the result reload"
    );
    ensure!(
        ins[7].mnemonic() == Mnemonic::Add
            && ins[7].op0_register() == Register::RSP
            && immediate(&ins[7]) == Some(catch_stack)
            && ins[8].mnemonic() == Mnemonic::Pop
            && ins[8].op0_register() == Register::RBP
            && ins[9].mnemonic() == Mnemonic::Ret
            && ins[9].op_count() == 0,
        "allocator catch has an unsupported epilogue"
    );
    Ok(CatchFrame {
        push_end: ins[1].next_ip() as usize - rva,
        allocation_end: ins[2].next_ip() as usize - rva,
        prolog_size: ins[3].next_ip() as usize - rva,
        stack_size: catch_stack,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unwind_capture_span(header: &[u8]) -> Result<usize> {
    ensure!(
        header.len() >= 4,
        "truncated allocator unwind capture header"
    );
    ensure!(header[0] & 7 == 1, "unsupported unwind capture version");
    let flags = header[0] >> 3;
    ensure!(
        flags & !7 == 0 && !(flags & 4 != 0 && flags & 3 != 0),
        "invalid unwind capture flags"
    );
    let aligned = (4usize
        .checked_add(
            usize::from(header[2])
                .checked_mul(2)
                .context("unwind capture slots overflow")?,
        )
        .context("unwind capture size overflow")?
        .checked_add(3)
        .context("unwind capture alignment overflow")?)
        & !3;
    aligned
        .checked_add(if flags == 4 {
            12
        } else if flags & 3 != 0 {
            8
        } else {
            0
        })
        .context("unwind capture tail overflow")
}

fn prove_wrapper(
    pe: &Pe<'_>,
    wrapper: RuntimeFunction,
    capture: &mut Value,
) -> Result<(usize, usize)> {
    let code = pe.bytes(wrapper.start, wrapper.end - wrapper.start)?;
    let unwind = pe.bytes(wrapper.unwind, 4)?;
    let end = wrapper
        .start
        .checked_add(code.len())
        .context("allocator capture range overflow")?;
    capture["wrapper_start_rva"] = json!(wrapper.start);
    capture["wrapper_end_rva"] = json!(end);
    capture["wrapper_code_hex"] = json!(hex(code));
    capture["unwind_header_hex"] = json!(hex(unwind));
    capture["stage"] = json!("validate-wrapper");
    ensure!(unwind.len() >= 4, "truncated allocator unwind header");
    ensure!(unwind[0] & 7 == 1, "unsupported allocator unwind version");
    if unwind[0] >> 3 == 0 {
        return forwarding_target(code, wrapper.start);
    }
    ensure!(
        unwind[0] >> 3 == 3,
        "allocator wrapper has unsupported unwind/handler"
    );
    let forward = spilled_forwarding_target(code, wrapper.start)?;
    let resolver = Resolver::new(pe.clone(), Binding::Loaded(0));
    let wrapper_unwind = resolver.unwind_profile(wrapper.start)?;
    ensure!(
        wrapper_unwind.flags == 3
            && wrapper_unwind.prolog_size == forward.prolog_size
            && wrapper_unwind.local_size == usize::try_from(forward.frame_size)?
            && wrapper_unwind.frame_register == Some(Register::RBP)
            && wrapper_unwind.frame_offset == usize::try_from(forward.frame_size)?
            && wrapper_unwind.pushed_nonvolatile == [Register::RBP]
            && wrapper_unwind.saved_ranges.is_empty()
            && wrapper_unwind.operations
                == [
                    UnwindCode {
                        code_offset: forward.prolog_size,
                        operation: UnwindOperation::SetFrameRegister,
                    },
                    UnwindCode {
                        code_offset: forward.allocation_end,
                        operation: UnwindOperation::Allocate(usize::try_from(forward.frame_size)?),
                    },
                    UnwindCode {
                        code_offset: forward.push_end,
                        operation: UnwindOperation::PushNonvolatile(Register::RBP),
                    },
                ],
        "allocator wrapper unwind does not match its complete frame"
    );
    let plan = resolver.exception_plan(wrapper.start, code)?;
    ensure!(
        plan.try_blocks == 1
            && plan.catch_handlers == 1
            && plan.catch_funclets.len() == 1
            && plan.switch_edges.is_empty()
            && plan.exceptional_edges.len() == 1
            && plan
                .exceptional_edges
                .get(&forward.call_rva)
                .is_some_and(|targets| targets.as_slice() == [forward.continuation_rva]),
        "allocator wrapper has an unproved exception path"
    );
    let (&funclet_rva, &continuation_rva) = plan.catch_funclets.iter().next().unwrap();
    ensure!(
        continuation_rva == forward.continuation_rva,
        "allocator catch continuation disagrees with the normal result reload"
    );
    let funclet = pe.function(funclet_rva)?;
    ensure!(
        pe.executable(funclet.start, funclet.end - funclet.start),
        "allocator catch funclet is not executable"
    );
    let catch_frame = prove_null_catch(
        pe.bytes(funclet.start, funclet.end - funclet.start)?,
        funclet.start,
        &forward,
    )?;
    let catch_unwind = resolver.unwind_profile(funclet_rva)?;
    ensure!(
        catch_unwind.flags == 3
            && catch_unwind.prolog_size == catch_frame.prolog_size
            && catch_unwind.local_size == usize::try_from(catch_frame.stack_size)?
            && catch_unwind.frame_register.is_none()
            && catch_unwind.frame_offset == 0
            && catch_unwind.pushed_nonvolatile == [Register::RBP]
            && catch_unwind.saved_ranges.is_empty()
            && catch_unwind.operations
                == [
                    UnwindCode {
                        code_offset: catch_frame.allocation_end,
                        operation: UnwindOperation::Allocate(usize::try_from(
                            catch_frame.stack_size,
                        )?),
                    },
                    UnwindCode {
                        code_offset: catch_frame.push_end,
                        operation: UnwindOperation::PushNonvolatile(Register::RBP),
                    },
                ]
            && Some(pe.u32(catch_unwind.data)? as usize) == plan.handler_rva
            && Some(pe.u32(catch_unwind.data + 4)? as usize) == plan.funcinfo_rva,
        "allocator catch unwind does not match its body or parent FH3 metadata"
    );
    capture["stage"] = json!("proved-catch-to-null");
    capture["handler_rva"] = json!(plan.handler_rva);
    capture["funcinfo_rva"] = json!(plan.funcinfo_rva);
    capture["catch_funclet_rva"] = json!(funclet_rva);
    capture["catch_continuation_rva"] = json!(continuation_rva);
    capture["result_frame_displacement"] = json!(forward.result_disp);
    Ok((forward.call_rva, forward.target_rva))
}

pub(super) fn bind(pe: &Pe<'_>, capture: &mut Value) -> Result<Proof> {
    *capture = json!({"stage":"resolve-live-api-slot", "unity_player_base_va":*il2cpp::UP_BASE,
        "game_assembly_base_va":*il2cpp::GA_BASE,"api_table_rva":*il2cpp::API_BASE_PTR,
        "api_index":130,"boundary":"live loaded slot and bounded wrapper bytes; capture is not acceptance"});
    let api_slot_rva = (*il2cpp::API_BASE_PTR)
        .checked_add(130usize.checked_mul(8).context("API index overflow")?)
        .context("allocator API slot overflow")?;
    let up = utils::scanner::unity_player_slice();
    let up_pe = Pe::new(up, memory::readable)?;
    capture["api_slot_rva"] = json!(api_slot_rva);
    capture["api_slot_va"] = json!(
        (*il2cpp::UP_BASE)
            .checked_add(api_slot_rva)
            .context("allocator slot VA overflow")?
    );
    let slot_bytes: [u8; 8] = up_pe.bytes(api_slot_rva, 8)?.try_into()?;
    capture["api_slot_bytes_hex"] = json!(hex(&slot_bytes));
    let address = usize::try_from(u64::from_le_bytes(slot_bytes))
        .context("allocator API pointer overflow")?;
    capture["api_pointer_va"] = json!(address);
    let api_rva = module_rva(address, *il2cpp::GA_BASE, pe.image_len())
        .context("allocator API outside GameAssembly")?;
    capture["api_pointer_rva"] = json!(api_rva);
    let wrapper = pe.function(api_rva)?;
    capture["wrapper_unwind_rva"] = json!(wrapper.unwind);
    capture["stage"] = json!("read-wrapper");
    ensure!(
        pe.executable(wrapper.start, wrapper.end - wrapper.start),
        "allocator wrapper is not executable"
    );
    let unwind = pe.bytes(wrapper.unwind, 4)?;
    capture["unwind_blob_hex"] =
        json!(hex(pe.bytes(wrapper.unwind, unwind_capture_span(unwind)?)?));
    let (forwarding_call_rva, allocator_rva) = prove_wrapper(pe, wrapper, capture)?;
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
    fn unwind_capture_includes_declared_slots_and_handler_or_chain_tail() {
        assert_eq!(unwind_capture_span(&[0x19, 0x0a, 3, 0x35]).unwrap(), 20);
        assert_eq!(unwind_capture_span(&[1, 0, 0, 0]).unwrap(), 4);
        assert_eq!(unwind_capture_span(&[0x21, 0, 0, 0]).unwrap(), 16);
        assert!(unwind_capture_span(&[1, 0]).is_err());
        assert!(unwind_capture_span(&[2, 0, 0, 0]).is_err());
        assert!(unwind_capture_span(&[0x39, 0, 0, 0]).is_err());
    }

    #[test]
    fn current_handler_wrapper_and_catch_share_the_same_null_result_local() {
        let wrapper = "554883ec30488d6c243048c745f8feffffffe8497f0700488945f0488b45f04883c4305dc3";
        let wrapper: Vec<_> = wrapper
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let forward = spilled_forwarding_target(&wrapper, 0x3eac500).unwrap();
        assert_eq!(forward.call_rva, 0x3eac512);
        assert_eq!(forward.target_rva, 0x3f24460);
        assert_eq!(forward.continuation_rva, 0x3eac51b);
        assert_eq!(forward.result_disp, -0x10);
        let mut overlapping = wrapper.clone();
        let spill = overlapping
            .windows(4)
            .position(|bytes| bytes == [0x48, 0x89, 0x45, 0xf0])
            .unwrap();
        overlapping[spill + 3] = 0xf8;
        assert!(spilled_forwarding_target(&overlapping, 0x3eac500).is_err());

        let catch = "4889542410554883ec20488d6a3033c0488945f0488d05d0ffffff4883c4205dc3";
        let mut catch: Vec<_> = catch
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        prove_null_catch(&catch, 0x3eac530, &forward).unwrap();
        catch[14] = 0x90;
        assert!(prove_null_catch(&catch, 0x3eac530, &forward).is_err());
    }

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
