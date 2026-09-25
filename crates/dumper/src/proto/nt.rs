use super::asm_address::{
    direct_branch_rva, direct_branch_target, global_memory_rva, module_rva, previous_type_load,
};
use crate::dump_progress::Progress;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::{
    proto::{
        FIGHT_GAME_SEND, IL2CPP_OBJECT_NEW_RVA, MessageMinimalInfo, NETWORK_MANAGER_SEND_NAME,
        NETWORK_MANAGER_SEND_VA, XLUA_OBJECT_TRANSLATOR_DELEGATE,
        XLUA_OBJECT_TRANSLATOR_METHOD_CLASS, XLUA_OBJECT_TRANSLATOR_STATIC_FIELDS_CLASS,
        XLUA_REGISTER_OBJECT_RVA,
    },
    script::TYPE_INFOS,
};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use il2cpp::vm::method::Il2CppMethod;
use il2cpp::{
    FUNCTIONS_TABLE_REFLECTION, GA_BASE, get_cached_class, get_native_method,
    vm::{
        metadata_cache, native_collections::Dictionary, object::Il2CppObject, r#type::Il2CppType,
    },
};
use reflection::{field_info::FieldInfo, runtime_type::RuntimeType};
use std::borrow::Cow;
use utils::game_assembly_slice;

pub fn get_rsp_notify_map() -> HashMap<RuntimeType, u16> {
    let mut process = false;

    let mut typedef_index = unsafe { il2cpp::ASSEMBLY_CSHARP_START };
    for _ in unsafe { typedef_index..il2cpp::MAX_TYPEDEFINDEX } {
        let class = metadata_cache::get_typeinfo_from_typedefindex(typedef_index);
        let runtime_type = RuntimeType::from_class(class).unwrap();
        if runtime_type.get_name().unwrap().as_str() == "NotifyType" {
            typedef_index += 2;
            process = true;
            continue;
        }

        if process {
            if let Some(dictionary) = runtime_type
                .get_fields(62)
                .iter()
                .find(|v| {
                    v.get_field_type().unwrap().format_type_name(true)
                        == "Dictionary<RuntimeTypeHandle, ushort>"
                })
                .map(|v| v.get_value(Il2CppObject::NULL).unwrap())
            {
                let dict = unsafe { *(dictionary.0 as *const Dictionary<Il2CppType, u16>) };

                return dict
                    .iter()
                    .map(|(ty, cmdid)| (RuntimeType::from_il2cpp_type(ty).unwrap(), cmdid))
                    .collect();
            }
            log::debug!("[Proto Dumper] cannot find nt field!");

            break;
        }

        typedef_index += 1;
        continue;
    }

    HashMap::new()
}

fn get_req_method_va_name_map() -> HashMap<usize, String> {
    let mut output = HashMap::new();

    let mappings = disasm_obf_deobf_method_by_xlua_obj_translator();
    let translator_method_class = &*XLUA_OBJECT_TRANSLATOR_METHOD_CLASS;
    let mut unique_methods = HashMap::<Cow<'static, str>, Vec<Il2CppMethod>>::new();
    FUNCTIONS_TABLE_REFLECTION
        .get()
        .unwrap()
        .iter()
        .for_each(|v| unique_methods.entry(v.1.get_name()).or_default().push(*v.1));

    for (obf, deobf) in mappings {
        if !deobf.ends_with("Req") {
            continue;
        }

        let Some(methods) = unique_methods.get(&Cow::Borrowed(obf.as_str())) else {
            continue;
        };

        for method in methods {
            if !translator_method_class.is_empty()
                && method.class().byval_arg().il_name() == *translator_method_class
            {
                continue;
            }

            output.insert(method.va(), deobf.clone());
        }
    }

    output
}

fn disasm_obf_deobf_method_by_xlua_obj_translator() -> HashMap<String, String> {
    let mut output = HashMap::new();

    let delegate_name = &*XLUA_OBJECT_TRANSLATOR_DELEGATE;
    let fields_class_name = &*XLUA_OBJECT_TRANSLATOR_STATIC_FIELDS_CLASS;
    let xlua_register_object_rva = *XLUA_REGISTER_OBJECT_RVA;
    if delegate_name.is_empty() || fields_class_name.is_empty() || xlua_register_object_rva == 0 {
        log::debug!(
            "[Proto Dumper] XLua ObjectTranslator metadata incomplete; skipping request name translation"
        );
        return output;
    }

    let Some(delegate_class) = get_cached_class(delegate_name) else {
        log::debug!(
            "[Proto Dumper] XLua delegate class not found; skipping request name translation"
        );
        return output;
    };
    let Some(type_infos) = TYPE_INFOS.get() else {
        log::debug!("[Proto Dumper] TYPE_INFOS unavailable; skipping request name translation");
        return output;
    };
    let Some(&delegate_type_rva) = type_infos.get(&delegate_class) else {
        log::debug!(
            "[Proto Dumper] XLua delegate TypeInfo unavailable; skipping request name translation"
        );
        return output;
    };

    let Some(obj_translator_fields_class) = get_cached_class(fields_class_name) else {
        log::debug!(
            "[Proto Dumper] XLua fields class not found; skipping request name translation"
        );
        return output;
    };
    let obj_translator_fields = obj_translator_fields_class
        .get_fields()
        .into_iter()
        .map(|v| {
            (
                v.offset(),
                strip_prefixes(
                    FieldInfo::from_il2cpp_field(v)
                        .unwrap()
                        .get_name()
                        .unwrap()
                        .as_str()
                        .split_once("__")
                        .map(|(_, rest)| rest)
                        .unwrap(),
                    &["Send"],
                )
                .to_string(),
            )
        })
        .collect::<HashMap<_, _>>();

    let slice = game_assembly_slice();
    if xlua_register_object_rva >= slice.len() {
        log::debug!(
            "[Proto Dumper] XLua RegisterObject RVA is out of range; skipping request name translation"
        );
        return output;
    }
    let mut decoder = Decoder::with_ip(
        64,
        &slice[xlua_register_object_rva..],
        *GA_BASE as u64 + xlua_register_object_rva as u64,
        DecoderOptions::NONE,
    );

    let mut instructions = VecDeque::<Instruction>::with_capacity(500);
    let mut instruction = Instruction::default();

    let mut static_field_offset = None;
    let mut push_cnt = 0;
    let mut past_prologue = false;

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        if instruction.mnemonic() == Mnemonic::Push {
            if past_prologue {
                push_cnt += 1;

                if push_cnt > 4 {
                    break;
                }
            }
        } else {
            past_prologue = true;
        }

        // mov rcx, cs:XLUA_DELEGATE_TYPE_INFO_VA
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_register() == Register::RCX
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_displacement64() == (delegate_type_rva + *il2cpp::GA_BASE) as u64
        {
            // traverse to find the displacement register
            let mut found_offset = None;
            for i in (0..instructions.len()).rev() {
                let inst = instructions[i];

                if inst.mnemonic() != Mnemonic::Mov {
                    continue;
                }

                let offset = (is_gp64_register(inst.op0_register())
                    && inst.op1_kind() == OpKind::Memory
                    || inst.op0_kind() == OpKind::Memory)
                    .then(|| inst.memory_displacement64());

                let Some(offset) = offset else {
                    continue;
                };

                if obj_translator_fields.contains_key(&(offset as usize)) {
                    found_offset = Some(offset);
                    break;
                }
            }

            if let Some(offset) = found_offset {
                static_field_offset = Some(offset);
            }

            continue;
        }

        // static_field_offset already set
        // call to il2cpp_object_new
        let il2cpp_object_new_rva = *IL2CPP_OBJECT_NEW_RVA;
        if let Some(offset) = static_field_offset
            && instruction.mnemonic() == Mnemonic::Call
            && direct_branch_rva(&instruction, *GA_BASE, slice.len()) == Some(il2cpp_object_new_rva)
        {
            decoder.decode_out(&mut instruction); // skip mov rsi, rax
            decoder.decode_out(&mut instruction);

            // mov rax, cs::METHOD_INFO_VA
            if instruction.mnemonic() == Mnemonic::Mov
                && let Some(rva) = global_memory_rva(&instruction, 1, *GA_BASE, slice.len())
            {
                let type_va = *GA_BASE + rva;

                let method = unsafe { *(type_va as *const Il2CppMethod) };
                if method.0 == 0 {
                    static_field_offset = None;
                    continue;
                }

                let Some(field_name) = obj_translator_fields.get(&(offset as usize)) else {
                    static_field_offset = None;
                    continue;
                };

                let name = method.get_name();

                output.insert(name.to_string(), field_name.to_string());
                static_field_offset = None;
            }

            continue;
        }

        instructions.push_back(instruction);
    }

    output
}

pub fn get_req_map(
    minimal_info: &HashMap<RuntimeType, MessageMinimalInfo>,
    rsp_notify_map: &HashMap<RuntimeType, u16>,
    req_map: &mut HashMap<RuntimeType, (u16, Option<String>)>,
    progress: &Progress,
) -> HashMap<RuntimeType, Vec<String>> {
    let Some(type_infos) = TYPE_INFOS.get() else {
        log::debug!("[Proto Dumper] TYPE_INFOS unavailable; skipping request mapping");
        return HashMap::new();
    };

    progress.step(0, 0, "resolve request TypeInfo slots");
    let type_info_rvas = minimal_info
        .iter()
        .filter(|(ty, _)| !ty.get_isenum().unwrap().unbox() && !rsp_notify_map.contains_key(ty))
        .filter_map(|(ty, _)| {
            type_infos
                .get(&ty.get_il2cpp_type().get_class())
                .map(|&rva| (rva, *ty))
        })
        .collect::<HashMap<_, _>>();

    progress.step(0, 0, "resolve request send targets");
    let networkmanager_send_name = &*NETWORK_MANAGER_SEND_NAME;
    let networkmanager_send_va = if networkmanager_send_name.is_empty() {
        0
    } else {
        get_native_method(&format!(
            "RPG.Client.NetworkManager::{}(System.UInt16,Google.Protobuf.IMessage,System.Boolean)",
            networkmanager_send_name
        ))
        .map_or(0, |method| method.va())
    };
    let networkmanager_send_va2 = *NETWORK_MANAGER_SEND_VA;
    let networkmanager_send_va3 = *FIGHT_GAME_SEND;

    let mut targets = HashMap::with_capacity(3);

    if networkmanager_send_va != 0 {
        targets.insert(networkmanager_send_va, ReqFlavor::Standard);
    }
    if networkmanager_send_va2 != 0 {
        targets.insert(networkmanager_send_va2, ReqFlavor::Standard);
    }
    if networkmanager_send_va3 != 0 {
        targets.insert(networkmanager_send_va3, ReqFlavor::Fight);
    }

    if targets.is_empty() {
        log::debug!("[Proto Dumper] no request send targets found; skipping request mapping");
        return HashMap::new();
    }

    log::debug!(
        "[Proto Dumper] scanning request call sites with {} send target(s)",
        targets.len()
    );

    disasm_all_req(&type_info_rvas, targets, rsp_notify_map, req_map, progress)
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
enum ReqFlavor {
    Standard, // DX, R8
    Fight,    // R8, R9
}

fn disasm_all_req(
    type_info_rvas: &HashMap<usize, RuntimeType>,
    targets: HashMap<usize, ReqFlavor>,
    rsp_notify_map: &HashMap<RuntimeType, u16>,
    out: &mut HashMap<RuntimeType, (u16, Option<String>)>,
    progress: &Progress,
) -> HashMap<RuntimeType, Vec<String>> {
    progress.step(0, 0, "resolve XLua request names");
    let va_deobf_map = get_req_method_va_name_map();
    let slice = game_assembly_slice();
    let base = *GA_BASE;
    progress.step(0, 0, "resolve object allocator");
    let object_new_rva = *IL2CPP_OBJECT_NEW_RVA;
    let mut decoder = Decoder::with_ip(64, slice, base as u64, DecoderOptions::NONE);
    progress.stage("request call-site scan", slice.len());
    let mut decoded = 0usize;
    let mut send_calls = 0usize;
    let mut indirect_branches = 0usize;

    let mut instruction = Instruction::default();
    let mut instructions = VecDeque::<Instruction>::with_capacity(500);
    let mut req_rvas: HashMap<RuntimeType, Vec<String>> = HashMap::new();

    #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    enum InstType {
        Memory { base: Register, displacement: i64 },
        Normal(Register),
    }

    impl InstType {
        pub fn new(op_kind: OpKind, reg: Register, memory: Register, displacement: i64) -> Self {
            if op_kind == OpKind::Memory {
                Self::Memory {
                    base: memory,
                    displacement,
                }
            } else {
                Self::Normal(reg)
            }
        }
        pub fn is_rax(&self) -> bool {
            match self {
                InstType::Memory { base, .. } => *base == Register::RAX,
                InstType::Normal(register) => *register == Register::RAX,
            }
        }
        pub fn is_none(&self) -> bool {
            match self {
                InstType::Memory { base, .. } => *base == Register::None,
                InstType::Normal(register) => *register == Register::None,
            }
        }
    }

    type CandidateInfo = (HashSet<u16>, HashSet<Option<String>>, Vec<String>);
    let mut candidates: HashMap<RuntimeType, CandidateInfo> = HashMap::new();
    let mut cur_func_va = None;

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if decoded % 4096 == 0 {
            progress.step(
                decoder.position(),
                instruction.ip() as usize,
                "decode request instructions",
            );
        }
        decoded += 1;

        if instruction.mnemonic() == Mnemonic::Push
            && let Some(prev) = instructions.back()
            && prev.mnemonic() != Mnemonic::Push
        {
            cur_func_va = Some(instruction.ip());
            instructions.clear();
        }

        if let Some(target) = direct_branch_target(&instruction)
            && let Some(&flavor) = targets.get(&target)
        {
            send_calls += 1;
            progress.step(
                decoder.position(),
                instruction.ip() as usize,
                "trace request arguments",
            );
            let mut obj_register = None;
            let mut cmd_id = None;
            let mut push_rva = None;
            let mut last_push_index = None;

            let mut i = instructions.len();
            while i > 0 {
                i -= 1;
                if instructions[i].mnemonic() == Mnemonic::Push {
                    last_push_index = Some(i);
                } else if last_push_index.is_some() {
                    break;
                }
            }
            if let Some(push_index) = last_push_index {
                push_rva = module_rva(instructions[push_index].ip() as usize, base, slice.len());
            }

            for i in (0..instructions.len()).rev() {
                let inst = instructions[i];
                if inst.mnemonic() == Mnemonic::Push {
                    break;
                }

                // 1: CmdId
                if cmd_id.is_none()
                    && inst.mnemonic() == Mnemonic::Mov
                    && matches!(
                        inst.op1_kind(),
                        OpKind::Immediate16
                            | OpKind::Immediate32
                            | OpKind::Immediate32to64
                            | OpKind::Immediate64
                    )
                {
                    let reg = inst.op0_register();
                    let is_match = match flavor {
                        ReqFlavor::Standard => reg == Register::DX,
                        ReqFlavor::Fight => reg == Register::R8 || reg == Register::R8W,
                    };
                    if is_match {
                        let id = inst.immediate(1) as u16;
                        if id != 0 && !rsp_notify_map.values().any(|&v| v == id) {
                            cmd_id = Some(id);
                        }
                    }
                    if cmd_id.is_some() {
                        continue;
                    }
                }

                // 2: Object Register
                if obj_register.is_none() && inst.mnemonic() == Mnemonic::Mov {
                    let reg = inst.op0_register();
                    let is_match = match flavor {
                        ReqFlavor::Standard => reg == Register::R8,
                        ReqFlavor::Fight => reg == Register::R9,
                    };
                    if is_match {
                        obj_register = Some(InstType::new(
                            inst.op1_kind(),
                            inst.op1_register(),
                            inst.memory_base(),
                            inst.memory_displacement64() as i64,
                        ));
                        continue;
                    }
                }

                // 3: register
                if let Some(reg) = obj_register
                    && inst.mnemonic() == Mnemonic::Mov
                    && (InstType::new(
                        inst.op0_kind(),
                        inst.op0_register(),
                        inst.memory_base(),
                        inst.memory_displacement64() as i64,
                    ) == reg)
                    && !reg.is_rax()
                {
                    let new = InstType::new(
                        inst.op1_kind(),
                        inst.op1_register(),
                        inst.memory_base(),
                        inst.memory_displacement64() as i64,
                    );
                    if !new.is_none() {
                        obj_register = Some(new);
                    }
                    continue;
                }

                // 4: Identification
                if let Some(cmd_id) = cmd_id
                    && let Some(reg) = obj_register
                {
                    // A: il2cpp_object_new
                    if reg.is_rax()
                        && (inst.mnemonic() == Mnemonic::Call || inst.mnemonic() == Mnemonic::Jmp)
                    {
                        if direct_branch_target(&inst).is_none() {
                            indirect_branches += 1;
                        }
                        if object_new_rva != 0
                            && direct_branch_rva(&inst, base, slice.len()) == Some(object_new_rva)
                            && let Some(rva) =
                                previous_type_load(&instructions, i, base, slice.len())
                            && let Some(&rt) = type_info_rvas.get(&rva)
                        {
                            let deobf_name =
                                cur_func_va.and_then(|v| va_deobf_map.get(&(v as usize)).cloned());
                            let entry = candidates
                                .entry(rt)
                                .or_insert_with(|| (HashSet::new(), HashSet::new(), Vec::new()));
                            entry.0.insert(cmd_id);
                            entry.1.insert(deobf_name);
                            if let Some(prva) = push_rva {
                                entry.2.push(format!("0x{prva:X}"));
                            }
                            break;
                        }
                        // RAX is this call's result. An unknown call cannot be
                        // traced through to an earlier allocation of another object.
                        break;
                    }

                    // B: Cmp
                    if flavor == ReqFlavor::Standard
                        && inst.mnemonic() == Mnemonic::Cmp
                        && inst.op0_kind() == OpKind::Memory
                        && inst.memory_base()
                            == match reg {
                                InstType::Normal(r) => r,
                                InstType::Memory { base, .. } => base,
                            }
                    {
                        let type_info_reg = inst.op1_register();
                        if type_info_reg != Register::None {
                            for j in (0..i).rev() {
                                let prev = instructions[j];
                                if prev.mnemonic() == Mnemonic::Mov
                                    && prev.op0_register() == type_info_reg
                                    && let Some(rva) =
                                        global_memory_rva(&prev, 1, base, slice.len())
                                    && let Some(&rt) = type_info_rvas.get(&rva)
                                {
                                    let deobf_name = cur_func_va
                                        .and_then(|v| va_deobf_map.get(&(v as usize)).cloned());
                                    let entry = candidates.entry(rt).or_insert_with(|| {
                                        (HashSet::new(), HashSet::new(), Vec::new())
                                    });
                                    entry.0.insert(cmd_id);
                                    entry.1.insert(deobf_name);
                                    if let Some(prva) = push_rva {
                                        entry.2.push(format!("0x{prva:X}"));
                                    }
                                    break;
                                }
                            }
                            if candidates.values().any(|v| v.0.contains(&cmd_id)) {
                                break;
                            }
                        }
                    }
                }
            }
        }
        if instructions.len() >= 500 {
            instructions.pop_front();
        }
        instructions.push_back(instruction);
    }

    let candidate_count = candidates.len();
    let mut ambiguous = 0;
    for (rt, (ids, names, rvas)) in candidates {
        if ids.len() == 1 {
            out.insert(
                rt,
                (
                    *ids.iter().next().unwrap(),
                    names.into_iter().flatten().next(),
                ),
            );
            req_rvas.insert(rt, rvas);
        } else {
            ambiguous += 1;
        }
    }
    log::info!(
        "[Proto Dumper] request scan completed instructions={decoded} send_calls={send_calls} indirect_branches_without_static_target={indirect_branches} candidate_types={candidate_count} mapped={} ambiguous_cmd_ids={ambiguous}",
        req_rvas.len()
    );
    req_rvas
}

pub(super) struct ResponseMappings {
    pub names: HashMap<String, String>,
    pub method_rvas: HashMap<String, Vec<String>>,
}

pub(super) fn collect_rsp_notify_mappings(
    minimal_info: &HashMap<RuntimeType, MessageMinimalInfo>,
    progress: &Progress,
) -> anyhow::Result<ResponseMappings> {
    use anyhow::Context;
    let cached_methods = FUNCTIONS_TABLE_REFLECTION
        .get()
        .context("reflection methods unavailable")?;
    let type_infos = TYPE_INFOS
        .get()
        .context("Script TypeInfo cache unavailable")?;
    let mut types = HashMap::new();
    progress.step(0, 0, "resolve response TypeInfo slots");
    for &ty in minimal_info.keys() {
        if let Some(&slot) = type_infos.get(&ty.get_il2cpp_type().get_class()) {
            types.insert(slot, ty);
        }
    }
    let slots = types.keys().copied().collect::<HashSet<_>>();
    let handlers = cached_methods
        .iter()
        .filter_map(|(signature, method)| {
            let name = signature
                .strip_suffix("(System.UInt16,System.Object)")?
                .rsplit_once("::")?
                .1;
            let prefix = ["_OnCmd", "_Cmd", "_On", "OnCmd", "On", "Cmd"]
                .into_iter()
                .find(|prefix| name.starts_with(prefix))?;
            Some((
                signature,
                method,
                name.strip_prefix(prefix)
                    .unwrap()
                    .replace("Cmd", "")
                    .replace("ScRep", "ScRsp"),
            ))
        })
        .collect::<Vec<_>>();
    let image = game_assembly_slice();
    let base = *GA_BASE;
    let functions = super::rsp_scan::FunctionTable::from_pe(image)
        .context("response handler function bounds")?;
    progress.stage("response/notify names", handlers.len());
    let mut output = ResponseMappings {
        names: HashMap::new(),
        method_rvas: HashMap::new(),
    };
    let mut formatted = HashMap::<RuntimeType, String>::new();
    let mut no_body = 0;
    let mut unmatched = 0;
    let mut decoded = 0;
    let mut matched = 0;
    for (index, (signature, method, name)) in handlers.into_iter().enumerate() {
        progress.step(index, method.0, "resolve response handler address");
        let va = method.va();
        let Some(rva) = module_rva(va, base, image.len()).filter(|&rva| rva != 0) else {
            no_body += 1;
            continue;
        };
        let Some(range) = functions.containing(rva) else {
            no_body += 1;
            continue;
        };
        progress.step(index, va, "decode response handler");
        let result = super::rsp_scan::scan(&image[range], va as u64, base, image.len(), &slots);
        decoded += result.decoded;
        let Some(slot) = result.slot else {
            unmatched += 1;
            continue;
        };
        // The scanner can return only a declared slot; no guessed native pointer.
        let ty = types[&slot];
        progress.step(index, ty.0, "format response type name");
        let formatted_name = if let Some(name) = formatted.get(&ty) {
            name.clone()
        } else {
            let value = ty.format_type_name(true);
            formatted.insert(ty, value.clone());
            value
        };
        output.names.insert(formatted_name.clone(), name.clone());
        output
            .method_rvas
            .entry(formatted_name.replace("ScRep", "ScRsp"))
            .or_default()
            .push(format!("0x{rva:X}"));
        matched += 1;
        log::debug!(
            "[Proto Dumper] response handler mapped index={index} rva=0x{rva:X} type_slot=0x{slot:X} method={signature} name={name}"
        );
    }
    log::info!(
        "[Proto Dumper] response scan completed matched_handlers={matched} named_types={} instructions={decoded} no_function_body={no_body} unmatched={unmatched}",
        output.names.len()
    );
    Ok(output)
}

fn strip_prefixes<'a>(s: &'a str, prefixes: &[&str]) -> &'a str {
    for p in prefixes {
        if let Some(rest) = s.strip_prefix(p) {
            return rest;
        }
    }
    s
}

fn is_gp64_register(register: Register) -> bool {
    matches!(
        register,
        Register::RAX
            | Register::RCX
            | Register::RDX
            | Register::RBX
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
