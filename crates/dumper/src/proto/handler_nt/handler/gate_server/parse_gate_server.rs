use crate::{
    proto::{
        field_metadata::checked_name,
        names::identifier,
        native_flow::{Binding, Resolver},
        native_pe::Pe,
        native_tail,
        output::{ProtoItem, TypeToItemMap, snake_field},
        sync_fields::factory_binding,
        sync_scan::{self, FactoryContext},
    },
    script::memory,
};
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use windows::{
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
    core::s,
};

#[derive(Default)]
pub(in crate::proto) struct ParsedNames {
    pub message: Option<String>,
    pub fields: HashMap<u32, String>,
    pub names: HashMap<String, String>,
    pub evidence: Vec<Value>,
    pub report: Value,
}

pub(in crate::proto) fn process(items: &TypeToItemMap) -> ParsedNames {
    let mut result = ParsedNames::default();
    if let Err(error) = process_inner(items, &mut result) {
        log::warn!("[Gateway Native] stage=factory binding reason={error:#}");
        result.report["failure"] = json!(format!("{error:#}"));
    }
    result
}

fn process_inner(items: &TypeToItemMap, result: &mut ParsedNames) -> Result<()> {
    let bound = factory_binding::bind(
        "RPG.Client.ServerDispatchData",
        "_ParseServerDispatchData",
        items,
    )?;
    let item = items
        .get(&bound.proto)
        .context("bound Proto item missing")?;
    let item = item.borrow();
    let ProtoItem::Message(message) = &*item else {
        anyhow::bail!("factory parameter is not a message");
    };
    result.message = Some(message.name.clone());
    result.fields = message
        .fields
        .iter()
        .map(|field| (field.number, field.name.clone()))
        .collect();
    super::decode_gateway::set_proto_fields(result.fields.clone());
    result.report = json!({"binding":bound.report, "message":message.name, "signature":bound.signature,
        "owner_class_va":bound.owner_class.0,
        "rva":bound.rva,"body_end":bound.body_end,
        "loaded_code_hex":bound.code.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "evidence_boundary":"current native implementation; hotfix overrides are not executed"});
    let image = utils::game_assembly_slice();
    let pe = Pe::new(image, memory::readable)?;
    result.report["allocator_attempt"] = json!({});
    let allocator = super::allocator::bind(&pe, &mut result.report["allocator_attempt"])?;
    let mut context = FactoryContext {
        allocator_rva: allocator.allocator_rva,
        ..FactoryContext::default()
    };
    let literals = crate::script::STRING_LITERALS
        .get()
        .context("current string literal table unavailable")?;
    let mut decoder = Decoder::with_ip(64, &bound.code, bound.rva as u64, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        ensure!(
            !instruction.is_invalid(),
            "invalid factory instruction at 0x{:X}",
            instruction.ip()
        );
        if instruction.mnemonic() != Mnemonic::Mov
            || instruction.op0_kind() != OpKind::Register
            || instruction.op0_register().size() != 8
            || instruction.op1_kind() != OpKind::Memory
            || instruction.memory_base() != Register::RIP
            || instruction.memory_index() != Register::None
            || instruction.has_segment_prefix()
            || instruction.memory_size().size() != 8
        {
            continue;
        }
        let slot =
            usize::try_from(instruction.ip_rel_memory_address()).context("RIP slot overflow")?;
        let site = instruction.ip() as usize;
        // Section ownership, not readable pages alone, establishes slot bounds.
        if usize::try_from(pe.u64(slot)?).ok() == Some(bound.owner_class.0) {
            context.owner_class_loads.insert(site, slot);
        } else if literals.contains_key(&slot) {
            context.literal_loads.insert(site, slot);
        }
    }
    ensure!(
        !context.owner_class_loads.is_empty(),
        "no live exact owner Class load in factory"
    );
    let module = unsafe { GetModuleHandleA(s!("kernel32.dll")) }?;
    let raise_exception = unsafe { GetProcAddress(module, s!("RaiseException")) }
        .context("RaiseException binding unavailable")? as usize;
    let mut resolver = Resolver::new(pe, Binding::Loaded(raise_exception));
    let plan = resolver.plan(bound.rva, &bound.code)?;
    let tail_pe = Pe::new(image, memory::readable)?;
    let own_function = tail_pe.function(bound.rva)?;
    ensure!(
        tail_pe.bytes(own_function.unwind, 4)?[0] >> 3 == 0,
        "static factory tail proof does not support a local unwind handler"
    );
    let methods = crate::script::METHODS
        .get()
        .context("current Script methods unavailable")?;
    let tail = native_tail::exits(
        &bound.code,
        bound.rva,
        Some(own_function.start..own_function.end),
        |target| {
            methods.contains_key(&(target as u64))
                && tail_pe.function(target).is_ok_and(|function| {
                    tail_pe.executable(function.start, function.end - function.start)
                })
        },
    )?;
    let tail_exits = tail.exits.iter().map(|exit| exit.site).collect();
    result.report["tail"] = json!(tail);
    let proto_by_offset: HashMap<_, Vec<_>> =
        message
            .fields
            .iter()
            .fold(HashMap::new(), |mut map, field| {
                map.entry(field.offset).or_insert_with(Vec::new).push(field);
                map
            });
    let mut candidates = HashMap::<String, BTreeSet<String>>::new();
    let mut scans = Vec::new();
    for bytes in [1, 4, 8] {
        let scan = sync_scan::scan_factory_planned_typed(
            &bound.code,
            bound.rva,
            &plan.terminal_calls,
            &plan.exceptional_edges,
            &plan.switch_edges,
            plan.code_bytes,
            bytes,
            &tail_exits,
            &context,
        );
        scans.push(json!({"bytes":bytes,"decoded":scan.decoded,"rejected_paths":scan.rejected_paths,
            "rejected_sites":scan.rejected_sites,"copies":scan.copies.len(),"literal_calls":scan.literal_key_calls.len()}));
        for copy in scan.copies {
            let Some(fields) = proto_by_offset
                .get(&copy.proto_offset)
                .filter(|fields| fields.len() == 1)
            else {
                continue;
            };
            let field = fields[0];
            for member in bound
                .members
                .iter()
                .filter(|member| member.bytes == bytes && member.offset == copy.business_offset)
            {
                if !factory_binding::proto_field_type_matches(bound.proto, &field.name, member.ty)?
                {
                    continue;
                }
                candidates
                    .entry(field.name.clone())
                    .or_default()
                    .insert(member.name.clone());
                result.evidence.push(json!({"message":message.name,"tag":field.number,"original":field.name,
                    "recovered":member.name,"source":"typed-static-factory-copy","proto_offset":copy.proto_offset,
                    "business_offset":copy.business_offset,"native_bytes":bytes,"business_type":"RPG.Client.ServerDispatchData",
                    "business_property_type":checked_name(member.ty.get_full_name()?)?,"business_member_kind":member.member_kind,
                    "getter_rva":member.getter_rva,"setter_rva":member.setter_rva,
                    "load_rva":copy.load_rva,"store_rva":copy.store_rva,"status":"candidate"}));
            }
        }
        // This existing handler category has separate key semantics from the
        // typed owner copy route; register/CFG provenance is now checked.
        for call in scan.literal_key_calls {
            let Some(fields) = proto_by_offset
                .get(&call.proto_offset)
                .filter(|fields| fields.len() == 1)
            else {
                continue;
            };
            let field = fields[0];
            let Some(value) = literals.get(&call.literal_slot_rva) else {
                continue;
            };
            let name = snake_field(&checked_name(*value)?);
            if !identifier(&name) {
                continue;
            }
            candidates
                .entry(field.name.clone())
                .or_default()
                .insert(name.clone());
            result.evidence.push(json!({"message":message.name,"tag":field.number,"original":field.name,"recovered":name,
                "source":"native-literal-key-call","proto_offset":call.proto_offset,"load_rva":call.load_rva,
                "call_rva":call.call_rva,"target_rva":call.target_rva,"literal_slot_rva":call.literal_slot_rva,
                "native_bytes":bytes,"semantic_boundary":"existing handler string-key naming; callee semantics require separate binding",
                "status":"candidate"}));
        }
    }
    for (raw, names) in candidates {
        if names.len() == 1 {
            result.names.insert(raw, names.into_iter().next().unwrap());
        }
    }
    result.report["allocator"] = json!(allocator);
    result.report["owner_class_loads"] = json!(context.owner_class_loads);
    result.report["scans"] = json!(scans);
    log::info!(
        "[Gateway Native] complete: message={} body_bytes={} owner_loads={} candidates={} evidence={}",
        message.name,
        bound.code.len(),
        context.owner_class_loads.len(),
        result.names.len(),
        result.evidence.len()
    );
    Ok(())
}
