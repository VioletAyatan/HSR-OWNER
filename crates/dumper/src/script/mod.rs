use crate::dump_progress::Progress;
use anyhow::{Context, Result, ensure};
use std::io::{BufWriter, Write};

mod init_calls;
mod memory;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use il2cpp::{
    MAX_TYPEDEFINDEX,
    vm::{
        class::Il2CppClass, method::Il2CppMethod, string::Il2CppString,
        r#type::Il2CppTypeNameFormat,
    },
};
use reflection::{method_info::MethodInfo, runtime_type::RuntimeType};
use serde::{Serialize, Serializer, ser::SerializeStruct as _};
use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};
use utils::{game_assembly_slice, scan_ga_section};

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ScriptMethod {
    pub address: usize,
    pub name: String,
    pub signature: String,
    pub type_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ScriptString {
    pub address: usize,
    pub value: Cow<'static, str>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ScriptMetadata {
    pub address: usize,
    pub name: String,
    pub signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ScriptMetadataMethod {
    pub address: usize,
    pub name: String,
    pub method_address: usize,
}

#[derive(Default)]
struct ScriptJson {
    pub script_method: HashMap<usize, ScriptMethod>,
    pub script_string: HashMap<usize, ScriptString>,
    pub script_metadata: HashMap<usize, ScriptMetadata>,
    pub script_metadata_method: HashMap<usize, ScriptMetadataMethod>,
}

impl Serialize for ScriptJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ScriptJson", 4)?;

        state.serialize_field(
            "ScriptMethod",
            &self.script_method.values().collect::<Vec<_>>(),
        )?;
        state.serialize_field(
            "ScriptString",
            &self.script_string.values().collect::<Vec<_>>(),
        )?;
        state.serialize_field(
            "ScriptMetadata",
            &self.script_metadata.values().collect::<Vec<_>>(),
        )?;
        state.serialize_field(
            "ScriptMetadataMethod",
            &self.script_metadata_method.values().collect::<Vec<_>>(),
        )?;

        state.end()
    }
}

pub static METADATA_METHODS: OnceLock<HashMap<i32, HashMap<i32, Vec<MethodInfo>>>> =
    OnceLock::new();
pub static TYPE_INFOS: OnceLock<HashMap<Il2CppClass, usize>> = OnceLock::new();
pub static METHODS: OnceLock<HashMap<u64, Il2CppMethod>> = OnceLock::new();
pub static STRING_LITERALS: OnceLock<HashMap<usize, Il2CppString>> = OnceLock::new();

pub(crate) fn is_ready() -> bool {
    METHODS.get().is_some()
        && TYPE_INFOS.get().is_some()
        && METADATA_METHODS.get().is_some()
        && STRING_LITERALS.get().is_some()
}

pub fn dump() -> Result<()> {
    let progress = Progress::start("Script")?;
    let result = dump_inner(&progress);
    progress.finish(&result);
    result
}

fn dump_inner(progress: &Progress) -> Result<()> {
    let initialized = [
        METHODS.get().is_some(),
        TYPE_INFOS.get().is_some(),
        METADATA_METHODS.get().is_some(),
        STRING_LITERALS.get().is_some(),
    ];
    if initialized.iter().all(|&ready| ready) {
        log::info!("[Script Dumper] using completed metadata cache");
        return Ok(());
    }
    ensure!(
        initialized.iter().all(|&ready| !ready),
        "incomplete Script cache; restart the game before retrying"
    );

    let mut out = ScriptJson::default();
    let mut methods = HashMap::new();
    dump_methods(&mut out, &mut methods, progress)?;

    progress.stage("locate metadata tables", 0);
    let (metadata_init_rva, table_va, offsets) =
        guarded(|| scan_address().context("metadata initializer/table signature not found"))
            .context("locate Script metadata tables")?;
    let base = *il2cpp::GA_BASE;
    let image = game_assembly_slice();
    ensure!(
        metadata_init_rva < image.len(),
        "initializer outside GameAssembly"
    );
    ensure!(
        table_va >= base && table_va - base <= image.len().saturating_sub(8),
        "metadata table root outside GameAssembly"
    );
    log::info!(
        "[Script Dumper] metadata_init_rva=0x{metadata_init_rva:X} table_rva=0x{:X} type_offset={:?} method_offset={:?} string_offset={:?}",
        table_va - base,
        offsets.get(&1),
        offsets.get(&3),
        offsets.get(&5)
    );

    progress.stage("scan metadata initialization call sites", image.len());
    let calls =
        guarded(|| init_calls::collect(image, base as u64, (base + metadata_init_rva) as u64))?;
    progress.stage("validate metadata initialization bounds", 0);
    let metadata = guarded(|| init_calls::validated_metadata(image, base, metadata_init_rva))?;
    let list_count = metadata.list_count;
    log::info!(
        "[Script Dumper] validated usage_pairs={} type_slots={} type_max_index={:?} method_slots={} method_max_index={:?} string_slots={} string_max_index={:?}",
        metadata.pair_count,
        metadata.slots.types.len(),
        metadata.slots.types.last(),
        metadata.slots.methods.len(),
        metadata.slots.methods.last(),
        metadata.slots.strings.len(),
        metadata.slots.strings.last()
    );
    ensure!(
        calls
            .indices
            .iter()
            .all(|&index| (index as usize) < list_count),
        "metadata call-site index exceeds validated usage-list count {list_count}"
    );
    log::info!(
        "[Script Dumper] verified initialization indices={} call_sites={} unresolved_calls={} max_index={}",
        calls.indices.len(),
        calls.sites,
        calls.unresolved,
        calls.indices.last().unwrap()
    );
    if calls.unresolved > 0 {
        log::info!(
            "[Script Dumper] {} initializer call arguments are dynamic/unresolved; initialization uses the validated full usage-list range",
            calls.unresolved
        );
    }
    log::info!(
        "[Script Dumper] validated initialization list_count={list_count}; no native fault probing"
    );
    progress.stage("initialize validated metadata indices", list_count);
    let init: extern "C" fn(u32) = unsafe { std::mem::transmute(base + metadata_init_rva) };
    for index in 0..list_count {
        progress.step(index, base + metadata_init_rva, "metadata_init");
        guarded(|| { init(index as u32); Ok(()) }).with_context(|| format!(
            "metadata_init index={index}; initialization stopped; restart the game before retrying after a native fault"))?;
    }

    let mut type_infos = HashMap::new();
    scan_table(
        progress,
        "type info",
        table_va,
        *offsets.get(&1).context("missing type table offset")?,
        &metadata.slots.types,
        |index, slot, raw| {
            let class = Il2CppClass(raw);
            progress.step(index, raw, "class type name");
            let name = class.byval_arg().get_name(Il2CppTypeNameFormat::IL);
            type_infos.insert(class, slot);
            out.script_metadata.insert(
                slot,
                ScriptMetadata {
                    address: slot,
                    name: format!("{name}_TypeInfo"),
                    signature: format!("{name}_c*"),
                },
            );
            Ok(())
        },
    )?;

    let mut metadata_methods: HashMap<i32, HashMap<i32, Vec<MethodInfo>>> = HashMap::new();
    scan_table(
        progress,
        "method info",
        table_va,
        *offsets.get(&3).context("missing method table offset")?,
        &metadata.slots.methods,
        |index, slot, raw| {
            let method = Il2CppMethod(raw);
            progress.step(index, raw, "il2cpp_method_get_class");
            let class = method.class();
            ensure!(class.0 != 0, "null declaring class");
            progress.step(index, raw, "RuntimeType::from_class");
            let runtime_type = RuntimeType::from_class(class)?;
            progress.step(index, raw, "MethodInfo::from_handle");
            let method_info = MethodInfo::from_handle(method)?;
            ensure!(
                method_info.0 != 0 && runtime_type.0 != 0,
                "null reflection metadata"
            );
            progress.step(index, raw, "class type name");
            let name = class.byval_arg().get_name(Il2CppTypeNameFormat::IL);
            progress.step(index, raw, "class metadata token");
            let class_token = runtime_type.get_metadata_token();
            progress.step(index, raw, "method metadata token");
            let method_token = method_info.get_metadata_token();
            metadata_methods
                .entry(class_token)
                .or_default()
                .entry(method_token)
                .or_default()
                .push(method_info);
            progress.step(index, raw, "method name and address");
            out.script_metadata_method.insert(
                slot,
                ScriptMetadataMethod {
                    address: slot,
                    name: format!("{}_{}", name, method.get_name()),
                    method_address: method.rva(),
                },
            );
            Ok(())
        },
    )?;

    let mut string_literals = HashMap::new();
    scan_table(
        progress,
        "string literals",
        table_va,
        *offsets.get(&5).context("missing string table offset")?,
        &metadata.slots.strings,
        |index, slot, raw| {
            let string = Il2CppString(raw);
            progress.step(index, raw, "read string literal");
            string_literals.insert(slot, string);
            out.script_string.insert(
                slot,
                ScriptString {
                    address: slot,
                    value: string.as_str(),
                },
            );
            Ok(())
        },
    )?;

    ensure!(!type_infos.is_empty(), "Script type-info table is empty");
    ensure!(
        !metadata_methods.is_empty(),
        "Script method-info table is empty"
    );
    progress.stage("write script-mini.json", out.script_method.len());
    let mut writer =
        BufWriter::with_capacity(64 * 1024, std::fs::File::create("./DUMP/script-mini.json")?);
    serde_json::to_writer_pretty(&mut writer, &out).context("serialize script-mini.json")?;
    writer.flush().context("flush script-mini.json")?;
    log::info!(
        "[Script Dumper] collected methods={} types={} metadata_methods={} strings={}",
        out.script_method.len(),
        out.script_metadata.len(),
        out.script_metadata_method.len(),
        out.script_string.len()
    );

    // The IPC task gate serializes dumpers. Publish only after every stage and
    // output write succeeds, so a retry cannot reuse a half-complete cache.
    METHODS
        .set(methods)
        .map_err(|_| anyhow::anyhow!("METHODS already published"))?;
    TYPE_INFOS
        .set(type_infos)
        .map_err(|_| anyhow::anyhow!("TYPE_INFOS already published"))?;
    METADATA_METHODS
        .set(metadata_methods)
        .map_err(|_| anyhow::anyhow!("METADATA_METHODS already published"))?;
    STRING_LITERALS
        .set(string_literals)
        .map_err(|_| anyhow::anyhow!("STRING_LITERALS already published"))?;
    Ok(())
}

fn guarded<T>(mut work: impl FnMut() -> Result<T>) -> Result<T> {
    // Catch Rust panics inside the SEH callback, never across its foreign ABI.
    microseh::try_seh(|| std::panic::catch_unwind(std::panic::AssertUnwindSafe(&mut work)))
        .map_err(|error| anyhow::anyhow!("native fault: {error:?}"))?
        .map_err(|payload| {
            anyhow::anyhow!(
                "panic: {}",
                payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic")
            )
        })?
}

#[cfg(test)]
mod tests {
    use super::{BTreeSet, Progress, guarded, visit_table};

    #[test]
    fn script_errors_and_panics_return_through_native_boundary() {
        let error = guarded::<()>(|| anyhow::bail!("metadata test failure")).unwrap_err();
        assert!(error.to_string().contains("metadata test failure"));
        let panic = guarded::<()>(|| panic!("metadata test panic")).unwrap_err();
        assert!(panic.to_string().contains("metadata test panic"));
    }

    #[test]
    fn table_traversal_uses_declared_slots_without_null_or_end_probing() {
        // A hole in a sparse table must not end the scan. Nonzero memory after
        // the last declared slot must never be interpreted as another object.
        let table = [101usize, 0, 202, usize::MAX];
        let progress = Progress::start("Script test").unwrap();
        let mut visited = Vec::new();
        visit_table(
            &progress,
            "test slots",
            table.as_ptr() as usize,
            0,
            &BTreeSet::from([0, 2]),
            |index, _, raw| {
                visited.push((index, raw));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(visited, [(0, 101), (2, 202)]);
    }

    #[test]
    fn declared_null_slot_is_an_error_not_a_successful_end() {
        let table = [0usize];
        let progress = Progress::start("Script test").unwrap();
        let error = visit_table(
            &progress,
            "test slots",
            table.as_ptr() as usize,
            0,
            &BTreeSet::from([0]),
            |_, _, _| panic!("null slot must not be visited"),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("declared metadata slot is null"));
    }

    #[test]
    fn accepts_a_readable_declared_slot_above_the_old_ceiling() {
        let index = 1_000_001;
        let mut table = vec![0usize; index + 1];
        table[index] = 77;
        let progress = Progress::start("Script test").unwrap();
        let mut visited = Vec::new();
        visit_table(
            &progress,
            "test slots",
            table.as_ptr() as usize,
            0,
            &BTreeSet::from([index as u32]),
            |index, _, raw| {
                visited.push((index, raw));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(visited, [(index, 77)]);
    }

    #[test]
    fn invalid_entry_address_fails_before_the_native_visitor() {
        let progress = Progress::start("Script test").unwrap();
        for (base, index, expected) in [
            (0, 0, "null table base"),
            (1, 0, "unreadable memory"),
            (usize::MAX - 3, 0, "memory range overflow"),
            (usize::MAX - 3, 1, "table address overflow"),
        ] {
            let error = visit_table(
                &progress,
                "test slots",
                base,
                0,
                &BTreeSet::from([index]),
                |_, _, _| panic!("invalid entry must not be visited"),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
    }
}

fn scan_table(
    progress: &Progress,
    name: &'static str,
    root: usize,
    offset: usize,
    slots: &BTreeSet<u32>,
    visit: impl FnMut(usize, usize, usize) -> Result<()>,
) -> Result<()> {
    progress.stage(name, slots.len());
    progress.step(0, root, "read table base");
    let table = guarded(|| unsafe {
        let container = memory::read_pointer(root)?;
        ensure!(container != 0, "null table container");
        let table = memory::read_pointer(memory::element_address(container, offset, 1)?)?;
        ensure!(table != 0, "null table base");
        Ok(table)
    })
    .with_context(|| format!("{name}: read table base"))?;
    visit_table(progress, name, table, *il2cpp::GA_BASE, slots, visit)
}

fn visit_table(
    progress: &Progress,
    name: &'static str,
    table: usize,
    game_base: usize,
    slots: &BTreeSet<u32>,
    mut visit: impl FnMut(usize, usize, usize) -> Result<()>,
) -> Result<()> {
    for &index in slots {
        let index = index as usize;
        let pointer = memory::element_address(table, index, size_of::<usize>())
            .with_context(|| format!("{name} index={index}"))?;
        progress.step(index, pointer, "read table entry");
        let raw = guarded(|| unsafe { memory::read_pointer(pointer) })
            .with_context(|| format!("{name} index={index} slot=0x{pointer:X}"))?;
        ensure!(
            raw != 0,
            "{name} index={index} slot=0x{pointer:X}: declared metadata slot is null after initialization"
        );
        let slot = pointer
            .checked_sub(game_base)
            .context("metadata slot is below GameAssembly base")?;
        guarded(|| visit(index, slot, raw)).with_context(|| progress.summary())?;
    }
    log::info!(
        "[Script Dumper] stage={name} entries={} max_index={:?} end=metadata-bound",
        slots.len(),
        slots.last()
    );
    Ok(())
}

fn dump_methods(
    out: &mut ScriptJson,
    methods: &mut HashMap<u64, Il2CppMethod>,
    progress: &Progress,
) -> Result<()> {
    let count = unsafe { MAX_TYPEDEFINDEX };
    progress.stage("method definitions", count as usize);
    let mut method_idx = 0;
    for typedef_index in 0..count {
        progress.step(typedef_index as usize, 0, "enumerate class methods");
        guarded(|| {
            let class = il2cpp::vm::metadata_cache::get_typeinfo_from_typedefindex(typedef_index);
            let name = class.byval_arg().get_name(Il2CppTypeNameFormat::IL);
            for method in class.get_methods() {
                out.script_method.insert(
                    method_idx,
                    ScriptMethod {
                        address: method.rva(),
                        name: format!("{}$${}", name, method.get_name()),
                        signature: String::new(),
                        type_signature: String::new(),
                    },
                );
                methods.insert(method.rva() as u64, method);
                method_idx += 1;
            }
            Ok(())
        })
        .with_context(|| format!("method definitions typedef_index={typedef_index}"))?;
    }
    log::info!("[Script Dumper] method definitions={method_idx}");
    Ok(())
}

fn scan_address() -> Option<(usize, usize, HashMap<usize, usize>)> {
    let Some(metadata_init_rva) = scan_ga_section("E8 ? ? ? ? C6 05 ? ? ? ? ? EB ? CC CC CC CC")
    else {
        log::debug!("[Script Dumper] Failed to find metadata_init_rva");
        return None;
    };

    let slice = game_assembly_slice();
    let mut decoder = Decoder::with_ip(
        64,
        slice.get(metadata_init_rva..slice.len().min(metadata_init_rva.checked_add(4096)?))?,
        (*il2cpp::GA_BASE + metadata_init_rva) as u64,
        DecoderOptions::NONE,
    );

    let mut instruction = Instruction::default();

    let mut jump_table_base = None;
    let mut jump_table_offset = None;
    let mut max_case = None;

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        // Find the lea instruction that loads the jump table base
        if instruction.mnemonic() == Mnemonic::Lea && instruction.op0_register() == Register::RDI {
            // This is: lea     rdi, jpt_1838E8730
            if instruction.is_ip_rel_memory_operand() {
                jump_table_base = Some(instruction.ip_rel_memory_address());
            }
        }

        // Find the max case comparison
        if instruction.mnemonic() == Mnemonic::Cmp && instruction.op0_register() == Register::EBX {
            // This is: cmp     ebx, 7
            max_case = Some(instruction.immediate32());
        }

        // Find the jump table access
        if jump_table_offset.is_none()
            && instruction.mnemonic() == Mnemonic::Movsxd
            && instruction.op0_register() == Register::RBX
            && instruction.op1_kind() == OpKind::Memory
        {
            // This is: movsxd  rbx, ds:(jpt_1838E8730 - 1838E8B94h)[rdi+rbx*4]
            jump_table_offset = Some(instruction.memory_displacement32());
        }

        // Stop when we reach the switch jump
        if instruction.mnemonic() == Mnemonic::Jmp && instruction.op0_kind() == OpKind::Register {
            break;
        }
    }

    let mut case_values = HashMap::new();

    // Now parse the jump table if we found all components
    if let (Some(base), Some(offset), Some(max)) = (jump_table_base, jump_table_offset, max_case) {
        // Calculate the actual jump table address
        // In the assembly: jpt_181488F6F - 181489260h
        // So the full address is base + offset
        if max > 32 {
            return None;
        }
        let jump_table_addr = base.wrapping_add_signed(offset as i32 as i64);

        // Read each case from the jump table
        for case_idx in 0..=max {
            // Calculate the original case value (after dec edx)
            let original_case = match case_idx {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 3,
                4 => 4,
                5 => 5,
                6 => 6,
                _ => continue,
            };

            // Skip the default case (case 2)
            if case_idx == 2 {
                continue;
            }

            // Read the 32-bit offset from the jump table
            let table_offset = (case_idx * 4) as u64;
            let offset_addr = jump_table_addr + table_offset;

            // Safety: Ensure we're reading within bounds
            if offset_addr >= *il2cpp::GA_BASE as u64
                && offset_addr.checked_add(4)? <= (*il2cpp::GA_BASE + slice.len()) as u64
            {
                let slice_offset = offset_addr as usize - *il2cpp::GA_BASE;
                let offset = i32::from_le_bytes([
                    slice[slice_offset],
                    slice[slice_offset + 1],
                    slice[slice_offset + 2],
                    slice[slice_offset + 3],
                ]);

                // Calculate target address
                let target_addr = base.wrapping_add(offset as u64);

                case_values.insert(original_case, target_addr);

                // Handle case 3 and 6 sharing the same code block
                if original_case == 3 {
                    case_values.insert(6, target_addr);
                }
            }
        }
    }

    fn get_table_and_offset(addr: u64) -> Option<(usize, usize)> {
        let rva = (addr as usize).checked_sub(*il2cpp::GA_BASE)?;
        let slice = game_assembly_slice();
        let mut decoder = Decoder::with_ip(
            64,
            slice.get(rva..slice.len().min(rva.checked_add(128)?))?,
            addr,
            DecoderOptions::NONE,
        );

        let mut instruction = Instruction::default();

        let mut table = None;
        let mut offset = None;

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if table.is_none()
                && instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Memory
            {
                table = Some(instruction.memory_displacement64() as usize);
                continue;
            }

            if table.is_some() && instruction.mnemonic() == Mnemonic::Mov {
                offset = Some(instruction.memory_displacement64() as usize);
                break;
            }
        }

        if let (Some(table), Some(offset)) = (table, offset) {
            return Some((table, offset));
        }

        None
    }

    let mut table_va = None;
    let mut offsets = HashMap::with_capacity(3);

    for (value, addr) in case_values {
        if let Some((table, offset)) = get_table_and_offset(addr) {
            if let Some(table_va) = table_va
                && table_va != table
            {
                continue;
            }
            table_va = Some(table);
            offsets.insert(value, offset);
        }
    }

    if let Some(table_va) = table_va
        && offsets.len() == 6
    {
        return Some((metadata_init_rva, table_va, offsets));
    }

    None
}
