use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use il2cpp::{get_cached_class, vm::value::Il2CppValue};
use reflection::runtime_type::RuntimeType;
use utils::game_assembly_slice;

mod config;
mod diagnostics;
mod excel_output;
mod json_output;
mod managed_error;
mod memory;
mod textmap;

use diagnostics::{checkpoint, operation};
use managed_error::invoke_error;

fn manifest_fields() -> Result<(String, String)> {
    checkpoint("Config: resolve manifest fields");
    let skill_type = runtime_type("RPG.Client.DiceCombat.DiceCombatBattleSkillCutInInfo")?;
    let row = skill_type.get_field("_Row".into(), 62)?;
    ensure!(
        !row.is_null(),
        "Config manifest: missing DiceCombatBattleSkillCutInInfo._Row"
    );
    let row_type = row.get_field_type()?;
    let type_field = row_type
        .get_fields_il2cpp()
        .into_iter()
        .find(|field| {
            field
                .get_field_type()
                .is_ok_and(|ty| ty.get_name().is_ok_and(|name| name.as_str() == "TextID"))
        })
        .context("Config manifest: cannot identify TypeName field (TextID)")?;

    let manifest_type = runtime_type("RPG.GameCore.ConfigManifest")?;
    let load_method = manifest_type
        .get_methods_il2cpp()
        .into_iter()
        .find(|method| {
            method
                .get_name()
                .is_ok_and(|name| name.as_str() == "LoadManifestItemByFileDiscovery")
        })
        .context("Config manifest: missing LoadManifestItemByFileDiscovery")?;
    let param_type = load_method
        .get_parameters()
        .first()
        .context("Config manifest: discovery method has no parameters")?
        .get_parameter_type()?;
    let ctor = param_type
        .get_methods_il2cpp()
        .into_iter()
        .find(|method| {
            let params = method.get_parameters();
            method.get_name().is_ok_and(|name| name.as_str() == ".ctor")
                && params.len() == 2
                && params[1]
                    .get_parameter_type()
                    .is_ok_and(|ty| ty.il_name() == "System.String[]")
        })
        .context("Config manifest: missing two-argument constructor with String[]")?;

    let rva = ctor.get_il2cpp_method().rva();
    ensure!(rva != 0, "Config manifest: constructor has no native body");
    let end = rva
        .checked_add(0x20)
        .context("Config manifest: invalid constructor RVA")?;
    let bytes = game_assembly_slice()
        .get(rva..end)
        .context("Config manifest: constructor RVA is outside GameAssembly")?;
    let mut decoder = Decoder::with_ip(
        64,
        bytes,
        (*il2cpp::GA_BASE + rva) as u64,
        DecoderOptions::NONE,
    );
    let mut written_offsets = Vec::new();
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.mnemonic() == Mnemonic::Ret {
            break;
        }
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && instruction.memory_base() != Register::None
        {
            written_offsets.push(instruction.memory_displacement32() as usize);
        }
    }
    let candidates = param_type
        .get_fields_il2cpp()
        .into_iter()
        .filter(|field| {
            field
                .get_field_type()
                .is_ok_and(|ty| ty.il_name() == "System.String[]")
                && !written_offsets.contains(&field.get_offset())
        })
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() == 1,
        "Config manifest: expected one path_list field, found {}",
        candidates.len()
    );
    let type_name = type_field.get_name()?.as_str().to_string();
    let path_name = candidates[0].get_name()?.as_str().to_string();
    checkpoint(format!(
        "Config: resolved TypeName={type_name}, path_list={path_name}"
    ));
    Ok((type_name, path_name))
}

fn runtime_type(name: &str) -> Result<RuntimeType> {
    RuntimeType::from_class(get_cached_class(name).with_context(|| format!("missing type {name}"))?)
        .with_context(|| format!("resolve runtime type {name}"))
}

pub fn dump() -> Result<()> {
    let session = diagnostics::Session::start()?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        operation("initialize IL2CPP runtime", || {
            crate::runtime::init_default();
            crate::runtime::attach_current_thread_to_il2cpp();
            Ok(())
        })?;
        operation("TextMap", textmap::dump)?;
        operation("ExcelOutput", excel_output::dump)?;
        operation("Config", config::dump)?;
        Ok(())
    }));
    let result = match result {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic payload");
            Err(anyhow::anyhow!(
                "Rust panic at {}: {message}",
                session.current()
            ))
        }
    };
    session.finish(&result);
    result
}

fn write_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    operation(format!("stream JSON {}", path.display()), || {
        json_output::value(path, value)?;
        diagnostics::file_written();
        Ok(())
    })
}

fn new_serializer() -> reflection::serializer::BoxedSerializer {
    let mut serializer = reflection::serializer::BoxedSerializer::default();
    serializer.set_checkpoint(Box::new(diagnostics::check_memory));
    serializer
}

fn write_table(table: RuntimeType, label: &str, path: &std::path::Path) -> Result<()> {
    operation(
        format!("stream table {label} -> {}", path.display()),
        || {
            json_output::rows(path, |emit| table_rows(table, label, emit))?;
            diagnostics::file_written();
            Ok(())
        },
    )
}

/// Shared table reader; errors must not silently truncate a successful export.
fn table_rows(
    table: RuntimeType,
    label: &str,
    emit: &mut dyn FnMut(serde_json::Value) -> Result<()>,
) -> Result<usize> {
    use il2cpp::vm::{boxed_value::BoxedBool, object::Il2CppObject};

    operation(format!("enumerate {label}"), || {
        let get_enumerator = table
            .get_methods_il2cpp()
            .into_iter()
            .find(|method| {
                let native = method.get_il2cpp_method();
                if il2cpp::api::il2cpp_method_is_instance(native)
                    || il2cpp::api::il2cpp_method_get_param_count(native) != 0
                {
                    return false;
                }
                method.get_return_type().is_ok_and(|ty| {
                    ty.get_name()
                        .is_ok_and(|name| name.as_str().contains("Enumerator"))
                })
            })
            .with_context(|| format!("{label}: no static zero-argument Enumerator method"))?;
        checkpoint(format!("{label}: invoke GetEnumerator"));
        let enumerator = get_enumerator
            .get_il2cpp_method()
            .invoke::<Il2CppObject>(Il2CppObject::NULL, &[])
            .map_err(invoke_error)?;
        ensure!(enumerator.0 != 0, "{label}: null enumerator");
        let enumerator_type = RuntimeType::from_object(enumerator)?;
        let current = enumerator_type.get_property("Current".into(), 62)?;
        ensure!(!current.is_null(), "{label}: missing Current property");
        let row_type = current.get_property_type()?;
        let is_value_type = il2cpp::api::il2cpp_class_is_valuetype(enumerator.get_class());
        let receiver = if is_value_type {
            Il2CppObject(il2cpp::api::il2cpp_object_unbox(enumerator) as usize)
        } else {
            enumerator
        };
        ensure!(receiver.0 != 0, "{label}: null enumerator receiver");
        let move_next = enumerator_type
            .find_method_il2cpp("MoveNext")
            .with_context(|| format!("{label}: missing MoveNext"))?
            .get_il2cpp_method();
        checkpoint(format!(
            "{label}: enumerator factory={} type={} value_type={is_value_type} MoveNext_rva=0x{:X}",
            get_enumerator.get_il2cpp_method().get_name(),
            enumerator_type.il_name(),
            move_next.rva()
        ));
        checkpoint(format!("{label}: initialize serializer"));
        let mut serializer = new_serializer();
        let mut count = 0;
        loop {
            diagnostics::check_memory()?;
            let index = count;
            diagnostics::row_checkpoint(label, index, "MoveNext");
            let has_next = move_next
                .invoke::<BoxedBool>(receiver, &[])
                .map_err(invoke_error)
                .with_context(|| format!("{label} row {index}: MoveNext"))?;
            ensure!(
                has_next.0 != 0,
                "{label} row {index}: MoveNext returned null"
            );
            if !has_next.unbox() {
                break;
            }
            diagnostics::row_checkpoint(label, index, "Current");
            let value = current
                .get_value(enumerator)
                .with_context(|| format!("{label} row {index}: Current"))?;
            diagnostics::row_checkpoint(label, index, "serialize");
            emit(
                serializer
                    .serialize(row_type, value)
                    .with_context(|| format!("{label} row {index}: serialize"))?,
            )?;
            count += 1;
        }
        checkpoint(format!("{label}: enumerated {count} rows"));
        if count == 0 {
            log::warn!("[Resources] {label}: empty runtime table");
        }
        Ok(count)
    })
}
