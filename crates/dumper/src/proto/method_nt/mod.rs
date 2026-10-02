use crate::proto::get_cached_class;
use crate::proto::util;
use il2cpp::vm::{metadata_cache, value::Il2CppValue};
use reflection::method_info::MethodInfo;
use reflection::runtime_type::RuntimeType;
use std::collections::{HashMap, HashSet};

pub mod method;
mod param_nt;
mod param_table;

pub fn get_method_nt_map()
-> std::io::Result<(HashMap<String, Vec<String>>, HashMap<String, String>)> {
    let (method_map, mut proto_name_map) = param_nt::process_table(param_table::PARAM_NT_MAP);

    let method_entries = method::get_method_nt_entries();
    let method_count = method_entries.len();
    proto_name_map.extend(method_entries);

    let mut enum_map = get_enum_names();
    let mut enum_conflicts = 0;
    for (original, recovered) in super::xlua_enum::recover()? {
        if let Some(previous) = enum_map.get(&original)
            && previous != &recovered
        {
            if enum_conflicts < 12 {
                log::warn!(
                    "[Method NT] conflicting enum sources: original={original} first={previous} candidate={recovered}"
                );
            }
            enum_conflicts += 1;
            enum_map.remove(&original);
        } else {
            enum_map.insert(original, recovered);
        }
    }
    let enum_count = enum_map.len();
    log::info!("[Method NT] enum sources: recovered={enum_count} conflicts={enum_conflicts}");
    proto_name_map.extend(enum_map);

    let deobf_to_obf: HashMap<&str, &str> = proto_name_map
        .iter()
        .map(|(k, v)| (v.as_str(), k.as_str()))
        .collect();

    let param_output: Vec<String> = param_table::PARAM_NT_MAP
        .iter()
        .filter_map(|(_, _, output_key, _)| {
            deobf_to_obf
                .get(output_key)
                .map(|obf| format!("{obf} {output_key}"))
        })
        .collect();

    let method_output: Vec<String> = proto_name_map
        .iter()
        .filter(|(obf, _)| !param_output.iter().any(|l| l.starts_with(obf.as_str())))
        .map(|(obf, deobf)| format!("{obf} {deobf}"))
        .collect();

    let param_count = param_output.len();
    let output_lines: Vec<String> = param_output.into_iter().chain(method_output).collect();

    std::fs::write("./DUMP/method_nt.txt", output_lines.join("\n"))?;

    log::debug!(
        "[Method NT] total: {} | param_nt: {} | method_nt: {} | enum_nt: {}",
        proto_name_map.len(),
        param_count,
        method_count,
        enum_count,
    );

    Ok((method_map, proto_name_map))
}

pub fn dump_global_field_map() -> HashMap<String, String> {
    let mut proto_props = HashSet::<String>::new();

    for i in unsafe { il2cpp::RPG_NETWORK_PROTO_START }..unsafe { il2cpp::RPG_NETWORK_PROTO_END } {
        let Ok(runtime_type) =
            RuntimeType::from_class(metadata_cache::get_typeinfo_from_typedefindex(i))
        else {
            continue;
        };
        for prop in runtime_type.get_properties(62) {
            if let Ok(name) = prop.get_name()
                && util::is_obf(&name.as_str())
            {
                proto_props.insert(name.as_str().to_string());
            }
        }
    }

    let mut map = HashMap::<String, String>::new();
    let mut conflicts = HashSet::new();

    for i in 0..unsafe { il2cpp::MAX_TYPEDEFINDEX } {
        let Ok(runtime_type) =
            RuntimeType::from_class(metadata_cache::get_typeinfo_from_typedefindex(i))
        else {
            continue;
        };

        for prop in runtime_type.get_properties(62) {
            let prop_name = prop.get_name().unwrap().as_str();
            if !proto_props.contains(prop_name.as_ref()) || conflicts.contains(prop_name.as_ref()) {
                continue;
            }
            for (method, prefix) in [
                (prop.get_get_method(true), "get_"),
                (prop.get_set_method(true), "set_"),
            ] {
                let Ok(method) = method else { continue };
                if method.is_null() {
                    continue;
                }
                let Ok(method_name) = method.get_name() else {
                    continue;
                };
                let raw_name = method_name.as_str();
                let Some(name) = raw_name.strip_prefix(prefix).filter(|n| !util::is_obf(n)) else {
                    continue;
                };
                let name = super::output::snake_field(name);
                if !super::names::identifier(&name) {
                    continue;
                }
                if let Some(previous) = map.get(prop_name.as_ref())
                    && previous != &name
                {
                    if conflicts.len() < 12 {
                        log::warn!(
                            "[Field NT] conflicting accessor names: original={prop_name} first={previous} candidate={name}"
                        );
                    }
                    map.remove(prop_name.as_ref());
                    conflicts.insert(prop_name.to_string());
                    break;
                }
                map.insert(prop_name.to_string(), name);
            }
        }
    }
    log::info!(
        "[Field NT] accessor names: recovered={} ambiguous={}",
        map.len(),
        conflicts.len()
    );
    map
}

pub fn get_enum_names() -> HashMap<String, String> {
    let mut output = HashMap::new();

    let Some(class) = get_cached_class("XLua.ObjectTranslator.IniterAdderUnityEngineVector2")
    else {
        log::debug!(
            "[Method NT] IniterAdderUnityEngineVector2 not found; skipping enum name translation"
        );
        return output;
    };
    for method in class.get_methods() {
        let m_name = method.get_name();

        if !m_name.starts_with("Proto") {
            continue;
        }

        let Ok(mi) = MethodInfo::from_handle(method) else {
            continue;
        };

        let args = mi.get_parameters();

        let Some(first_arg) = args.first() else {
            continue;
        };

        let Ok(first_arg_type) = first_arg.get_parameter_type() else {
            continue;
        };
        let obf_name = first_arg_type.il_name();

        if !util::is_obf(&obf_name) {
            continue;
        }

        let Some(deobf_name) = m_name
            .strip_prefix("Proto")
            .and_then(|sp| sp.strip_suffix("_cast"))
        else {
            continue;
        };

        output.insert(obf_name.to_string(), deobf_name.to_string());
    }

    output
}
