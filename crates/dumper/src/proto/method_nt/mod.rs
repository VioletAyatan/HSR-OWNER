use crate::proto::get_cached_class;
use crate::proto::util;
use crate::script::memory;
use il2cpp::vm::{class::Il2CppClass, metadata_cache, value::Il2CppValue};
use reflection::method_info::MethodInfo;
use reflection::runtime_type::RuntimeType;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use utils::game_assembly_slice;

const GLOBAL_FIELD_EVIDENCE_PATH: &str = "./DUMP/proto-global-field-name-evidence.json";
const GLOBAL_FIELD_SOURCE: &str = "same-PropertyInfo accessor global alias";

#[derive(Serialize)]
struct GlobalFieldEvidence {
    source: &'static str,
    proto_raw_names: usize,
    accessor_candidates: Vec<GlobalAccessorEvidence>,
    summary: GlobalFieldSummary,
}

#[derive(Serialize)]
struct GlobalAccessorEvidence {
    original: String,
    candidate: String,
    raw_accessor_name: String,
    accessor_kind: &'static str,
    property_handle: usize,
    enumerated_typedef_index: u32,
    enumerated_type_name: Option<String>,
    actual_accessor_declaring_type: Option<String>,
    accessor_handle: usize,
    native_method_handle: Option<usize>,
    native_rva: Option<usize>,
    inherited: Option<bool>,
    final_global_status: &'static str,
    provenance_errors: Vec<String>,
}

#[derive(Serialize)]
struct GlobalFieldSummary {
    type_metadata_errors: usize,
    property_name_errors: usize,
    accessor_name_errors: usize,
    provenance_errors: usize,
    accessor_candidates: usize,
    recovered: usize,
    ambiguous: usize,
}

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

pub fn dump_global_field_map() -> std::io::Result<HashMap<String, String>> {
    log::info!("[Field NT] stage=collect-proto-raw-property-names");
    let mut proto_props = HashSet::<String>::new();
    let mut type_metadata_errors = 0;
    let mut property_name_errors = 0;
    let mut accessor_name_errors = 0;
    let mut accessor_lookup_errors = 0;
    let mut provenance_errors = 0;
    let mut logged_name_errors = 0;
    let mut logged_provenance_errors = 0;
    let mut logged_metadata_errors = 0;

    for i in unsafe { il2cpp::RPG_NETWORK_PROTO_START }..unsafe { il2cpp::RPG_NETWORK_PROTO_END } {
        let runtime_type = match RuntimeType::from_class(
            metadata_cache::get_typeinfo_from_typedefindex(i),
        ) {
            Ok(runtime_type) => runtime_type,
            Err(error) => {
                type_metadata_errors += 1;
                if logged_metadata_errors < 12 {
                    log::warn!(
                        "[Field NT] proto RuntimeType metadata failed: typedef_index={i} error={error:#}"
                    );
                    logged_metadata_errors += 1;
                }
                continue;
            }
        };
        for prop in runtime_type.get_properties(62) {
            match prop.get_name() {
                Ok(name) if util::is_obf(&name.as_str()) => {
                    proto_props.insert(name.as_str().to_string());
                }
                Ok(_) => {}
                Err(error) => {
                    property_name_errors += 1;
                    if logged_name_errors < 12 {
                        log::warn!(
                            "[Field NT] proto property-name binding failed: typedef_index={i} property=0x{:X} error={error:#}",
                            prop.0
                        );
                        logged_name_errors += 1;
                    }
                }
            }
        }
    }

    let mut map = HashMap::<String, String>::new();
    let mut conflicts = HashSet::new();
    let mut evidence_rows = Vec::<GlobalAccessorEvidence>::new();
    let mut enumerated_names = HashMap::<u32, Option<String>>::new();
    let mut declaring_names = HashMap::<RuntimeType, Option<String>>::new();
    let game_assembly_len = game_assembly_slice().len();
    let game_assembly_base = *il2cpp::GA_BASE;
    log::info!(
        "[Field NT] stage=scan-global-accessor-aliases proto_raw_names={}",
        proto_props.len()
    );

    for i in 0..unsafe { il2cpp::MAX_TYPEDEFINDEX } {
        let runtime_type = match RuntimeType::from_class(
            metadata_cache::get_typeinfo_from_typedefindex(i),
        ) {
            Ok(runtime_type) => runtime_type,
            Err(error) => {
                type_metadata_errors += 1;
                if logged_metadata_errors < 12 {
                    log::warn!(
                        "[Field NT] RuntimeType metadata failed: typedef_index={i} error={error:#}"
                    );
                    logged_metadata_errors += 1;
                }
                continue;
            }
        };

        for prop in runtime_type.get_properties(62) {
            let prop_name = match prop.get_name() {
                Ok(name) => name.as_str().to_string(),
                Err(error) => {
                    property_name_errors += 1;
                    if logged_name_errors < 12 {
                        log::warn!(
                            "[Field NT] property-name binding failed: typedef_index={i} type=0x{:X} property=0x{:X} error={error:#}",
                            runtime_type.0,
                            prop.0
                        );
                        logged_name_errors += 1;
                    }
                    continue;
                }
            };
            if !proto_props.contains(&prop_name) {
                continue;
            }
            for (method_result, prefix, accessor_kind) in [
                (prop.get_get_method(true), "get_", "getter"),
                (prop.get_set_method(true), "set_", "setter"),
            ] {
                let method = match method_result {
                    Ok(method) => method,
                    Err(error) => {
                        accessor_lookup_errors += 1;
                        if logged_name_errors < 12 {
                            log::warn!(
                                "[Field NT] accessor lookup failed: original={prop_name} typedef_index={i} property=0x{:X} accessor_kind={accessor_kind} error={error:#}",
                                prop.0
                            );
                            logged_name_errors += 1;
                        }
                        continue;
                    }
                };
                if method.is_null() {
                    continue;
                }
                let method_name = match method.get_name() {
                    Ok(name) => name.as_str().to_string(),
                    Err(error) => {
                        accessor_name_errors += 1;
                        if logged_name_errors < 12 {
                            log::warn!(
                                "[Field NT] accessor-name binding failed: original={prop_name} typedef_index={i} property=0x{:X} accessor_kind={accessor_kind} method=0x{:X} error={error:#}",
                                prop.0,
                                method.0
                            );
                            logged_name_errors += 1;
                        }
                        continue;
                    }
                };
                let Some(name) = method_name
                    .strip_prefix(prefix)
                    .filter(|n| !util::is_obf(n))
                else {
                    continue;
                };
                let name = super::output::snake_field(name);
                if !super::names::identifier(&name) {
                    continue;
                }

                observe_global_candidate(&mut map, &mut conflicts, &prop_name, &name);

                let enumerated_type_name = enumerated_names
                    .entry(i)
                    .or_insert_with(|| {
                        runtime_type
                            .get_full_name()
                            .ok()
                            .map(|s| s.as_str().to_string())
                    })
                    .clone();
                let mut row_errors = Vec::new();
                if enumerated_type_name.is_none() {
                    row_errors.push("failed to read enumerating RuntimeType full name".to_owned());
                }
                let actual_declaring_type = match method.get_declaring_type() {
                    Ok(declaring_type) if !declaring_type.is_null() => {
                        let declaring_name = declaring_names
                            .entry(declaring_type)
                            .or_insert_with(|| {
                                declaring_type
                                    .get_full_name()
                                    .ok()
                                    .map(|s| s.as_str().to_string())
                            })
                            .clone();
                        if declaring_name.is_none() {
                            row_errors.push(
                                "failed to read actual accessor DeclaringType full name".to_owned(),
                            );
                        }
                        Some((declaring_type, declaring_name))
                    }
                    Ok(_) => {
                        row_errors.push("accessor DeclaringType is null".to_owned());
                        None
                    }
                    Err(error) => {
                        row_errors
                            .push(format!("failed to query accessor DeclaringType: {error:#}"));
                        None
                    }
                };
                let actual_accessor_declaring_type = actual_declaring_type
                    .as_ref()
                    .and_then(|(_, name)| name.clone());
                let inherited = actual_declaring_type
                    .as_ref()
                    .map(|(declaring_type, _)| *declaring_type != runtime_type);
                let (native_method_handle, native_rva) = match checked_native_method_rva(
                    method,
                    game_assembly_base,
                    game_assembly_len,
                ) {
                    Ok((handle, rva)) => (Some(handle), Some(rva)),
                    Err(error) => {
                        row_errors.push(format!("native accessor identity/RVA failed: {error:#}"));
                        (None, None)
                    }
                };
                provenance_errors += row_errors.len();
                for error in &row_errors {
                    if logged_provenance_errors < 12 {
                        log::warn!(
                            "[Field NT] accessor provenance failed: original={prop_name} candidate={name} typedef_index={i} property=0x{:X} accessor_kind={accessor_kind} method=0x{:X} reason={error}",
                            prop.0,
                            method.0
                        );
                        logged_provenance_errors += 1;
                    }
                }
                evidence_rows.push(GlobalAccessorEvidence {
                    original: prop_name.clone(),
                    candidate: name,
                    raw_accessor_name: method_name,
                    accessor_kind,
                    property_handle: prop.0,
                    enumerated_typedef_index: i,
                    enumerated_type_name,
                    actual_accessor_declaring_type,
                    accessor_handle: method.0,
                    native_method_handle,
                    native_rva,
                    inherited,
                    final_global_status: "pending",
                    provenance_errors: row_errors,
                });
            }
        }
    }

    let mut property_consensus = HashMap::<(String, String), HashSet<(u32, usize)>>::new();
    for row in &evidence_rows {
        property_consensus
            .entry((row.original.clone(), row.candidate.clone()))
            .or_default()
            .insert((row.enumerated_typedef_index, row.property_handle));
    }
    for row in &mut evidence_rows {
        row.final_global_status = global_candidate_status(
            &map,
            &conflicts,
            &row.original,
            &row.candidate,
            property_consensus
                .get(&(row.original.clone(), row.candidate.clone()))
                .map(HashSet::len)
                .unwrap_or_default(),
        );
    }
    let mut logged_conflicts = 0;
    for row in &evidence_rows {
        if row.final_global_status == "ambiguous-candidate-conflict" && logged_conflicts < 12 {
            log::warn!(
                "[Field NT] global accessor-name conflict: original={} candidate={} accessor={} typedef_index={} type={} declaring_type={}",
                row.original,
                row.candidate,
                row.raw_accessor_name,
                row.enumerated_typedef_index,
                row.enumerated_type_name
                    .as_deref()
                    .unwrap_or("<unavailable>"),
                row.actual_accessor_declaring_type
                    .as_deref()
                    .unwrap_or("<unavailable>")
            );
            logged_conflicts += 1;
        }
    }

    let accessor_candidates = evidence_rows.len();
    let summary = GlobalFieldSummary {
        type_metadata_errors,
        property_name_errors,
        accessor_name_errors: accessor_name_errors + accessor_lookup_errors,
        provenance_errors,
        accessor_candidates,
        recovered: map.len(),
        ambiguous: conflicts.len(),
    };
    let evidence = GlobalFieldEvidence {
        source: GLOBAL_FIELD_SOURCE,
        proto_raw_names: proto_props.len(),
        accessor_candidates: evidence_rows,
        summary,
    };
    log::info!("[Field NT] stage=write-global-accessor-provenance");
    let serialized = serde_json::to_vec_pretty(&evidence).map_err(std::io::Error::other)?;
    std::fs::write(GLOBAL_FIELD_EVIDENCE_PATH, serialized)?;

    log::info!(
        "[Field NT] accessor names: recovered={} ambiguous={} candidates={} name_errors={} provenance_errors={} metadata_errors={} evidence={}",
        map.len(),
        conflicts.len(),
        accessor_candidates,
        property_name_errors + accessor_name_errors + accessor_lookup_errors,
        provenance_errors,
        type_metadata_errors,
        GLOBAL_FIELD_EVIDENCE_PATH
    );
    Ok(map)
}

fn observe_global_candidate(
    map: &mut HashMap<String, String>,
    conflicts: &mut HashSet<String>,
    original: &str,
    candidate: &str,
) {
    if conflicts.contains(original) {
        return;
    }
    if map
        .get(original)
        .is_some_and(|previous| previous != candidate)
    {
        map.remove(original);
        conflicts.insert(original.to_owned());
    } else {
        map.insert(original.to_owned(), candidate.to_owned());
    }
}

fn checked_native_method_rva(
    method: MethodInfo,
    game_assembly_base: usize,
    game_assembly_len: usize,
) -> anyhow::Result<(usize, usize)> {
    anyhow::ensure!(!method.is_null(), "null reflection accessor method");
    memory::readable(method.0, 24)?;
    let handle = method.get_il2cpp_method();
    anyhow::ensure!(handle.0 != 0, "reflection method has a null native handle");
    memory::readable(handle.0, 16)?;
    let class = handle.class();
    anyhow::ensure!(class.0 != 0, "native accessor has a null declaring class");
    memory::readable(class.0, size_of::<Il2CppClass>())?;
    let va = handle.va();
    let rva = super::asm_address::module_rva(va, game_assembly_base, game_assembly_len)
        .ok_or_else(|| {
            anyhow::anyhow!("accessor VA 0x{va:X} is outside current GameAssembly module")
        })?;
    Ok((handle.0, rva))
}

fn global_candidate_status(
    map: &HashMap<String, String>,
    conflicts: &HashSet<String>,
    original: &str,
    candidate: &str,
    consensus: usize,
) -> &'static str {
    if conflicts.contains(original) {
        "ambiguous-candidate-conflict"
    } else if map.get(original).is_some_and(|mapped| mapped == candidate) {
        if consensus > 1 {
            "mapped-consensus"
        } else {
            "mapped"
        }
    } else {
        "not-global-result"
    }
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

#[cfg(test)]
mod global_field_map_tests {
    use super::{checked_native_method_rva, global_candidate_status, observe_global_candidate};
    use reflection::method_info::MethodInfo;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn identical_owner_candidates_fold_without_changing_mapping() {
        let mut map = HashMap::new();
        let mut conflicts = HashSet::new();
        observe_global_candidate(&mut map, &mut conflicts, "ABCDABCDEFGHI", "score");
        observe_global_candidate(&mut map, &mut conflicts, "ABCDABCDEFGHI", "score");

        assert_eq!(map.get("ABCDABCDEFGHI").map(String::as_str), Some("score"));
        assert!(!conflicts.contains("ABCDABCDEFGHI"));
        assert_eq!(
            global_candidate_status(&map, &conflicts, "ABCDABCDEFGHI", "score", 2),
            "mapped-consensus"
        );
    }

    #[test]
    fn conflicting_owner_candidates_remove_global_mapping() {
        let mut map = HashMap::new();
        let mut conflicts = HashSet::new();
        observe_global_candidate(&mut map, &mut conflicts, "ABCDABCDEFGHI", "score");
        observe_global_candidate(&mut map, &mut conflicts, "ABCDABCDEFGHI", "points");
        observe_global_candidate(&mut map, &mut conflicts, "ABCDABCDEFGHI", "score");

        assert!(!map.contains_key("ABCDABCDEFGHI"));
        assert!(conflicts.contains("ABCDABCDEFGHI"));
        assert_eq!(
            global_candidate_status(&map, &conflicts, "ABCDABCDEFGHI", "score", 2),
            "ambiguous-candidate-conflict"
        );
        assert_eq!(
            global_candidate_status(&map, &conflicts, "ABCDABCDEFGHI", "points", 1),
            "ambiguous-candidate-conflict"
        );
    }

    #[test]
    fn null_reflection_method_fails_before_calling_reflection_apis() {
        let error = checked_native_method_rva(MethodInfo(0), 0, 0).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("null reflection accessor method")
        );
    }
}
