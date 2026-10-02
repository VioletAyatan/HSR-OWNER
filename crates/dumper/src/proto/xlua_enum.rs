//! XLua enum array getters retain semantic names. Bind them only to declared
//! enum-array TypeInfo slots compared with their System.Object argument.
use std::{
    collections::{HashMap, HashSet},
    io,
};

use anyhow::{Result, ensure};
use il2cpp::{CLASS_TABLE_VEC, GA_BASE, get_cached_class, vm::value::Il2CppValue};
use reflection::{
    attributes::MethodAttributes, method_info::MethodInfo, runtime_type::RuntimeType,
};
use utils::game_assembly_slice;

use super::{
    asm_address::module_rva,
    field_metadata::checked_name,
    names::identifier,
    rsp_scan::{FunctionTable, scan_unique},
    util::is_obf,
};
use crate::script::{TYPE_INFOS, memory};

fn candidate_name(method: &str) -> Option<&str> {
    let name = method.strip_prefix("Proto")?.strip_suffix("Get")?;
    (identifier(name) && !is_obf(name)).then_some(name)
}

fn insert_candidate(
    map: &mut HashMap<String, String>,
    blocked: &mut HashSet<String>,
    raw: &str,
    name: &str,
) {
    if blocked.contains(raw) {
        return;
    }
    if map.get(raw).is_some_and(|previous| previous != name) {
        map.remove(raw);
        blocked.insert(raw.into());
    } else {
        map.insert(raw.into(), name.into());
    }
}

fn remove_shared_names(map: &mut HashMap<String, String>, blocked: &mut HashSet<String>) {
    let mut counts = HashMap::new();
    for name in map.values() {
        *counts.entry(name.clone()).or_insert(0usize) += 1;
    }
    map.retain(|raw, name| {
        if counts[name] > 1 {
            blocked.insert(raw.clone());
            false
        } else {
            true
        }
    });
}

#[derive(Default)]
struct Diagnostics {
    methods: usize,
    bound: usize,
    ambiguous: usize,
    unbound: usize,
    metadata_errors: usize,
    samples: usize,
    context: String,
}
impl Diagnostics {
    fn failure(&mut self, reason: impl std::fmt::Display) {
        if self.samples < 12 {
            log::warn!("[XLua Enum] context={} reason={reason}", self.context);
        }
        self.samples += 1;
    }
}

fn signature(method: MethodInfo) -> Result<bool> {
    ensure!(method.0 != 0, "null reflection method");
    let attrs = method.get_attributes()?;
    ensure!(!attrs.is_null(), "null method attributes");
    if !attrs.unbox().contains(MethodAttributes::Static) {
        return Ok(false);
    }
    let parameters = method.get_parameters();
    if parameters.len() != 4 {
        return Ok(false);
    }
    for (parameter, expected) in parameters.iter().zip([
        "System.IntPtr",
        "XLua.ObjectTranslator",
        "System.Object",
        "System.Int32",
    ]) {
        ensure!(parameter.0 != 0, "null reflection parameter");
        let ty = parameter.get_parameter_type()?;
        ensure!(ty.0 != 0, "null parameter type");
        let name = checked_name(ty.get_full_name()?)?;
        if name != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn recover_inner(stats: &mut Diagnostics) -> io::Result<HashMap<String, String>> {
    let mut output = HashMap::new();
    let Some(type_infos) = TYPE_INFOS.get() else {
        stats.metadata_errors += 1;
        stats.failure("declared TypeInfo slots unavailable");
        return Ok(output);
    };
    let table = CLASS_TABLE_VEC
        .get()
        .ok_or_else(|| io::Error::other("class table unavailable"))?;
    let (start, end, maximum) = unsafe {
        (
            il2cpp::RPG_NETWORK_PROTO_START,
            il2cpp::RPG_NETWORK_PROTO_END,
            il2cpp::MAX_TYPEDEFINDEX,
        )
    };
    if start > end || end > maximum || end as usize > table.len() {
        return Err(io::Error::other(format!(
            "invalid proto metadata range: {start}..{end}, maximum={maximum} classes={}",
            table.len()
        )));
    }
    let image = game_assembly_slice();
    let base = *GA_BASE;
    let mut enums = HashMap::<usize, String>::new();
    let mut blocked_slots = HashSet::new();
    for index in start..end {
        stats.context = format!("enum metadata index={index}");
        let class = table[index as usize];
        let entry = (|| -> Result<Option<(usize, String)>> {
            memory::readable(class.0, size_of::<usize>())?;
            let ty = RuntimeType::from_class(class)?;
            ensure!(ty.0 != 0, "null enum runtime type");
            let is_enum = ty.get_isenum()?;
            ensure!(!is_enum.is_null(), "null enum flag");
            if !is_enum.unbox() {
                return Ok(None);
            }
            let raw = checked_name(ty.get_name()?)?;
            if !is_obf(&raw) || !identifier(&raw) {
                return Ok(None);
            }
            let array = class.get_array_class(1);
            ensure!(array.0 != 0, "null enum array class");
            let Some(&slot) = type_infos.get(&array) else {
                return Ok(None);
            };
            ensure!(
                slot.checked_add(size_of::<usize>())
                    .is_some_and(|end| end <= image.len()),
                "enum array slot outside module: 0x{slot:X}"
            );
            Ok(Some((slot, raw)))
        })();
        match entry {
            Ok(Some((slot, raw))) if !blocked_slots.contains(&slot) => {
                if enums.get(&slot).is_some_and(|previous| previous != &raw) {
                    enums.remove(&slot);
                    blocked_slots.insert(slot);
                    stats.ambiguous += 1;
                    stats.failure(format_args!("conflicting enum array slot 0x{slot:X}"));
                } else {
                    enums.insert(slot, raw);
                }
            }
            Ok(_) => {}
            Err(error) => {
                stats.metadata_errors += 1;
                stats.failure(format_args!("{error:#}"));
            }
        }
    }
    let Some(callbacks) = get_cached_class("XLua.StaticLuaCallbacks") else {
        stats.metadata_errors += 1;
        stats.failure("StaticLuaCallbacks unavailable");
        return Ok(output);
    };
    memory::readable(callbacks.0, size_of::<usize>()).map_err(io::Error::other)?;
    let functions = FunctionTable::from_pe(image).map_err(io::Error::other)?;
    let slots = enums.keys().copied().collect();
    let mut blocked = HashSet::new();
    for method in callbacks.get_methods() {
        stats.context = format!("callback method=0x{:X}", method.0);
        let entry = (|| -> Result<Option<(String, usize)>> {
            memory::readable(method.0, size_of::<usize>())?;
            let reflection = MethodInfo::from_handle(method)?;
            ensure!(reflection.0 != 0, "null reflection method");
            let name = checked_name(reflection.get_name()?)?;
            let Some(candidate) = candidate_name(&name) else {
                return Ok(None);
            };
            stats.methods += 1;
            stats.context = format!("callback={name} method=0x{:X}", method.0);
            ensure!(
                signature(reflection)?,
                "callback signature is not a static enum array getter"
            );
            let rva = module_rva(method.va(), base, image.len())
                .filter(|&rva| rva != 0)
                .ok_or_else(|| anyhow::anyhow!("callback address outside module"))?;
            Ok(Some((candidate.into(), rva)))
        })();
        let (name, rva) = match entry {
            Ok(Some(entry)) => entry,
            Ok(None) => continue,
            Err(error) => {
                stats.metadata_errors += 1;
                stats.failure(format_args!("{error:#}"));
                continue;
            }
        };
        let body = functions
            .containing(rva)
            .and_then(|range| Some((image.get(range)?, base.checked_add(rva)? as u64)));
        let Some((code, ip)) = body else {
            stats.unbound += 1;
            stats.failure("callback has no bounded module body or its address overflows");
            continue;
        };
        let matched = scan_unique(code, ip, base, image.len(), &slots);
        let Some(raw) = matched.slot.and_then(|slot| enums.get(&slot)) else {
            stats.unbound += 1;
            stats.failure("no unique enum-array comparison from System.Object");
            continue;
        };
        stats.bound += 1;
        let previous = output.get(raw).cloned();
        insert_candidate(&mut output, &mut blocked, raw, &name);
        if previous.is_some_and(|previous| previous != name) {
            stats.failure(format_args!(
                "conflicting candidates original={raw} candidate={name}"
            ));
        }
    }
    remove_shared_names(&mut output, &mut blocked);
    stats.ambiguous += blocked.len();
    Ok(output)
}

pub(super) fn recover() -> io::Result<HashMap<String, String>> {
    let mut stats = Diagnostics::default();
    let result = microseh::try_seh(|| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| recover_inner(&mut stats)))
    })
    .map_err(|error| {
        io::Error::other(format!(
            "XLua enum native fault context={}: {error:?}",
            stats.context
        ))
    })
    .and_then(|result| {
        result.map_err(|_| io::Error::other(format!("XLua enum panic context={}", stats.context)))
    })
    .and_then(|result| result);
    log::info!(
        "[XLua Enum] methods={} bound={} accepted={} ambiguous={} unbound={} metadata_errors={}",
        stats.methods,
        stats.bound,
        result.as_ref().map_or(0, HashMap::len),
        stats.ambiguous,
        stats.unbound,
        stats.metadata_errors
    );
    if let Err(error) = &result {
        log::error!("[XLua Enum] recovery failed: {error}");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semantic_names_require_the_complete_getter_name() {
        assert_eq!(
            candidate_name("ProtoCmdAdventureTypeGet"),
            Some("CmdAdventureType")
        );
        for name in [
            "ProtoGet",
            "ProtoAAAAAAAAAAAGet",
            "Proto9StatusGet",
            "CmdAdventureTypeGet",
            "ProtoStatusSet",
            "ProtoStatusGetExtra",
        ] {
            assert_eq!(candidate_name(name), None);
        }
    }
    #[test]
    fn conflicts_stay_blocked_and_shared_business_names_are_removed() {
        let mut map = HashMap::new();
        let mut blocked = HashSet::new();
        insert_candidate(&mut map, &mut blocked, "AAAAAAAAAAA", "Status");
        insert_candidate(&mut map, &mut blocked, "AAAAAAAAAAA", "Other");
        insert_candidate(&mut map, &mut blocked, "AAAAAAAAAAA", "Status");
        assert!(!map.contains_key("AAAAAAAAAAA"));
        insert_candidate(&mut map, &mut blocked, "BBBBBBBBBBB", "Status");
        insert_candidate(&mut map, &mut blocked, "CCCCCCCCCCC", "Status");
        insert_candidate(&mut map, &mut blocked, "DDDDDDDDDDD", "Unique");
        remove_shared_names(&mut map, &mut blocked);
        assert_eq!(
            map,
            HashMap::from([("DDDDDDDDDDD".into(), "Unique".into())])
        );
        assert_eq!(blocked.len(), 3);
    }
}
