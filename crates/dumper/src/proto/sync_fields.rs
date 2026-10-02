//! Name an unknown wire field only through a direct native instance copy into an
//! own, typed business property with independently agreeing getter and setter.
use std::{
    collections::{HashMap, HashSet},
    io,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use il2cpp::{
    FUNCTIONS_TABLE_REFLECTION, GA_BASE,
    vm::{array::Il2CppArray, boxed_value::BoxedBool, object::Il2CppObject},
};
use reflection::{
    attributes::MethodAttributes, method_info::MethodInfo, parameter_info::RuntimeParameterInfo,
    property_info::PropertyInfo, runtime_type::RuntimeType,
};
use serde::Serialize;
use windows::{
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
    core::s,
};

use super::{
    asm_address::module_rva,
    cache::{CachedType, TypeCache},
    field_metadata::checked_name,
    names::{ScopedFieldNames, field_name_key, identifier},
    native_flow::{Binding, Plan, Resolver, Statistics},
    native_pe::Pe,
    output::{ProtoItem, TypeToItemMap, snake_field},
    rsp_scan::FunctionTable,
    sync_scan::{self, Mode},
    util::is_obf,
};
use crate::{dump_progress::Progress, script::memory};

#[path = "sync_declared_fields.rs"]
mod declared_fields;

#[derive(Clone)]
struct Accessor {
    name: String,
    kind: String,
    ty: RuntimeType,
    bytes: usize,
    offset: u32,
    getter_rva: usize,
    setter_rva: usize,
    member_kind: &'static str,
}

#[derive(Serialize)]
struct Evidence {
    message: String,
    tag: u32,
    original: String,
    recovered: String,
    proto_offset: u32,
    business_type: String,
    business_offset: u32,
    business_property_type: String,
    business_member_kind: &'static str,
    kind: String,
    native_bytes: usize,
    sync_method: String,
    sync_return_type: String,
    return_abi: &'static str,
    sync_rva: usize,
    getter_rva: usize,
    setter_rva: usize,
    load_rva: usize,
    store_rva: usize,
    status: &'static str,
    final_name: Option<String>,
}

#[derive(Default, Serialize)]
pub(super) struct SyncFields {
    methods_considered: usize,
    sync_methods: usize,
    specialized_sync_methods: usize,
    other_proto_methods: usize,
    reference_return_methods: usize,
    unsupported_return_types: usize,
    owners: usize,
    typed_accessors: usize,
    declared_fields: usize,
    copies: usize,
    conflicts: usize,
    unbound_accessors: usize,
    metadata_errors: usize,
    control_flow_errors: usize,
    control_flow: Statistics,
    reflection_array_shapes: HashMap<String, usize>,
    other_reflection_arrays: usize,
    evidence: Vec<Evidence>,
    #[serde(skip)]
    pub names: ScopedFieldNames,
    #[serde(skip)]
    blocked: HashSet<(String, u32)>,
    #[serde(skip)]
    preserved_existing: HashSet<(String, u32)>,
    #[serde(skip)]
    rejected_existing_collisions: HashSet<(String, u32)>,
    #[serde(skip)]
    context: String,
}

fn sync_method_name(name: &str) -> bool {
    // Names only select candidates. Instance/parameter/property metadata and
    // the complete native copy proof below still decide whether to accept.
    name == "Sync"
        || name
            .strip_prefix("Sync")
            .and_then(|suffix| suffix.as_bytes().first())
            .is_some_and(u8::is_ascii_uppercase)
}

fn sync_signature(signature: &str) -> bool {
    signature
        .rsplit_once("::")
        .and_then(|(_, method)| method.split_once('('))
        .is_some_and(|(name, _)| sync_method_name(name))
}

fn proto_signature(signature: &str, message_names: &HashSet<String>) -> bool {
    let Some((_, method)) = signature.rsplit_once("::") else {
        return false;
    };
    let Some((name, arguments)) = method.split_once('(') else {
        return false;
    };
    // Constructor reflection uses another runtime class. Ordinary methods
    // still require the actual instance, parameter and return metadata below.
    !matches!(name, ".ctor" | ".cctor")
        && arguments.strip_suffix(')').is_some_and(|argument| {
            message_names.contains(argument)
                || argument
                    .strip_prefix("Proto.")
                    .is_some_and(|name| message_names.contains(name))
        })
}

fn sync_return_abi(name: &str, cached: Option<&CachedType>) -> bool {
    // The scanner models RCX=this, RDX=Proto. An aggregate return can insert
    // a hidden first argument and shift both, so only known scalar/void
    // returns establish this calling convention.
    name == "System.Void"
        || matches!(
            cached,
            Some(
                CachedType::Boolean
                    | CachedType::Byte
                    | CachedType::SByte
                    | CachedType::UInt16
                    | CachedType::Int16
                    | CachedType::UInt32
                    | CachedType::Int32
                    | CachedType::UInt64
                    | CachedType::Int64
                    | CachedType::Single
                    | CachedType::Double
            )
        )
}

fn reflection_bool(value: BoxedBool) -> Result<bool> {
    memory::readable(value.0, 17)?;
    let object = Il2CppObject(value.0);
    ensure!(
        object.get_class()
            == il2cpp::get_cached_class("System.Boolean").context("Boolean class unavailable")?,
        "unexpected reflection boolean class"
    );
    ensure!(
        il2cpp::api::il2cpp_object_get_size(object) >= 17,
        "reflection boolean allocation too small"
    );
    let byte = unsafe { ((value.0 + 16) as *const u8).read() };
    ensure!(byte <= 1, "invalid reflection boolean value");
    Ok(byte != 0)
}

fn return_abi(
    method: MethodInfo,
    ty: RuntimeType,
    name: &str,
    cache: &TypeCache,
) -> Result<Option<&'static str>> {
    if sync_return_abi(name, cache.type_map.get(&ty)) {
        return Ok(Some(if name == "System.Void" {
            "void"
        } else {
            "scalar"
        }));
    }
    // A closed managed reference returns one pointer in RAX; it adds no hidden
    // aggregate buffer before RCX=this/RDX=Proto. Do not infer this from names.
    if reflection_bool(method.get_is_generic_method()?)? || !managed_reference(ty)? {
        return Ok(None);
    }
    Ok(Some("managed-reference"))
}

fn managed_reference(ty: RuntimeType) -> Result<bool> {
    memory::readable(ty.0, 24)?;
    Ok(!(reflection_bool(ty.get_isvaluetype()?)?
        || reflection_bool(ty.get_isbyref()?)?
        || reflection_bool(ty.get_ispointer()?)?
        || reflection_bool(ty.get_is_generic_parameter()?)?
        || reflection_bool(ty.get_is_generic_type_definition()?)?
        || reflection_bool(ty.contains_generic_parameters()?)?))
}

fn instance(method: MethodInfo, owner: RuntimeType) -> Result<bool> {
    ensure!(method.0 != 0, "null reflection method");
    memory::readable(method.0, 24)?;
    let attrs = method.get_attributes()?;
    memory::readable(attrs.0, 20)?;
    Ok(!attrs.unbox().contains(MethodAttributes::Static) && method.get_declaring_type()? == owner)
}

fn kind(ty: RuntimeType, cache: &TypeCache) -> Option<&'static str> {
    match cache.type_map.get(&ty) {
        Some(CachedType::Int32) => Some("int32"),
        Some(CachedType::UInt32) => Some("uint32"),
        Some(CachedType::Boolean) => Some("bool"),
        Some(CachedType::Int64) => Some("int64"),
        Some(CachedType::UInt64) => Some("uint64"),
        _ => None,
    }
}

fn scalar_bytes(kind: &str) -> Option<usize> {
    match kind {
        "bool" => Some(1),
        "int32" | "uint32" | "sint32" | "fixed32" | "sfixed32" => Some(4),
        "int64" | "uint64" | "sint64" | "fixed64" | "sfixed64" => Some(8),
        _ => None,
    }
}

fn accessor_kind(ty: RuntimeType, cache: &TypeCache) -> Result<Option<(String, usize)>> {
    if let Some(kind) = kind(ty, cache) {
        return Ok(Some((
            kind.into(),
            scalar_bytes(kind).context("scalar width")?,
        )));
    }
    memory::readable(ty.0, 24)?;
    if reflection_bool(ty.get_isenum()?)? {
        let value = ty.get_field("value__".into(), 54)?;
        memory::readable(value.0, 32)?;
        ensure!(
            value.get_declaringtype()? == ty && checked_name(value.get_name()?)? == "value__",
            "invalid enum underlying field"
        );
        return Ok(matches!(
            cache.type_map.get(&value.get_field_type()?),
            Some(CachedType::Int32 | CachedType::UInt32)
        )
        .then(|| ("enum".into(), 4)));
    }
    Ok(managed_reference(ty)?.then(|| ("reference".into(), 8)))
}

fn wire_bytes(kind: &str, enum_names: &HashSet<String>) -> Option<usize> {
    scalar_bytes(kind).or_else(|| {
        if enum_names.contains(kind) {
            Some(4)
        } else if !kind.is_empty() && !matches!(kind, "float" | "double") {
            Some(8)
        } else {
            None
        }
    })
}

fn same_proto_property(proto: RuntimeType, name: &str, ty: RuntimeType) -> Result<bool> {
    let property = proto.get_property(name.into(), 54)?;
    memory::readable(property.0, 24)?;
    if checked_name(property.get_name()?)? != name || property.get_property_type()? != ty {
        return Ok(false);
    }
    let getter = property.get_get_method(true)?;
    Ok(getter.0 != 0 && instance(getter, proto)? && getter.get_return_type()? == ty)
}

fn compatible_kind(property: &str, wire: &str) -> bool {
    property == wire
        || matches!(
            (property, wire),
            ("int32", "sint32" | "sfixed32")
                | ("uint32", "fixed32")
                | ("int64", "sint64" | "sfixed64")
                | ("uint64", "fixed64")
        )
}

fn reference_body(
    address: usize,
    length: usize,
    allocation: usize,
) -> Result<std::ops::Range<usize>> {
    let bytes = length
        .checked_mul(size_of::<usize>())
        .context("array size overflow")?;
    let total = 32usize.checked_add(bytes).context("array size overflow")?;
    ensure!(total <= allocation, "array body exceeds managed allocation");
    let start = address.checked_add(32).context("array address overflow")?;
    let end = start.checked_add(bytes).context("array address overflow")?;
    Ok(start..end)
}

fn references<T: From<usize>>(
    array: Il2CppArray,
    element: &str,
    out: &mut SyncFields,
) -> Result<Vec<T>> {
    memory::readable(array.0, 32)?;
    let expected =
        il2cpp::get_cached_class(element).context("reflection element class unavailable")?;
    let class = array.class();
    memory::readable(class.0, 16)?;
    ensure!(
        il2cpp::api::il2cpp_class_get_rank(class) == 1 && array.bounds() == 0,
        "reflection array is not an SZArray"
    );
    ensure!(
        il2cpp::api::il2cpp_class_array_element_size(class) == size_of::<usize>() as i32,
        "reflection array is not a reference array"
    );
    let array_type = RuntimeType::from_class(class)?;
    let actual_element = array_type.get_element_type()?;
    ensure!(
        actual_element.0 != 0,
        "reflection array has no element type"
    );
    memory::readable(actual_element.0, 24)?;
    let actual_class = actual_element.get_il2cpp_type().get_class();
    memory::readable(actual_class.0, 16)?;
    ensure!(
        class == actual_class.get_array_class(1),
        "reflection array class is not the element's SZArray"
    );
    let expected = RuntimeType::from_class(expected)?;
    let compatible = expected.is_assignable_from(actual_element)?;
    memory::readable(compatible.0, 17)?;
    let actual_name = checked_name(array_type.get_full_name()?)?;
    let shape = format!("{element} <- {actual_name}");
    if let Some(count) = out.reflection_array_shapes.get_mut(&shape) {
        *count += 1;
    } else if out.reflection_array_shapes.len() < 12 {
        out.reflection_array_shapes.insert(shape, 1);
    } else {
        out.other_reflection_arrays += 1;
    }
    // GetParameters can return a derived ParameterInfo[] even for an empty
    // method signature. Prove its declared element type, not merely its items.
    ensure!(
        compatible.unbox(),
        "unexpected reflection array type: expected={element}[] actual={actual_name}"
    );
    let length = array.len();
    let allocation = il2cpp::api::il2cpp_object_get_size(Il2CppObject(array.0)) as usize;
    let body = reference_body(array.0, length, allocation)?;
    memory::readable(body.start, body.len())?;
    let mut output = Vec::with_capacity(length);
    for index in 0..length {
        let address = body
            .start
            .checked_add(
                index
                    .checked_mul(size_of::<usize>())
                    .context("array index overflow")?,
            )
            .context("array address overflow")?;
        let value = unsafe { (address as *const usize).read_unaligned() };
        memory::readable(value, 16)?;
        let ty = RuntimeType::from_class(Il2CppObject(value).get_class())?;
        let compatible = actual_element.is_assignable_from(ty)?;
        memory::readable(compatible.0, 17)?;
        ensure!(compatible.unbox(), "unexpected reflection array element");
        output.push(T::from(value));
    }
    Ok(output)
}

fn parameters(method: MethodInfo, out: &mut SyncFields) -> Result<Vec<RuntimeParameterInfo>> {
    references(
        method.get_parameters_array()?,
        "System.Reflection.ParameterInfo",
        out,
    )
}

struct Bounds<'a> {
    functions: FunctionTable<'a>,
    entries: Vec<usize>,
    executable: Vec<std::ops::Range<usize>>,
}

fn executable_ranges(image: &[u8]) -> Result<Vec<std::ops::Range<usize>>> {
    fn bytes<const N: usize>(image: &[u8], offset: usize) -> Result<[u8; N]> {
        image
            .get(offset..offset.checked_add(N).context("PE offset overflow")?)
            .context("truncated PE section metadata")?
            .try_into()
            .map_err(Into::into)
    }
    let pe = u32::from_le_bytes(bytes(image, 0x3c)?) as usize;
    let count =
        u16::from_le_bytes(bytes(image, pe.checked_add(6).context("PE overflow")?)?) as usize;
    let optional_size =
        u16::from_le_bytes(bytes(image, pe.checked_add(20).context("PE overflow")?)?) as usize;
    let sections = pe
        .checked_add(24)
        .and_then(|n| n.checked_add(optional_size))
        .context("PE overflow")?;
    let mut out = Vec::new();
    for index in 0..count {
        let section = sections
            .checked_add(index.checked_mul(40).context("PE section overflow")?)
            .context("PE section overflow")?;
        let record: [u8; 40] = bytes(image, section)?;
        if u32::from_le_bytes(record[36..40].try_into()?) & 0x2000_0000 == 0 {
            continue;
        }
        let start = u32::from_le_bytes(record[12..16].try_into()?) as usize;
        let size = u32::from_le_bytes(record[8..12].try_into()?)
            .max(u32::from_le_bytes(record[16..20].try_into()?)) as usize;
        let end = start
            .checked_add(size)
            .context("PE executable section overflow")?;
        ensure!(
            start < end && end <= image.len(),
            "executable section outside image"
        );
        out.push(start..end);
    }
    ensure!(!out.is_empty(), "no executable sections");
    Ok(out)
}

fn body<'a>(method: MethodInfo, image: &'a [u8], bounds: &Bounds<'_>) -> Result<(usize, &'a [u8])> {
    let handle = method.get_il2cpp_method();
    memory::readable(handle.0, 16)?;
    let rva = module_rva(handle.va(), *GA_BASE, image.len())
        .filter(|rva| *rva != 0)
        .context("method address outside GameAssembly")?;
    let executable = bounds
        .executable
        .iter()
        .find(|range| range.contains(&rva))
        .context("method is outside executable sections")?;
    ensure!(
        bounds.entries.binary_search(&rva).is_ok(),
        "method entry is absent from current metadata"
    );
    // Leaf accessors have no unwind record. Their own declared entry, the next
    // current metadata entry and executable section establish a safe upper
    // bound; the scanner stops paths at returns and never enters a neighbour.
    let next = bounds
        .entries
        .get(bounds.entries.partition_point(|entry| *entry <= rva))
        .copied()
        .unwrap_or(executable.end)
        .min(executable.end);
    let end = bounds
        .functions
        .containing(rva)
        .map_or(next, |range| range.end.min(next));
    ensure!(rva < end, "empty method body bound");
    let body = image
        .get(rva..end)
        .context("method body outside GameAssembly")?;
    memory::readable(body.as_ptr() as usize, body.len())?;
    Ok((rva, body))
}

impl SyncFields {
    fn failure(&mut self, reason: impl std::fmt::Display) {
        if self.metadata_errors < 12 {
            log::warn!("[Sync Fields] context={} reason={reason}", self.context);
        }
        self.metadata_errors += 1;
    }

    fn accessors(
        &mut self,
        owner: RuntimeType,
        cache: &TypeCache,
        image: &[u8],
        bounds: &Bounds<'_>,
    ) -> Result<Vec<Accessor>> {
        let mut out = Vec::new();
        // DeclaredOnly | Instance | Public | NonPublic. Inherited properties
        // must not supply names for another owner's native object layout.
        for property in references::<PropertyInfo>(
            owner.get_properties_array(54)?,
            "System.Reflection.PropertyInfo",
            self,
        )? {
            let result = (|| -> Result<Option<Accessor>> {
                ensure!(property.0 != 0, "null business property");
                let name = checked_name(property.get_name()?)?;
                if !identifier(&name) || is_obf(&name) {
                    return Ok(None);
                }
                let ty = property.get_property_type()?;
                let Some((kind, bytes)) = accessor_kind(ty, cache)? else {
                    return Ok(None);
                };
                let getter = property.get_get_method(true)?;
                let setter = property.get_set_method(true)?;
                if getter.0 == 0 || setter.0 == 0 {
                    return Ok(None);
                }
                if !instance(getter, owner)? || !instance(setter, owner)? {
                    return Ok(None);
                }
                let getter_params = parameters(getter, self)?;
                let setter_params = parameters(setter, self)?;
                if !getter_params.is_empty()
                    || setter_params.len() != 1
                    || getter.get_return_type()? != ty
                    || setter_params[0].get_parameter_type()? != ty
                    || checked_name(setter.get_return_type()?.get_full_name()?)? != "System.Void"
                {
                    return Ok(None);
                }
                let (getter_rva, getter_body) = body(getter, image, bounds)?;
                let (setter_rva, setter_body) = body(setter, image, bounds)?;
                let read = sync_scan::scan_typed(getter_body, getter_rva, Mode::Getter, bytes);
                let write = sync_scan::scan_typed(setter_body, setter_rva, Mode::Setter, bytes);
                let Some(offset) = read
                    .accessor_offset
                    .filter(|offset| *offset >= 16 && Some(*offset) == write.accessor_offset)
                else {
                    self.unbound_accessors += 1;
                    return Ok(None);
                };
                Ok(Some(Accessor {
                    name: snake_field(&name),
                    kind,
                    ty,
                    bytes,
                    offset,
                    getter_rva,
                    setter_rva,
                    member_kind: "property",
                }))
            })();
            match result {
                Ok(Some(accessor)) => out.push(accessor),
                Ok(None) => {}
                Err(error) => self.failure(format_args!("property=0x{:X}: {error:#}", property.0)),
            }
        }
        // Different semantic properties sharing an offset provide no unique
        // business name, even if their current native accessors are aliases.
        let mut grouped = HashMap::<u32, Vec<Accessor>>::new();
        for accessor in out {
            grouped.entry(accessor.offset).or_default().push(accessor);
        }
        let mut unique = Vec::new();
        for group in grouped.into_values() {
            if group.iter().all(|a| {
                a.name == group[0].name
                    && a.kind == group[0].kind
                    && a.ty == group[0].ty
                    && a.bytes == group[0].bytes
            }) {
                unique.push(group[0].clone());
            } else {
                self.conflicts += 1;
            }
        }
        match declared_fields::collect(owner, cache, self) {
            Ok(fields) => {
                for field in fields {
                    // Preserve the independently checked property route at
                    // every overlapping slot. Plain fields only add new slots.
                    if unique.iter().any(|property| {
                        let left = u64::from(property.offset)..u64::from(property.offset) + property.bytes as u64;
                        let right = u64::from(field.offset)..u64::from(field.offset) + field.bytes as u64;
                        left.start < right.end && right.start < left.end
                    }) {
                        continue;
                    }
                    self.declared_fields += 1;
                    unique.push(field);
                }
            }
            Err(error) => self.failure(format_args!("declared field layout: {error:#}")),
        }
        self.typed_accessors += unique.len();
        Ok(unique)
    }

    fn insert(&mut self, evidence: Evidence) {
        let key = (evidence.message.clone(), evidence.tag);
        let tags = self.names.entry(evidence.message.clone()).or_default();
        if !self.blocked.contains(&key) {
            if tags
                .get(&evidence.tag)
                .is_some_and(|name| *name != evidence.recovered)
            {
                // An invalid scoped candidate deliberately blocks global
                // fallback; final output validation preserves the raw name.
                tags.insert(evidence.tag, String::new());
                self.blocked.insert(key);
                self.conflicts += 1;
            } else {
                tags.insert(evidence.tag, evidence.recovered.clone());
            }
        }
        self.evidence.push(evidence);
    }

    pub(super) fn retain_unresolved(&mut self, baseline: &TypeToItemMap) {
        for item in baseline.values() {
            let item = item.borrow();
            let ProtoItem::Message(message) = &*item else {
                continue;
            };
            let Some(tags) = self.names.get_mut(&message.name) else {
                continue;
            };
            for field in &message.fields {
                if !is_obf(&field.name) && tags.remove(&field.number).is_some() {
                    let key = (message.name.clone(), field.number);
                    self.blocked.remove(&key);
                    self.preserved_existing.insert(key);
                }
            }
            // A new alias must not make another already accepted field revert
            // to its raw name in the final message-wide collision check.
            let occupied: HashSet<_> = message
                .fields
                .iter()
                .chain(message.oneofs.iter().flat_map(|oneof| &oneof.fields))
                .filter(|field| !is_obf(&field.name))
                .map(|field| field_name_key(&field.name))
                .collect();
            let collisions: Vec<_> = tags
                .iter()
                .filter(|(_, name)| occupied.contains(&field_name_key(name)))
                .map(|(&tag, _)| tag)
                .collect();
            for tag in collisions {
                tags.remove(&tag);
                let key = (message.name.clone(), tag);
                self.blocked.remove(&key);
                self.rejected_existing_collisions.insert(key);
            }
        }
    }

    pub(super) fn merge_into(&mut self, names: &mut ScopedFieldNames) {
        for (message, tags) in &self.names {
            let target = names.entry(message.clone()).or_default();
            for (&tag, name) in tags {
                if target.get(&tag).is_some_and(|previous| previous != name) {
                    target.insert(tag, String::new());
                    self.blocked.insert((message.clone(), tag));
                    self.conflicts += 1;
                } else {
                    target.insert(tag, name.clone());
                }
            }
        }
    }

    pub(super) fn write(&mut self, items: &TypeToItemMap, path: &Path) -> io::Result<()> {
        let mut final_names = HashMap::new();
        for item in items.values() {
            let item = item.borrow();
            if let ProtoItem::Message(message) = &*item {
                for field in &message.fields {
                    final_names.insert(
                        (message.name.clone(), field.number),
                        snake_field(&field.name),
                    );
                }
            }
        }
        let mut accepted = HashSet::new();
        for evidence in &mut self.evidence {
            let key = (evidence.message.clone(), evidence.tag);
            evidence.final_name = final_names.get(&key).cloned();
            evidence.status = if self.preserved_existing.contains(&key) {
                "preserved-existing-name"
            } else if self.rejected_existing_collisions.contains(&key) {
                "rejected-existing-name-collision"
            } else if self.blocked.contains(&key) {
                "conflicting-evidence"
            } else if evidence.final_name.as_deref() == Some(&evidence.recovered) {
                accepted.insert(key);
                "accepted-native-copy"
            } else {
                "rejected-by-output-validation"
            };
        }
        log::info!(
            "[Sync Fields] complete: methods={} sync_methods={} specialized_sync_methods={} other_proto_methods={} unsupported_returns={} owners={} accessors={} copies={} accepted_tags={} preserved_tags={} existing_name_collisions={} conflicts={} unbound_accessors={} metadata_errors={}",
            self.methods_considered,
            self.sync_methods,
            self.specialized_sync_methods,
            self.other_proto_methods,
            self.unsupported_return_types,
            self.owners,
            self.typed_accessors,
            self.copies,
            accepted.len(),
            self.preserved_existing.len(),
            self.rejected_existing_collisions.len(),
            self.conflicts,
            self.unbound_accessors,
            self.metadata_errors
        );
        let report = serde_json::json!({
            "game_version": &*crate::version::GAME_VERSION,
            "source": "current instance native methods with one Proto parameter, direct copy and own typed property getter/setter with equal runtime types; hotfix overrides are not executed by this collector",
            "accepted_tags": accepted.len(), "preserved_tags": self.preserved_existing.len(),
            "existing_name_collisions": self.rejected_existing_collisions.len(), "summary": self,
        });
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&report).map_err(io::Error::other)?,
        )
    }
}

fn collect_inner(
    out: &mut SyncFields,
    items: &TypeToItemMap,
    cache: &TypeCache,
    progress: &Progress,
) -> Result<()> {
    let table = FUNCTIONS_TABLE_REFLECTION
        .get()
        .context("reflection method table unavailable")?;
    let image = utils::game_assembly_slice();
    let functions = FunctionTable::from_pe(image)?;
    let methods = crate::script::METHODS
        .get()
        .context("Script method entries unavailable")?;
    let executable = executable_ranges(image)?;
    let mut entries: Vec<_> = methods
        .keys()
        .filter_map(|rva| usize::try_from(*rva).ok())
        .filter(|rva| executable.iter().any(|range| range.contains(rva)))
        .collect();
    entries.sort_unstable();
    entries.dedup();
    ensure!(!entries.is_empty(), "no declared executable method entries");
    let bounds = Bounds {
        functions,
        entries,
        executable,
    };
    let flow = (|| -> Result<_> {
        let module = unsafe { GetModuleHandleA(s!("kernel32.dll")) }?;
        let expected = unsafe { GetProcAddress(module, s!("RaiseException")) }
            .context("OS RaiseException binding unavailable")? as usize;
        let pe = Pe::new(image, memory::readable)?;
        log::debug!(
            "[Sync Flow] stage=PE/import validation preferred_base=0x{:X} image_bytes={} runtime_functions={} RaiseException_imports={}",
            pe.preferred_base(),
            pe.image_len(),
            pe.function_count(),
            pe.raise_exception_iats().len()
        );
        Ok(Resolver::new(pe, Binding::Loaded(expected)))
    })();
    let mut flow = match flow {
        Ok(flow) => Some(flow),
        Err(error) => {
            out.control_flow_errors += 1;
            log::warn!(
                "[Sync Flow] stage=PE/import validation reason={error:#}; retain ordinary call successors"
            );
            None
        }
    };
    let message_names: HashSet<_> = items
        .values()
        .filter_map(|item| {
            if let ProtoItem::Message(message) = &*item.borrow() {
                Some(message.name.clone())
            } else {
                None
            }
        })
        .collect();
    let candidates: Vec<_> = table
        .iter()
        .filter(|(signature, _)| {
            sync_signature(signature) || proto_signature(signature, &message_names)
        })
        .collect();
    let enum_names: HashSet<_> = items
        .values()
        .filter_map(|item| {
            if let ProtoItem::Enum(enumeration) = &*item.borrow() {
                Some(enumeration.name.clone())
            } else {
                None
            }
        })
        .collect();
    progress.stage("business Proto copy field names", candidates.len());
    let mut accessors = HashMap::<RuntimeType, Vec<Accessor>>::new();
    for (index, (signature, handle)) in candidates.into_iter().enumerate() {
        out.methods_considered += 1;
        out.context = signature.clone();
        progress.step(
            index,
            handle.0,
            "bind native instance copy to typed business properties",
        );
        let result = (|| -> Result<()> {
            memory::readable(handle.0, 16)?;
            let method = MethodInfo::from_handle(*handle)?;
            ensure!(method.0 != 0, "null business method");
            let owner = method.get_declaring_type()?;
            let name = checked_name(method.get_name()?)?;
            if items.contains_key(&owner) || !instance(method, owner)? || !managed_reference(owner)? {
                return Ok(());
            }
            let params = parameters(method, out)?;
            if params.len() != 1 {
                return Ok(());
            }
            let proto = params[0].get_parameter_type()?;
            let Some(item) = items.get(&proto) else {
                return Ok(());
            };
            let item = item.borrow();
            let ProtoItem::Message(message) = &*item else {
                return Ok(());
            };
            let return_type = method.get_return_type()?;
            let return_name = checked_name(return_type.get_full_name()?)?;
            let Some(return_abi) = return_abi(method, return_type, &return_name, cache)? else {
                out.unsupported_return_types += 1;
                if out.unsupported_return_types <= 12 {
                    log::debug!(
                        "[Sync Fields] unsupported return ABI: method={} return_type={}",
                        signature,
                        return_name
                    );
                }
                return Ok(());
            };
            out.sync_methods += 1;
            out.reference_return_methods += usize::from(return_abi == "managed-reference");
            out.other_proto_methods += usize::from(!sync_method_name(&name));
            out.specialized_sync_methods += usize::from(
                sync_method_name(&name) && !matches!(name.as_str(), "Sync" | "SyncFrom"),
            );
            let (rva, code) = body(method, image, &bounds)?;
            let plan = match flow.as_mut().map(|flow| flow.plan(rva, code)).transpose() {
                Ok(plan) => plan.unwrap_or_default(),
                Err(error) => {
                    out.control_flow_errors += 1;
                    if out.control_flow_errors <= 12 {
                        log::debug!(
                            "[Sync Flow] stage=caller validation method={} rva=0x{:X} reason={error:#}; retain ordinary call successors",
                            signature,
                            rva
                        );
                    }
                    Plan::default()
                }
            };
            if !plan.terminal_calls.is_empty()
                && flow
                    .as_ref()
                    .is_some_and(|flow| flow.stats.planned_callers <= 12)
            {
                log::debug!(
                    "[Sync Flow] method={} rva=0x{:X} terminal_calls={} catch_edges={} funcinfo={:?}",
                    signature,
                    rva,
                    plan.terminal_calls.len(),
                    plan.exceptional_edges.values().map(Vec::len).sum::<usize>(),
                    plan.funcinfo_rva
                );
            }
            let mut copies = Vec::new();
            for bytes in [4, 1, 8] {
                if !message
                    .fields
                    .iter()
                    .any(|field| wire_bytes(&field.kind, &enum_names) == Some(bytes))
                {
                    continue;
                }
                let copied = sync_scan::scan_planned_typed(
                    code,
                    rva,
                    Mode::Sync,
                    &plan.terminal_calls,
                    &plan.exceptional_edges,
                    &plan.switch_edges,
                    plan.code_bytes,
                    bytes,
                );
                copies.extend(copied.copies.into_iter().map(|copy| (bytes, copy)));
            }
            out.copies += copies.len();
            if copies.is_empty() {
                return Ok(());
            }
            if !accessors.contains_key(&owner) {
                let found = out.accessors(owner, cache, image, &bounds)?;
                accessors.insert(owner, found);
            }
            let business_type = checked_name(owner.get_full_name()?)?;
            let business = &accessors[&owner];
            let mut offsets = HashMap::<u32, usize>::new();
            for field in message
                .fields
                .iter()
                .chain(message.oneofs.iter().flat_map(|oneof| &oneof.fields))
            {
                *offsets.entry(field.offset).or_default() += 1;
            }
            for (bytes, copy) in copies {
                let Some(field) = message.fields.iter().find(|field| {
                    field.offset == copy.proto_offset
                        && offsets[&field.offset] == 1
                        && wire_bytes(&field.kind, &enum_names) == Some(bytes)
                        && is_obf(&field.name)
                }) else {
                    continue;
                };
                let Some(property) = business.iter().find(|a| {
                    a.offset == copy.business_offset
                        && a.bytes == bytes
                        && (compatible_kind(&a.kind, &field.kind)
                            || matches!(a.kind.as_str(), "enum" | "reference"))
                }) else {
                    continue;
                };
                // Equal copy width is insufficient for enums and references.
                // Bind the raw protocol property to exactly the same runtime
                // type; different business enums or collection shapes reject.
                match same_proto_property(proto, &field.name, property.ty) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        out.failure(format_args!(
                            "Proto property={} tag={}: {error:#}",
                            field.name, field.number
                        ));
                        continue;
                    }
                }
                out.insert(Evidence {
                    message: message.name.clone(),
                    tag: field.number,
                    original: field.name.clone(),
                    recovered: property.name.clone(),
                    proto_offset: field.offset,
                    business_type: business_type.clone(),
                    business_offset: property.offset,
                    business_property_type: checked_name(property.ty.get_full_name()?)?,
                    business_member_kind: property.member_kind,
                    kind: field.kind.clone(),
                    native_bytes: bytes,
                    sync_method: name.clone(),
                    sync_return_type: return_name.clone(),
                    return_abi,
                    sync_rva: rva,
                    getter_rva: property.getter_rva,
                    setter_rva: property.setter_rva,
                    load_rva: copy.load_rva,
                    store_rva: copy.store_rva,
                    status: "candidate",
                    final_name: None,
                });
            }
            Ok(())
        })();
        if let Err(error) = result {
            out.failure(format_args!("{error:#}"));
        }
    }
    out.owners = accessors.len();
    if let Some(flow) = flow {
        out.control_flow = flow.stats;
    }
    log::info!(
        "[Sync Flow] complete: examined={} proven={} cache_hits={} terminal_calls={} catch_edges={} unsupported_callers={} errors={}",
        out.control_flow.functions_examined,
        out.control_flow.proven_functions,
        out.control_flow.cache_hits,
        out.control_flow.terminal_calls,
        out.control_flow.exceptional_edges,
        out.control_flow.unsupported_callers,
        out.control_flow_errors
    );
    log::info!(
        "[Sync Fields] candidates: methods={} sync_methods={} specialized_sync_methods={} other_proto_methods={} unsupported_returns={} owners={} accessors={} copies={} tags={} conflicts={} metadata_errors={}",
        out.methods_considered,
        out.sync_methods,
        out.specialized_sync_methods,
        out.other_proto_methods,
        out.unsupported_return_types,
        out.owners,
        out.typed_accessors,
        out.copies,
        out.names.values().map(HashMap::len).sum::<usize>(),
        out.conflicts,
        out.metadata_errors
    );
    Ok(())
}

pub(super) fn collect(
    items: &TypeToItemMap,
    cache: &TypeCache,
    progress: &Progress,
) -> io::Result<SyncFields> {
    let mut out = SyncFields::default();
    microseh::try_seh(|| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collect_inner(&mut out, items, cache, progress)
        }))
    })
    .map_err(|e| {
        io::Error::other(format!(
            "Sync field native fault context={}: {e:?}",
            out.context
        ))
    })?
    .map_err(|_| io::Error::other(format!("Sync field panic context={}", out.context)))?
    .map_err(io::Error::other)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additional_methods_are_selected_by_the_exact_actual_proto_argument() {
        let names = HashSet::from(["ABCDEFGHIJK".to_string()]);
        for name in ["Update", "_SyncFromProto", "Create", "KLMNOPQRSTU"] {
            assert!(proto_signature(
                &format!("Business::{name}(ABCDEFGHIJK)"),
                &names
            ));
            assert!(proto_signature(
                &format!("Business::{name}(Proto.ABCDEFGHIJK)"),
                &names
            ));
        }
        for signature in [
            "Business::.ctor(ABCDEFGHIJK)",
            "Business::Update(KLMNOPQRSTU)",
            "Business::Update(ABCDEFGHIJK,System.Int32)",
            "Business::Update(ABCDEFGHIJK[])",
            "Business::Update(List<ABCDEFGHIJK>)",
            "Business::Update(ABCDEFGHIJK)",
        ] {
            let expected = signature == "Business::Update(ABCDEFGHIJK)";
            assert_eq!(proto_signature(signature, &names), expected, "{signature}");
        }
        assert!(!proto_signature("Update(ABCDEFGHIJK)", &names));
        assert!(!proto_signature("Business::Update(ABCDEFGHIJK", &names));
    }

    #[test]
    fn specialized_sync_names_are_selected_from_the_method_not_owner_or_arguments() {
        for name in [
            "Sync",
            "SyncFrom",
            "SyncDaily",
            "SyncMuseumData",
            "SyncChessRogueAeonInfo",
            "SyncLayout",
            "SyncUpdate",
            "SyncFromProto",
        ] {
            assert!(sync_method_name(name), "{name}");
            assert!(sync_signature(&format!(
                "Business::{name}(Proto.ABCDEFGHIJK)"
            )));
        }
        for name in ["Synchronize", "AsyncSync", "sync", "Sync2", "Sync_Data", ""] {
            assert!(!sync_method_name(name), "{name}");
            assert!(!sync_signature(&format!(
                "SyncDaily::{name}(SyncFromProto)"
            )));
        }
        assert!(!sync_signature("SyncDaily(Proto.ABCDEFGHIJK)"));
        assert!(!sync_signature("Business::SyncDaily"));
        assert!(!sync_signature("Business::Update(SyncDaily)"));
    }

    #[test]
    fn reflection_reference_body_uses_allocation_and_checked_arithmetic() {
        assert_eq!(reference_body(100, 3, 56).unwrap(), 132..156);
        assert!(reference_body(100, 4, 56).is_err());
        assert!(reference_body(100, usize::MAX, usize::MAX).is_err());
        assert!(reference_body(usize::MAX - 10, 0, 32).is_err());
    }

    #[test]
    fn aggregate_or_unknown_returns_cannot_shift_the_scanners_owner_arguments() {
        assert!(sync_return_abi("System.Void", None));
        assert!(sync_return_abi(
            "System.Boolean",
            Some(&CachedType::Boolean)
        ));
        assert!(sync_return_abi("System.UInt32", Some(&CachedType::UInt32)));
        assert!(sync_return_abi("System.Double", Some(&CachedType::Double)));
        assert!(!sync_return_abi("Business.Snapshot", None));
        assert!(!sync_return_abi("System.Nullable<System.Int32>", None));
        assert!(!sync_return_abi("Business.Mode", Some(&CachedType::Enum)));
        assert!(!sync_return_abi("System.Object", Some(&CachedType::Object)));
    }

    fn evidence(message: &str, recovered: &str) -> Evidence {
        Evidence {
            message: message.into(),
            tag: 7,
            original: "ABCDEFGHIJK".into(),
            recovered: recovered.into(),
            proto_offset: 32,
            business_type: "Business".into(),
            business_offset: 48,
            business_property_type: "System.UInt32".into(),
            business_member_kind: "property",
            kind: "uint32".into(),
            native_bytes: 4,
            sync_method: "Sync".into(),
            sync_return_type: "System.Void".into(),
            return_abi: "void",
            sync_rva: 1,
            getter_rva: 2,
            setter_rva: 3,
            load_rva: 4,
            store_rva: 5,
            status: "candidate",
            final_name: None,
        }
    }

    #[test]
    fn conflicting_native_evidence_stays_blocked_and_does_not_leak_between_messages() {
        let mut out = SyncFields::default();
        out.insert(evidence("First", "score"));
        out.insert(evidence("First", "level"));
        out.insert(evidence("First", "score"));
        out.insert(evidence("Second", "level"));
        assert_eq!(out.names["First"][&7], "");
        assert_eq!(out.names["Second"][&7], "level");
        let mut constants =
            HashMap::from([("Second".into(), HashMap::from([(7, "other".into())]))]);
        out.merge_into(&mut constants);
        assert_eq!(constants["Second"][&7], "");
    }

    #[test]
    fn sync_only_fills_fields_still_obfuscated_after_existing_name_validation() {
        use super::super::output::{Field, Message, MessageType};
        use std::{cell::RefCell, rc::Rc};

        let mut out = SyncFields::default();
        out.insert(evidence("First", "star"));
        out.insert(evidence("First", "level"));
        out.insert(evidence("Second", "score"));
        let mut collision = evidence("First", "RoleStar");
        collision.tag = 8;
        out.insert(collision);
        let mut baseline = TypeToItemMap::new();
        for (index, (message, name)) in [("First", "role_star"), ("Second", "ABCDEFGHIJK")]
            .into_iter()
            .enumerate()
        {
            baseline.insert(
                RuntimeType(index + 1),
                Rc::new(RefCell::new(ProtoItem::Message(Message {
                    cmd_id: 0,
                    name: message.into(),
                    deobfuscated_name: None,
                    fields: vec![Field {
                        kind: "uint32".into(),
                        name: name.into(),
                        number: 7,
                        offset: 32,
                    }],
                    oneofs: vec![],
                    children: vec![],
                    has_parent: false,
                    msg_type: MessageType::None,
                    write_to_rva: 0,
                    merge_from_rva: 0,
                }))),
            );
        }
        if let ProtoItem::Message(message) = &mut *baseline[&RuntimeType(1)].borrow_mut() {
            message.fields.push(Field {
                kind: "uint32".into(),
                name: "BCDEFGHIJKL".into(),
                number: 8,
                offset: 36,
            });
        }
        out.retain_unresolved(&baseline);
        let mut scoped = ScopedFieldNames::new();
        out.merge_into(&mut scoped);
        assert!(!scoped["First"].contains_key(&7));
        assert!(!scoped["First"].contains_key(&8));
        assert_eq!(scoped["Second"][&7], "score");
        assert!(out.preserved_existing.contains(&("First".into(), 7)));
        assert!(!out.blocked.contains(&("First".into(), 7)));
        assert!(
            out.rejected_existing_collisions
                .contains(&("First".into(), 8))
        );
        if let ProtoItem::Message(message) = &*baseline[&RuntimeType(1)].borrow() {
            assert_eq!(message.fields[0].name, "role_star");
        }
    }
}
