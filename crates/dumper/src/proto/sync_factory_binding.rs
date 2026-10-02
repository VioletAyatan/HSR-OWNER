//! Runtime proof that a native factory is a current, unambiguous static method
//! returning its own closed managed type and accepting one actual Proto type.

use std::collections::HashSet;

use anyhow::{Context, Result, ensure};
use il2cpp::{
    FUNCTIONS_TABLE_REFLECTION, GA_BASE,
    api::{self, il2cpp_type_equals},
    vm::{class::Il2CppClass, method::Il2CppMethod, r#type::Il2CppType},
};
use reflection::{
    attributes::MethodAttributes, method_info::MethodInfo, runtime_type::RuntimeType,
};
use serde::Serialize;

use super::{
    Accessor, Bounds, SyncFields, TypeCache, TypeToItemMap, checked_name, executable_ranges,
    managed_reference, native_body, parameters, reflection_bool, same_proto_property,
};
use crate::{
    proto::{asm_address, native_pe::Pe, output::ProtoItem},
    script::memory,
};

/// A member whose type, ownership, offset and accessor/field identity have
/// already passed the same checks used by the ordinary Sync-field collector.
pub(in crate::proto) struct FactoryMember {
    pub(in crate::proto) name: String,
    pub(in crate::proto) kind: String,
    pub(in crate::proto) ty: RuntimeType,
    pub(in crate::proto) type_name: String,
    pub(in crate::proto) bytes: usize,
    pub(in crate::proto) offset: u32,
    pub(in crate::proto) getter_rva: usize,
    pub(in crate::proto) setter_rva: usize,
    pub(in crate::proto) member_kind: &'static str,
}

/// A report-safe projection of one typed member. It contains names and RVA
/// evidence, but no live IL2CPP pointers or member values.
#[derive(Serialize)]
pub(in crate::proto) struct FactoryMemberReport {
    name: String,
    kind: String,
    type_name: String,
    bytes: usize,
    offset: u32,
    getter_rva: usize,
    setter_rva: usize,
    member_kind: &'static str,
}

#[derive(Serialize)]
pub(in crate::proto) struct FactoryCandidateDecision {
    signature: String,
    rva: Option<usize>,
    stage: &'static str,
    reason: String,
}

#[derive(Serialize)]
pub(in crate::proto) struct FactoryBindingReport {
    requested_owner: String,
    requested_method: String,
    selected_signature: String,
    selected_rva: usize,
    body_start: usize,
    body_end: usize,
    proto_type: String,
    proto_parameter_index: usize,
    candidate_decisions: Vec<FactoryCandidateDecision>,
    members: Vec<FactoryMemberReport>,
    property_decisions: serde_json::Value,
}

/// Runtime-owned values and current full-PE code for one proved factory.
/// Callers may use these values for a separate native data-flow proof.
pub(in crate::proto) struct BoundFactory {
    pub(in crate::proto) method: MethodInfo,
    pub(in crate::proto) native_method: Il2CppMethod,
    pub(in crate::proto) owner: RuntimeType,
    pub(in crate::proto) owner_class: Il2CppClass,
    pub(in crate::proto) proto: RuntimeType,
    pub(in crate::proto) proto_parameter_index: usize,
    pub(in crate::proto) signature: String,
    pub(in crate::proto) rva: usize,
    pub(in crate::proto) body_end: usize,
    pub(in crate::proto) code: Vec<u8>,
    pub(in crate::proto) members: Vec<FactoryMember>,
    pub(in crate::proto) report: FactoryBindingReport,
}

struct CandidateProof {
    method: MethodInfo,
    native_method: Il2CppMethod,
    owner: RuntimeType,
    owner_class: Il2CppClass,
    proto: RuntimeType,
    proto_parameter_index: usize,
    signature: String,
    rva: usize,
    body_end: usize,
    code: Vec<u8>,
    members: Vec<FactoryMember>,
    property_decisions: serde_json::Value,
}

/// Resolve a factory by live reflection and current Script/PE evidence.
///
/// The return type must be exactly the closed declaring type, and exactly one
/// parameter must be one of the current Proto Message runtime types in `items`.
pub(in crate::proto) fn bind(
    owner_name: &str,
    method_name: &str,
    items: &TypeToItemMap,
) -> Result<BoundFactory> {
    ensure!(!owner_name.is_empty(), "factory owner name is empty");
    ensure!(!method_name.is_empty(), "factory method name is empty");

    let table = FUNCTIONS_TABLE_REFLECTION
        .get()
        .context("reflection method table unavailable")?;
    let image = utils::game_assembly_slice();
    let methods = crate::script::METHODS
        .get()
        .context("Script method entries unavailable")?;
    let shared_method_rvas = crate::script::METHODS_SHARED_RVAS
        .get()
        .context("Script shared method-entry evidence unavailable")?;
    let functions = super::FunctionTable::from_pe(image)?;
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

    let proto_types: HashSet<_> = items
        .iter()
        .filter_map(|(ty, item)| matches!(&*item.borrow(), ProtoItem::Message(_)).then_some(*ty))
        .collect();
    ensure!(
        !proto_types.is_empty(),
        "current Proto Message map is empty"
    );

    let mut decisions = Vec::new();
    let mut valid = Vec::new();
    let mut owner_method_count = 0usize;

    let signature_prefix = format!("{owner_name}::{method_name}(");
    for (table_signature, native_method) in table {
        if !table_signature.starts_with(&signature_prefix) {
            continue;
        }
        if let Err(error) = memory::readable(native_method.0, 16) {
            decisions.push(FactoryCandidateDecision {
                signature: table_signature.clone(),
                rva: None,
                stage: "native-method-handle",
                reason: format!("invalid-native-method-handle: {error:#}"),
            });
            continue;
        }
        if native_method.get_name().as_ref() != method_name {
            continue;
        }
        let method = match MethodInfo::from_handle(*native_method) {
            Ok(method) if method.0 != 0 => method,
            Ok(_) => continue,
            Err(error) => {
                decisions.push(FactoryCandidateDecision {
                    signature: table_signature.clone(),
                    rva: checked_rva(*native_method, image),
                    stage: "reflection-handle",
                    reason: format!("cannot-resolve-MethodInfo: {error:#}"),
                });
                continue;
            }
        };
        let declared_owner = match method.get_declaring_type() {
            Ok(owner) if owner.0 != 0 => owner,
            Ok(_) => continue,
            Err(error) => {
                decisions.push(FactoryCandidateDecision {
                    signature: table_signature.clone(),
                    rva: checked_rva(*native_method, image),
                    stage: "declaring-owner",
                    reason: format!("cannot-resolve-declaring-type: {error:#}"),
                });
                continue;
            }
        };
        let actual_owner_name = match declared_owner.get_full_name().and_then(checked_name) {
            Ok(name) => name,
            Err(error) => {
                decisions.push(FactoryCandidateDecision {
                    signature: table_signature.clone(),
                    rva: checked_rva(*native_method, image),
                    stage: "declaring-owner",
                    reason: format!("cannot-read-owner-name: {error:#}"),
                });
                continue;
            }
        };
        if actual_owner_name != owner_name {
            continue;
        }
        owner_method_count += 1;

        let rva = checked_rva(*native_method, image);
        match prove_candidate(
            table_signature,
            *native_method,
            method,
            declared_owner,
            owner_name,
            method_name,
            &proto_types,
            &bounds,
            image,
            methods,
            shared_method_rvas,
        ) {
            Ok(proof) => {
                decisions.push(FactoryCandidateDecision {
                    signature: proof.signature.clone(),
                    rva: Some(proof.rva),
                    stage: "accepted",
                    reason: "static-own-closed-proto-factory-and-full-body-proven".to_owned(),
                });
                valid.push(proof);
            }
            Err((stage, error)) => decisions.push(FactoryCandidateDecision {
                signature: table_signature.clone(),
                rva,
                stage,
                reason: format!("{error:#}"),
            }),
        }
    }

    ensure!(
        owner_method_count > 0,
        "no reflection method with requested owner and method name"
    );
    ensure!(
        valid.len() == 1,
        "factory binding is not unique: owner_methods={owner_method_count} valid_candidates={}; decisions={}",
        valid.len(),
        serde_json::to_string(&decisions).unwrap_or_else(|_| "[]".to_owned())
    );

    let selected = valid
        .pop()
        .context("unique factory candidate disappeared")?;
    let member_reports = selected
        .members
        .iter()
        .map(|member| FactoryMemberReport {
            name: member.name.clone(),
            kind: member.kind.clone(),
            type_name: member.type_name.clone(),
            bytes: member.bytes,
            offset: member.offset,
            getter_rva: member.getter_rva,
            setter_rva: member.setter_rva,
            member_kind: member.member_kind,
        })
        .collect();
    let proto_type = checked_name(selected.proto.get_full_name()?)?;
    let report = FactoryBindingReport {
        requested_owner: owner_name.to_owned(),
        requested_method: method_name.to_owned(),
        selected_signature: selected.signature.clone(),
        selected_rva: selected.rva,
        body_start: selected.rva,
        body_end: selected.body_end,
        proto_type,
        proto_parameter_index: selected.proto_parameter_index,
        candidate_decisions: decisions,
        members: member_reports,
        property_decisions: selected.property_decisions,
    };

    Ok(BoundFactory {
        method: selected.method,
        native_method: selected.native_method,
        owner: selected.owner,
        owner_class: selected.owner_class,
        proto: selected.proto,
        proto_parameter_index: selected.proto_parameter_index,
        signature: selected.signature,
        rva: selected.rva,
        body_end: selected.body_end,
        code: selected.code,
        members: selected.members,
        report,
    })
}

/// Prove that a Proto property with this raw name has the exact same closed
/// RuntimeType as a discovered factory member.
pub(in crate::proto) fn proto_field_type_matches(
    proto: RuntimeType,
    raw_name: &str,
    ty: RuntimeType,
) -> Result<bool> {
    same_proto_property(proto, raw_name, ty)
}

fn prove_candidate(
    table_signature: &str,
    native_method: Il2CppMethod,
    method: MethodInfo,
    owner: RuntimeType,
    owner_name: &str,
    method_name: &str,
    proto_types: &HashSet<RuntimeType>,
    bounds: &Bounds<'_>,
    image: &[u8],
    methods: &std::collections::HashMap<u64, Il2CppMethod>,
    shared_method_rvas: &HashSet<u64>,
) -> std::result::Result<CandidateProof, (&'static str, anyhow::Error)> {
    let checked = (|| -> Result<CandidateProof> {
        memory::readable(native_method.0, 16)?;
        memory::readable(method.0, 24)?;
        ensure!(
            MethodInfo::from_handle(native_method)?.0 == method.0
                && method.get_il2cpp_method().0 == native_method.0,
            "reflection and native method handles do not round-trip"
        );
        ensure!(
            native_method.get_name().as_ref() == method_name
                && checked_name(method.get_name()?)? == method_name,
            "native and reflection method names disagree"
        );

        let owner_class = owner.get_il2cpp_type().get_class();
        ensure!(owner_class.0 != 0, "owner has a null Il2CppClass");
        memory::readable(owner_class.0, 16)?;
        ensure!(
            il2cpp::get_cached_class(owner_name).is_some_and(|class| class == owner_class),
            "owner class disagrees with current cached class"
        );
        ensure!(
            method.get_declaring_type()? == owner && native_method.class() == owner_class,
            "native and reflection declaring owners disagree"
        );
        ensure!(
            checked_name(owner.get_full_name()?)? == owner_name,
            "closed owner name changed during binding"
        );
        ensure!(
            managed_reference(owner)?,
            "owner is not a closed managed reference"
        );

        let attributes = method.get_attributes()?;
        memory::readable(attributes.0, 20)?;
        ensure!(
            attributes.unbox().contains(MethodAttributes::Static),
            "factory method is not static"
        );
        ensure!(
            !api::il2cpp_method_is_instance(native_method),
            "native method is instance while reflection marks it static"
        );
        ensure!(
            !reflection_bool(method.get_is_generic_method()?)?,
            "factory method is generic"
        );

        let returned = method.get_return_type()?;
        ensure!(
            returned == owner,
            "factory return RuntimeType is not its owner"
        );
        ensure!(
            managed_reference(returned)?,
            "factory return is not a closed managed reference"
        );
        check_native_type(
            api::il2cpp_method_get_return_type(native_method),
            returned,
            "native return type disagrees with reflection",
        )?;

        let mut out = SyncFields::default();
        let runtime_parameters = parameters(method, &mut out)?;
        ensure!(
            runtime_parameters.len() == 1,
            "factory must have exactly one runtime parameter for the scanner ABI"
        );
        let native_parameter_count =
            usize::try_from(api::il2cpp_method_get_param_count(native_method))
                .context("invalid native parameter count")?;
        ensure!(
            runtime_parameters.len() == native_parameter_count,
            "native and reflection parameter counts disagree"
        );
        let mut proto_parameters = Vec::new();
        let mut parameter_types = Vec::with_capacity(runtime_parameters.len());
        for (index, parameter) in runtime_parameters.iter().enumerate() {
            let ty = parameter.get_parameter_type()?;
            ensure!(ty.0 != 0, "parameter RuntimeType is null");
            memory::readable(ty.0, 24)?;
            check_native_type(
                api::il2cpp_method_get_param(native_method, index as u32),
                ty,
                "native parameter type disagrees with reflection",
            )?;
            let type_name = checked_name(ty.get_full_name()?)?;
            if proto_types.contains(&ty) {
                ensure!(
                    managed_reference(ty)?,
                    "Proto parameter is not a closed managed reference"
                );
                proto_parameters.push((index, ty));
            }
            parameter_types.push(type_name);
        }
        ensure!(
            proto_parameters.len() == 1,
            "factory must have exactly one current Proto Message parameter; found {}",
            proto_parameters.len()
        );
        let (proto_parameter_index, proto) = proto_parameters[0];
        ensure!(
            proto_parameter_index == 0,
            "factory Proto parameter must be ordinal zero for the scanner ABI"
        );
        let signature = format!("{owner_name}::{method_name}({})", parameter_types.join(","));
        ensure!(
            table_signature.starts_with(&format!("{owner_name}::{method_name}(")),
            "reflection signature key does not identify requested method"
        );

        let rva = asm_address::module_rva(native_method.va(), *GA_BASE, image.len())
            .filter(|rva| *rva != 0)
            .context("native method address is outside GameAssembly")?;
        ensure!(
            methods
                .get(&(rva as u64))
                .is_some_and(|entry| entry.0 == native_method.0),
            "native method does not match its current ScriptMethod entry"
        );
        ensure!(
            !shared_method_rvas.contains(&(rva as u64)),
            "native RVA is shared by ambiguous ScriptMethod entries"
        );
        ensure!(
            FUNCTIONS_TABLE_REFLECTION
                .get()
                .context("reflection method table unavailable")?
                .values()
                .filter(|candidate| candidate.0 == native_method.0)
                .count()
                == 1,
            "native method handle is shared by multiple reflection entries"
        );

        let (body_start, body_end, body) = exact_full_body(method, rva, image, bounds)?;
        ensure!(
            body_start == rva,
            "factory entry is not the .pdata function start"
        );
        let members = out.accessors(owner, &signature, &TypeCache::init(), image, bounds)?;
        let property_decisions = serde_json::to_value(std::mem::take(&mut out.property_decisions))
            .context("serialize factory property decisions")?;
        let members = members
            .into_iter()
            .map(factory_member)
            .collect::<Result<Vec<_>>>()?;

        Ok(CandidateProof {
            method,
            native_method,
            owner,
            owner_class,
            proto,
            proto_parameter_index,
            signature,
            rva,
            body_end,
            code: body.to_vec(),
            members,
            property_decisions,
        })
    })();

    checked.map_err(|error| {
        let text = format!("{error:#}");
        let stage = if text.contains("ScriptMethod")
            || text.contains("shared")
            || text.contains("native method")
            || text.contains(".pdata")
            || text.contains("body")
        {
            "native-entry-and-bounds"
        } else if text.contains("parameter") || text.contains("Proto") {
            "closed-proto-parameter"
        } else if text.contains("return") || text.contains("owner") {
            "owner-and-return"
        } else if text.contains("static") || text.contains("generic") {
            "method-shape"
        } else {
            "reflection-native-cross-check"
        };
        (stage, error)
    })
}

fn factory_member(accessor: Accessor) -> Result<FactoryMember> {
    Ok(FactoryMember {
        name: accessor.name,
        kind: accessor.kind,
        ty: accessor.ty,
        type_name: checked_name(accessor.ty.get_full_name()?)?,
        bytes: accessor.bytes,
        offset: accessor.offset,
        getter_rva: accessor.getter_rva,
        setter_rva: accessor.setter_rva,
        member_kind: accessor.member_kind,
    })
}

fn check_native_type(native: Il2CppType, reflected: RuntimeType, reason: &str) -> Result<()> {
    ensure!(native.0 != 0, "native type handle is null");
    memory::readable(native.0, 16)?;
    let reflected = reflected.get_il2cpp_type();
    ensure!(reflected.0 != 0, "reflection Il2CppType handle is null");
    memory::readable(reflected.0, 16)?;
    ensure!(il2cpp_type_equals(native, reflected), "{reason}");
    Ok(())
}

fn checked_rva(method: Il2CppMethod, image: &[u8]) -> Option<usize> {
    memory::readable(method.0, 16).ok()?;
    asm_address::module_rva(method.va(), *GA_BASE, image.len())
}

/// Return the exact current .pdata bounds and reject Script metadata entries
/// inside the native function. `native_body` is also checked for equality so
/// its executable-section/metadata validation remains part of the proof.
fn exact_full_body<'a>(
    method: MethodInfo,
    rva: usize,
    image: &'a [u8],
    bounds: &Bounds<'_>,
) -> Result<(usize, usize, &'a [u8])> {
    let function = Pe::new(image, memory::readable)?.function(rva)?;
    let (start, end) = (function.start, function.end);
    ensure!(start == rva, "method RVA is not an exact .pdata entry");
    ensure!(
        bounds
            .executable
            .iter()
            .any(|range| range.start <= start && end <= range.end),
        "complete .pdata function is not contained in one executable section"
    );
    ensure!(
        bounds
            .functions
            .containing(rva)
            .is_some_and(|range| range.end == end),
        "FunctionTable bounds disagree with exact .pdata end"
    );
    ensure!(
        !bounds
            .entries
            .iter()
            .any(|entry| start < *entry && *entry < end),
        "current ScriptMethod metadata entry falls inside factory function"
    );
    let (body_rva, body) = native_body(method.get_il2cpp_method(), image, bounds)?;
    ensure!(body_rva == start, "native_body returned a different RVA");
    ensure!(
        body.len() == end - start,
        "native_body silently truncated the complete .pdata function"
    );
    Ok((start, end, body))
}
