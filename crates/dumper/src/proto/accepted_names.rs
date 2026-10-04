use super::{
    names::{apply_type_names, field_name_key, identifier, protox_map_entry_name},
    output::{ProtoItem, TypeToItemMap, is_omitted_oneof_discriminator, short_name, snake_field},
};
use reflection::runtime_type::RuntimeType;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
    sync::LazyLock,
};

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV_REVERSE_OFFSET: u64 = 7_809_847_782_465_536_322;
const FNV_PRIME: u64 = 1_099_511_628_211;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ItemKind {
    Message,
    Enum,
}

impl ItemKind {
    fn marker(self) -> char {
        match self {
            Self::Message => 'M',
            Self::Enum => 'E',
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Enum => "enum",
        }
    }
}

#[derive(Clone, Debug)]
enum TypeExpr {
    Scalar(String),
    Repeated(Box<TypeExpr>),
    Optional(Box<TypeExpr>),
    Map(Box<TypeExpr>, Box<TypeExpr>),
    Ref(RuntimeType),
    Unknown(String),
}

impl TypeExpr {
    fn references(&self, result: &mut Vec<RuntimeType>) {
        match self {
            Self::Repeated(inner) | Self::Optional(inner) => inner.references(result),
            Self::Map(key, value) => {
                key.references(result);
                value.references(result);
            }
            Self::Ref(runtime_type) => result.push(*runtime_type),
            Self::Scalar(_) | Self::Unknown(_) => {}
        }
    }

    fn render(
        &self,
        labels: Option<&HashMap<RuntimeType, String>>,
        kinds: &HashMap<RuntimeType, ItemKind>,
        self_target: Option<RuntimeType>,
    ) -> String {
        match self {
            Self::Scalar(name) => format!("S:{name}"),
            Self::Repeated(inner) => {
                format!("R({})", inner.render(labels, kinds, self_target))
            }
            Self::Optional(inner) => {
                format!("O({})", inner.render(labels, kinds, self_target))
            }
            Self::Map(key, value) => format!(
                "K({},{})",
                key.render(labels, kinds, self_target),
                value.render(labels, kinds, self_target)
            ),
            Self::Ref(runtime_type) if Some(*runtime_type) == self_target => "@SELF".into(),
            Self::Ref(runtime_type) => {
                let marker = kinds
                    .get(runtime_type)
                    .copied()
                    .unwrap_or(ItemKind::Message)
                    .marker();
                let label = labels
                    .and_then(|labels| labels.get(runtime_type))
                    .cloned()
                    .unwrap_or_else(|| marker.to_string());
                format!("@{marker}:{label}")
            }
            Self::Unknown(name) => format!("U:{name}"),
        }
    }
}

#[derive(Clone, Debug)]
struct FieldBuild {
    tag: u32,
    expr: TypeExpr,
    oneof_tags: Vec<u32>,
}

#[derive(Clone, Debug)]
struct NodeBuild {
    kind: ItemKind,
    raw_path: String,
    display_path: String,
    parent: Option<RuntimeType>,
    children: Vec<RuntimeType>,
    fields: Vec<FieldBuild>,
    oneof_groups: Vec<Vec<u32>>,
    enum_values: Vec<i32>,
    cmd_id: u16,
    write_to_rva: usize,
    merge_from_rva: usize,
}

#[derive(Clone, Debug)]
struct IncomingEdge {
    source: RuntimeType,
    tag: u32,
    oneof_tags: Vec<u32>,
    expr: TypeExpr,
    target: RuntimeType,
}

#[derive(Clone, Debug)]
struct FieldShape {
    shape: String,
    oneof_tags: Vec<u32>,
}

#[derive(Clone, Debug)]
struct NodeShape {
    kind: ItemKind,
    raw_path: String,
    display_path: String,
    shape: String,
    fingerprint: String,
    fields: BTreeMap<u32, FieldShape>,
    parent: Option<RuntimeType>,
    cmd_id: u16,
    write_to_rva: usize,
    merge_from_rva: usize,
}

#[derive(Clone, Debug)]
struct StructuralGraph {
    nodes: HashMap<RuntimeType, NodeShape>,
}

#[derive(Debug, Deserialize)]
struct AcceptedManifest {
    schema_version: u32,
    dataset_id: String,
    fingerprint_rounds: usize,
    #[serde(default)]
    source: serde_json::Value,
    types: Vec<AcceptedType>,
    #[serde(default)]
    packets: Vec<AcceptedPacket>,
}

#[derive(Debug, Deserialize)]
struct AcceptedType {
    canonical: String,
    kind: String,
    shape: String,
    fingerprint: String,
    cmd_id: Option<u16>,
    #[serde(default)]
    write_to_rva: usize,
    #[serde(default)]
    merge_from_rva: usize,
    accepted_name: Option<String>,
    #[serde(default)]
    fields: Vec<AcceptedField>,
    #[serde(default)]
    oneofs: Vec<AcceptedOneof>,
    #[serde(default)]
    variants: Vec<AcceptedVariant>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AliasAction {
    Alias,
    OverrideExact,
}

#[derive(Debug, Deserialize)]
struct AcceptedField {
    tag: u32,
    shape: String,
    #[serde(default)]
    oneof_tags: Vec<u32>,
    expected: String,
    accepted: String,
    action: AliasAction,
}

#[derive(Debug, Deserialize)]
struct AcceptedOneof {
    member_tags: Vec<u32>,
    expected: String,
    accepted: String,
    action: AliasAction,
}

#[derive(Debug, Deserialize)]
struct AcceptedVariant {
    number: i32,
    expected: String,
    accepted: String,
    action: AliasAction,
}

#[derive(Debug, Deserialize)]
struct AcceptedPacket {
    cmd_id: i32,
    type_canonical: String,
    type_fingerprint: String,
    accepted_name: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ApplicationReport {
    schema_version: u32,
    dataset_id: String,
    fingerprint_rounds: usize,
    source: serde_json::Value,
    matches: Vec<String>,
    applied: Vec<String>,
    already_present: Vec<String>,
    unresolved: Vec<String>,
    ambiguous: Vec<String>,
    conflicts: Vec<String>,
}

pub(super) struct AcceptedApplication {
    pub(super) report: ApplicationReport,
    pub(super) type_aliases: HashMap<String, String>,
}

impl ApplicationReport {
    fn new(manifest: &AcceptedManifest) -> Self {
        Self {
            schema_version: manifest.schema_version,
            dataset_id: manifest.dataset_id.clone(),
            fingerprint_rounds: manifest.fingerprint_rounds,
            source: manifest.source.clone(),
            matches: Vec::new(),
            applied: Vec::new(),
            already_present: Vec::new(),
            unresolved: Vec::new(),
            ambiguous: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    fn finish(&mut self) {
        for rows in [
            &mut self.matches,
            &mut self.applied,
            &mut self.already_present,
            &mut self.unresolved,
            &mut self.ambiguous,
            &mut self.conflicts,
        ] {
            rows.sort();
            rows.dedup();
        }
    }
}

fn fnv1a(bytes: impl IntoIterator<Item = u8>, seed: u64) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn hash_pair(value: &str) -> String {
    let bytes = value.as_bytes();
    format!(
        "{:016x}{:016x}",
        fnv1a(bytes.iter().copied(), FNV_OFFSET),
        fnv1a(bytes.iter().rev().copied(), FNV_REVERSE_OFFSET)
    )
}

fn scalar(name: &str) -> bool {
    matches!(
        name,
        "double"
            | "float"
            | "int32"
            | "int64"
            | "uint32"
            | "uint64"
            | "sint32"
            | "sint64"
            | "fixed32"
            | "fixed64"
            | "sfixed32"
            | "sfixed64"
            | "bool"
            | "string"
            | "bytes"
            | "google.protobuf.Any"
    )
}

fn clean_type_token(token: &str) -> &str {
    token
        .strip_prefix('.')
        .unwrap_or(token)
        .strip_prefix("Proto.")
        .or_else(|| token.strip_prefix("proto."))
        .unwrap_or(token.strip_prefix('.').unwrap_or(token))
}

fn split_map(value: &str) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    for (index, ch) in value.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return Some((&value[..index], &value[index + 1..])),
            _ => {}
        }
    }
    None
}

fn unique_alias(
    aliases: &HashMap<String, Vec<RuntimeType>>,
    candidate: &str,
) -> Option<RuntimeType> {
    let candidates = aliases.get(candidate)?;
    (candidates.len() == 1).then_some(candidates[0])
}

fn resolve_type(
    owner: RuntimeType,
    token: &str,
    aliases: &HashMap<String, Vec<RuntimeType>>,
    parents: &HashMap<RuntimeType, RuntimeType>,
    raw_paths: &HashMap<RuntimeType, String>,
    display_paths: &HashMap<RuntimeType, String>,
) -> Option<RuntimeType> {
    let token = clean_type_token(token);
    if token.contains('.') {
        if let Some(runtime_type) = unique_alias(aliases, token) {
            return Some(runtime_type);
        }
        if aliases.get(token).is_some() {
            return None;
        }
    }

    let mut scope = Some(owner);
    while let Some(runtime_type) = scope {
        for paths in [raw_paths, display_paths] {
            let candidate = format!("{}.{}", paths.get(&runtime_type)?, token);
            if let Some(resolved) = unique_alias(aliases, &candidate) {
                return Some(resolved);
            }
            if aliases.get(&candidate).is_some() {
                return None;
            }
        }
        scope = parents.get(&runtime_type).copied();
    }
    unique_alias(aliases, token)
}

fn parse_type_expr(
    owner: RuntimeType,
    kind: &str,
    aliases: &HashMap<String, Vec<RuntimeType>>,
    parents: &HashMap<RuntimeType, RuntimeType>,
    raw_paths: &HashMap<RuntimeType, String>,
    display_paths: &HashMap<RuntimeType, String>,
) -> TypeExpr {
    let kind = kind.trim();
    if let Some(inner) = kind.strip_prefix("repeated ") {
        return TypeExpr::Repeated(Box::new(parse_type_expr(
            owner,
            inner,
            aliases,
            parents,
            raw_paths,
            display_paths,
        )));
    }
    if let Some(inner) = kind.strip_prefix("optional ") {
        return TypeExpr::Optional(Box::new(parse_type_expr(
            owner,
            inner,
            aliases,
            parents,
            raw_paths,
            display_paths,
        )));
    }
    if let Some(inner) = kind
        .strip_prefix("map<")
        .and_then(|value| value.strip_suffix('>'))
        && let Some((key, value)) = split_map(inner)
    {
        return TypeExpr::Map(
            Box::new(parse_type_expr(
                owner,
                key.trim(),
                aliases,
                parents,
                raw_paths,
                display_paths,
            )),
            Box::new(parse_type_expr(
                owner,
                value.trim(),
                aliases,
                parents,
                raw_paths,
                display_paths,
            )),
        );
    }
    let token = clean_type_token(kind);
    if scalar(token) {
        TypeExpr::Scalar(token.to_owned())
    } else if let Some(runtime_type) =
        resolve_type(owner, token, aliases, parents, raw_paths, display_paths)
    {
        TypeExpr::Ref(runtime_type)
    } else {
        TypeExpr::Unknown(token.to_owned())
    }
}

fn path_for(
    runtime_type: RuntimeType,
    parents: &HashMap<RuntimeType, RuntimeType>,
    local_names: &HashMap<RuntimeType, String>,
    memo: &mut HashMap<RuntimeType, String>,
) -> String {
    if let Some(path) = memo.get(&runtime_type) {
        return path.clone();
    }
    let local = local_names[&runtime_type].clone();
    let path = parents
        .get(&runtime_type)
        .map(|parent| {
            format!(
                "{}.{}",
                path_for(*parent, parents, local_names, memo),
                local
            )
        })
        .unwrap_or(local);
    memo.insert(runtime_type, path.clone());
    path
}

fn build_graph(items: &TypeToItemMap, rounds: usize) -> Result<StructuralGraph, String> {
    if items.is_empty() {
        return Err("accepted-name structural graph is empty".into());
    }
    let runtime_by_ptr: HashMap<usize, RuntimeType> = items
        .iter()
        .map(|(runtime_type, item)| (Rc::as_ptr(item) as usize, *runtime_type))
        .collect();
    let mut omitted = HashSet::new();
    for item in items.values() {
        let item = item.borrow();
        let ProtoItem::Message(message) = &*item else {
            continue;
        };
        for child in &message.children {
            let child_item = child.borrow();
            if is_omitted_oneof_discriminator(message, &child_item) {
                let child_runtime = runtime_by_ptr
                    .get(&(Rc::as_ptr(child) as usize))
                    .copied()
                    .ok_or_else(|| {
                        format!("child of {} is absent from TypeToItemMap", message.name)
                    })?;
                omitted.insert(child_runtime);
            }
        }
    }
    let mut parents = HashMap::new();
    let mut children: HashMap<RuntimeType, Vec<RuntimeType>> = HashMap::new();
    let mut kinds = HashMap::new();
    let mut raw_locals = HashMap::new();
    let mut display_locals = HashMap::new();

    for (runtime_type, item) in items {
        if omitted.contains(runtime_type) {
            continue;
        }
        match &*item.borrow() {
            ProtoItem::Message(message) => {
                kinds.insert(*runtime_type, ItemKind::Message);
                raw_locals.insert(*runtime_type, short_name(&message.name).to_owned());
                display_locals.insert(
                    *runtime_type,
                    short_name(
                        message
                            .deobfuscated_name
                            .as_deref()
                            .unwrap_or(&message.name),
                    )
                    .to_owned(),
                );
                for child in &message.children {
                    let child_runtime = runtime_by_ptr
                        .get(&(Rc::as_ptr(child) as usize))
                        .copied()
                        .ok_or_else(|| {
                            format!("child of {} is absent from TypeToItemMap", message.name)
                        })?;
                    if omitted.contains(&child_runtime) {
                        continue;
                    }
                    if let Some(previous) = parents.insert(child_runtime, *runtime_type)
                        && previous != *runtime_type
                    {
                        return Err(format!(
                            "runtime type {:?} has multiple structural parents",
                            child_runtime
                        ));
                    }
                    children
                        .entry(*runtime_type)
                        .or_default()
                        .push(child_runtime);
                }
            }
            ProtoItem::Enum(enumeration) => {
                kinds.insert(*runtime_type, ItemKind::Enum);
                raw_locals.insert(*runtime_type, short_name(&enumeration.name).to_owned());
                display_locals.insert(
                    *runtime_type,
                    short_name(
                        enumeration
                            .deobfuscated_name
                            .as_deref()
                            .unwrap_or(&enumeration.name),
                    )
                    .to_owned(),
                );
            }
        }
    }

    let mut raw_paths = HashMap::new();
    let mut display_paths = HashMap::new();
    for runtime_type in items.keys() {
        if omitted.contains(runtime_type) {
            continue;
        }
        path_for(*runtime_type, &parents, &raw_locals, &mut raw_paths);
        path_for(*runtime_type, &parents, &display_locals, &mut display_paths);
    }

    let mut aliases: HashMap<String, Vec<RuntimeType>> = HashMap::new();
    for (runtime_type, item) in items {
        if omitted.contains(runtime_type) {
            continue;
        }
        let mut candidates = vec![
            raw_locals[runtime_type].clone(),
            display_locals[runtime_type].clone(),
            raw_paths[runtime_type].clone(),
            display_paths[runtime_type].clone(),
        ];
        match &*item.borrow() {
            ProtoItem::Message(message) => candidates.push(clean_type_token(&message.name).into()),
            ProtoItem::Enum(enumeration) => {
                candidates.push(clean_type_token(&enumeration.name).into())
            }
        }
        candidates.sort();
        candidates.dedup();
        for candidate in candidates {
            let entries = aliases.entry(candidate).or_default();
            if !entries.contains(runtime_type) {
                entries.push(*runtime_type);
            }
        }
    }

    let mut builds = HashMap::new();
    for (runtime_type, item) in items {
        if omitted.contains(runtime_type) {
            continue;
        }
        let item = item.borrow();
        let build = match &*item {
            ProtoItem::Message(message) => {
                let mut group_by_tag = HashMap::<u32, Vec<u32>>::new();
                let mut oneof_groups = Vec::new();
                for oneof in &message.oneofs {
                    let mut tags = oneof
                        .fields
                        .iter()
                        .map(|field| field.number)
                        .collect::<Vec<_>>();
                    tags.sort_unstable();
                    tags.dedup();
                    for tag in &tags {
                        group_by_tag.insert(*tag, tags.clone());
                    }
                    oneof_groups.push(tags);
                }
                oneof_groups.sort();
                let mut fields = Vec::new();
                for field in message
                    .fields
                    .iter()
                    .chain(message.oneofs.iter().flat_map(|oneof| oneof.fields.iter()))
                {
                    fields.push(FieldBuild {
                        tag: field.number,
                        expr: parse_type_expr(
                            *runtime_type,
                            &field.kind,
                            &aliases,
                            &parents,
                            &raw_paths,
                            &display_paths,
                        ),
                        oneof_tags: group_by_tag.get(&field.number).cloned().unwrap_or_default(),
                    });
                }
                fields.sort_by_key(|field| field.tag);
                NodeBuild {
                    kind: ItemKind::Message,
                    raw_path: raw_paths[runtime_type].clone(),
                    display_path: display_paths[runtime_type].clone(),
                    parent: parents.get(runtime_type).copied(),
                    children: children.get(runtime_type).cloned().unwrap_or_default(),
                    fields,
                    oneof_groups,
                    enum_values: Vec::new(),
                    cmd_id: message.cmd_id,
                    write_to_rva: message.write_to_rva,
                    merge_from_rva: message.merge_from_rva,
                }
            }
            ProtoItem::Enum(enumeration) => {
                let mut enum_values = enumeration
                    .variants
                    .iter()
                    .map(|(_, number)| *number)
                    .collect::<Vec<_>>();
                enum_values.sort_unstable();
                NodeBuild {
                    kind: ItemKind::Enum,
                    raw_path: raw_paths[runtime_type].clone(),
                    display_path: display_paths[runtime_type].clone(),
                    parent: parents.get(runtime_type).copied(),
                    children: children.get(runtime_type).cloned().unwrap_or_default(),
                    fields: Vec::new(),
                    oneof_groups: Vec::new(),
                    enum_values,
                    cmd_id: 0,
                    write_to_rva: 0,
                    merge_from_rva: 0,
                }
            }
        };
        builds.insert(*runtime_type, build);
    }

    let mut incoming: HashMap<RuntimeType, Vec<IncomingEdge>> = HashMap::new();
    for (source, node) in &builds {
        for field in &node.fields {
            let mut references = Vec::new();
            field.expr.references(&mut references);
            for target in references {
                incoming.entry(target).or_default().push(IncomingEdge {
                    source: *source,
                    tag: field.tag,
                    oneof_tags: field.oneof_tags.clone(),
                    expr: field.expr.clone(),
                    target,
                });
            }
        }
    }

    fn tags(tags: &[u32]) -> String {
        tags.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn representation(
        runtime_type: RuntimeType,
        node: &NodeBuild,
        labels: Option<&HashMap<RuntimeType, String>>,
        kinds: &HashMap<RuntimeType, ItemKind>,
        incoming: &HashMap<RuntimeType, Vec<IncomingEdge>>,
    ) -> String {
        let label = |target: RuntimeType| {
            let marker = kinds[&target].marker();
            let value = labels
                .and_then(|labels| labels.get(&target))
                .cloned()
                .unwrap_or_else(|| marker.to_string());
            format!("{marker}:{value}")
        };
        let parent = node.parent.map(&label).unwrap_or_else(|| "-".into());
        let mut children = node
            .children
            .iter()
            .map(|child| label(*child))
            .collect::<Vec<_>>();
        children.sort();
        let mut incoming_edges = incoming
            .get(&runtime_type)
            .into_iter()
            .flatten()
            .map(|edge| {
                format!(
                    "{}:{}:o={}:t={}",
                    label(edge.source),
                    edge.tag,
                    tags(&edge.oneof_tags),
                    edge.expr.render(labels, kinds, Some(edge.target))
                )
            })
            .collect::<Vec<_>>();
        incoming_edges.sort();
        let core = match node.kind {
            ItemKind::Message => {
                let fields = node
                    .fields
                    .iter()
                    .map(|field| {
                        format!(
                            "{}:{}:o={}",
                            field.tag,
                            field.expr.render(labels, kinds, None),
                            tags(&field.oneof_tags)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                let groups = node
                    .oneof_groups
                    .iter()
                    .map(|group| tags(group))
                    .collect::<Vec<_>>()
                    .join(";");
                format!("M|g={groups}|f={fields}")
            }
            ItemKind::Enum => format!(
                "E|v={}",
                node.enum_values
                    .iter()
                    .map(i32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        };
        format!(
            "{core}|p={parent}|c={}|in={}",
            children.join(";"),
            incoming_edges.join(";")
        )
    }

    let mut labels = builds
        .iter()
        .map(|(runtime_type, node)| {
            (
                *runtime_type,
                hash_pair(&representation(
                    *runtime_type,
                    node,
                    None,
                    &kinds,
                    &incoming,
                )),
            )
        })
        .collect::<HashMap<_, _>>();
    for _ in 0..rounds {
        labels = builds
            .iter()
            .map(|(runtime_type, node)| {
                (
                    *runtime_type,
                    hash_pair(&representation(
                        *runtime_type,
                        node,
                        Some(&labels),
                        &kinds,
                        &incoming,
                    )),
                )
            })
            .collect();
    }

    let mut nodes = HashMap::new();
    for (runtime_type, node) in builds {
        let shape = representation(runtime_type, &node, Some(&labels), &kinds, &incoming);
        let fields = node
            .fields
            .iter()
            .map(|field| {
                (
                    field.tag,
                    FieldShape {
                        shape: format!(
                            "{}|o={}",
                            field.expr.render(Some(&labels), &kinds, None),
                            tags(&field.oneof_tags)
                        ),
                        oneof_tags: field.oneof_tags.clone(),
                    },
                )
            })
            .collect();
        nodes.insert(
            runtime_type,
            NodeShape {
                kind: node.kind,
                raw_path: node.raw_path,
                display_path: node.display_path,
                fingerprint: hash_pair(&shape),
                shape,
                fields,
                parent: node.parent,
                cmd_id: node.cmd_id,
                write_to_rva: node.write_to_rva,
                merge_from_rva: node.merge_from_rva,
            },
        );
    }
    Ok(StructuralGraph { nodes })
}

fn is_obfuscated(name: &str) -> bool {
    name.len() == 11 && name.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn is_generated_obfuscated(name: &str) -> bool {
    is_obfuscated(name)
        || (name.split('_').any(is_obfuscated)
            && name
                .bytes()
                .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase()))
}

fn current_type_name(item: &ProtoItem) -> &str {
    match item {
        ProtoItem::Message(message) => short_name(
            message
                .deobfuscated_name
                .as_deref()
                .unwrap_or(&message.name),
        ),
        ProtoItem::Enum(enumeration) => short_name(
            enumeration
                .deobfuscated_name
                .as_deref()
                .unwrap_or(&enumeration.name),
        ),
    }
}

fn alias_allowed(current: &str, expected: &str, action: AliasAction, generated: bool) -> bool {
    match action {
        AliasAction::Alias => {
            if generated {
                is_generated_obfuscated(current)
            } else {
                is_obfuscated(current)
            }
        }
        AliasAction::OverrideExact => current == expected,
    }
}

fn validate_manifest(manifest: &AcceptedManifest) -> Result<(), String> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "unsupported accepted-name manifest schema {}",
            manifest.schema_version
        ));
    }
    if manifest.dataset_id.trim().is_empty() {
        return Err("accepted-name manifest dataset_id is empty".into());
    }
    if manifest.fingerprint_rounds > 64 {
        return Err("accepted-name manifest fingerprint_rounds exceeds 64".into());
    }
    let mut canonicals = HashSet::new();
    for record in &manifest.types {
        if !canonicals.insert(record.canonical.as_str()) {
            return Err(format!("duplicate accepted type {}", record.canonical));
        }
        if !matches!(record.kind.as_str(), "message" | "enum") {
            return Err(format!(
                "invalid accepted type kind {} for {}",
                record.kind, record.canonical
            ));
        }
        if record.fingerprint != hash_pair(&record.shape) {
            return Err(format!(
                "accepted type fingerprint mismatch for {}",
                record.canonical
            ));
        }
        if let Some(name) = &record.accepted_name
            && !identifier(name)
        {
            return Err(format!(
                "invalid accepted type identifier {name} for {}",
                record.canonical
            ));
        }
        let mut field_tags = HashSet::new();
        for field in &record.fields {
            if !field_tags.insert(field.tag) {
                return Err(format!(
                    "duplicate accepted field tag {} for {}",
                    field.tag, record.canonical
                ));
            }
            if !identifier(&field.accepted) {
                return Err(format!(
                    "invalid accepted field identifier {} for {} tag {}",
                    field.accepted, record.canonical, field.tag
                ));
            }
            if !field.oneof_tags.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(format!(
                    "unsorted/duplicate oneof tags for {} tag {}",
                    record.canonical, field.tag
                ));
            }
        }
        let mut oneofs = HashSet::new();
        for oneof in &record.oneofs {
            if !oneof.member_tags.windows(2).all(|pair| pair[0] < pair[1])
                || !oneofs.insert(oneof.member_tags.clone())
            {
                return Err(format!(
                    "invalid/duplicate accepted oneof for {}",
                    record.canonical
                ));
            }
            if !identifier(&oneof.accepted) {
                return Err(format!(
                    "invalid accepted oneof identifier {} for {}",
                    oneof.accepted, record.canonical
                ));
            }
        }
        let mut variants = HashSet::new();
        for variant in &record.variants {
            if !variants.insert(variant.number) {
                return Err(format!(
                    "duplicate accepted enum variant {} for {}",
                    variant.number, record.canonical
                ));
            }
            if !identifier(&variant.accepted) {
                return Err(format!(
                    "invalid accepted enum variant {} for {}",
                    variant.accepted, record.canonical
                ));
            }
        }
    }
    let mut packet_ids = HashSet::new();
    let mut packet_names = HashSet::new();
    for packet in &manifest.packets {
        if !packet_ids.insert(packet.cmd_id) {
            return Err(format!("duplicate accepted packet ID {}", packet.cmd_id));
        }
        if !packet_names.insert(packet.accepted_name.as_str()) {
            return Err(format!(
                "duplicate accepted packet name {}",
                packet.accepted_name
            ));
        }
        let Some(record) = manifest
            .types
            .iter()
            .find(|record| record.canonical == packet.type_canonical)
        else {
            return Err(format!(
                "accepted packet {} refers to missing type {}",
                packet.cmd_id, packet.type_canonical
            ));
        };
        if record.kind != "message" || record.fingerprint != packet.type_fingerprint {
            return Err(format!(
                "accepted packet {} type guard mismatch",
                packet.cmd_id
            ));
        }
    }
    Ok(())
}

fn field_entry<'a>(
    message: &'a super::output::Message,
    tag: u32,
) -> Option<&'a super::output::Field> {
    message
        .fields
        .iter()
        .chain(message.oneofs.iter().flat_map(|oneof| oneof.fields.iter()))
        .find(|field| field.number == tag)
}

fn field_entry_mut<'a>(
    message: &'a mut super::output::Message,
    tag: u32,
) -> Option<&'a mut super::output::Field> {
    message
        .fields
        .iter_mut()
        .chain(
            message
                .oneofs
                .iter_mut()
                .flat_map(|oneof| oneof.fields.iter_mut()),
        )
        .find(|field| field.number == tag)
}

fn apply_field_records(
    items: &mut TypeToItemMap,
    graph: &StructuralGraph,
    future_symbols: &HashMap<(Option<RuntimeType>, String), usize>,
    runtime_type: RuntimeType,
    record: &AcceptedType,
    report: &mut ApplicationReport,
) {
    let Some(item) = items.get(&runtime_type) else {
        return;
    };
    let mut item = item.borrow_mut();
    let ProtoItem::Message(message) = &mut *item else {
        if !record.fields.is_empty() || !record.oneofs.is_empty() {
            report.conflicts.push(format!(
                "type={} reason=field-record-on-enum",
                record.canonical
            ));
        }
        return;
    };

    let mut proposals = HashMap::<u32, (&AcceptedField, String)>::new();
    for accepted in &record.fields {
        let identity = format!("field={}:tag={}", record.canonical, accepted.tag);
        let Some(structural) = graph.nodes[&runtime_type].fields.get(&accepted.tag) else {
            report
                .unresolved
                .push(format!("{identity} reason=tag-not-found"));
            continue;
        };
        if structural.shape != accepted.shape || structural.oneof_tags != accepted.oneof_tags {
            report
                .conflicts
                .push(format!("{identity} reason=field-shape-mismatch"));
            continue;
        }
        let Some(field) = field_entry(message, accepted.tag) else {
            report
                .unresolved
                .push(format!("{identity} reason=tag-not-found"));
            continue;
        };
        if field.name == accepted.accepted {
            report.already_present.push(identity);
            continue;
        }
        if !alias_allowed(&field.name, &accepted.expected, accepted.action, false) {
            report.conflicts.push(format!(
                "{identity} reason=current-readable current={} expected={} accepted={}",
                field.name, accepted.expected, accepted.accepted
            ));
            continue;
        }
        proposals.insert(accepted.tag, (accepted, field.name.clone()));
    }

    let originals = message
        .fields
        .iter()
        .chain(message.oneofs.iter().flat_map(|oneof| oneof.fields.iter()))
        .map(|field| (field.number, field.name.clone(), field.kind.clone()))
        .collect::<Vec<_>>();
    let mut proposed = originals
        .iter()
        .map(|(tag, name, _)| {
            (
                *tag,
                proposals
                    .get(tag)
                    .map(|(accepted, _)| accepted.accepted.clone())
                    .unwrap_or_else(|| name.clone()),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut reserved = message
        .oneofs
        .iter()
        .map(|oneof| snake_field(oneof.name.strip_suffix("Case").unwrap_or(&oneof.name)))
        .collect::<HashSet<_>>();
    for child in &message.children {
        reserved.insert(current_type_name(&child.borrow()).to_owned());
        if let ProtoItem::Enum(enumeration) = &*child.borrow() {
            reserved.extend(enumeration.variants.iter().map(|(name, _)| name.clone()));
        }
    }

    loop {
        let mut counts = HashMap::<String, usize>::new();
        for name in proposed.values() {
            *counts
                .entry(field_name_key(&snake_field(name)))
                .or_default() += 1;
        }
        let mut changed = false;
        for (tag, original, kind) in &originals {
            let Some((accepted, _)) = proposals.get(tag) else {
                continue;
            };
            let candidate = &proposed[tag];
            if candidate == original {
                continue;
            }
            let display = snake_field(candidate);
            let map_entry_conflict =
                kind.starts_with("map<") && reserved.contains(&protox_map_entry_name(&display));
            if !identifier(&display)
                || counts[&field_name_key(&display)] > 1
                || reserved.contains(&display)
                || future_symbols
                    .get(&(Some(runtime_type), display.clone()))
                    .copied()
                    .unwrap_or_default()
                    > 1
                || map_entry_conflict
            {
                proposed.insert(*tag, original.clone());
                report.conflicts.push(format!(
                    "field={}:tag={} reason=invalid-or-conflicting accepted={}",
                    record.canonical, tag, accepted.accepted
                ));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for (tag, (accepted, original)) in proposals {
        let final_name = proposed[&tag].clone();
        if final_name == accepted.accepted {
            if let Some(field) = field_entry_mut(message, tag) {
                field.name = final_name;
                report
                    .applied
                    .push(format!("field={}:tag={tag}", record.canonical));
            }
        } else if final_name == original {
            // A detailed rejection was already recorded above.
        }
    }

    let mut symbols = message
        .fields
        .iter()
        .chain(message.oneofs.iter().flat_map(|oneof| oneof.fields.iter()))
        .map(|field| snake_field(&field.name))
        .collect::<HashSet<_>>();
    symbols.extend(reserved);
    for accepted in &record.oneofs {
        let identity = format!(
            "oneof={}:tags={}",
            record.canonical,
            accepted
                .member_tags
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let matches = message
            .oneofs
            .iter()
            .enumerate()
            .filter(|(_, oneof)| {
                let mut tags = oneof
                    .fields
                    .iter()
                    .map(|field| field.number)
                    .collect::<Vec<_>>();
                tags.sort_unstable();
                tags.dedup();
                tags == accepted.member_tags
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            report.unresolved.push(format!(
                "{identity} reason=group-match-count count={}",
                matches.len()
            ));
            continue;
        }
        let index = matches[0];
        let current = snake_field(
            message.oneofs[index]
                .name
                .strip_suffix("Case")
                .unwrap_or(&message.oneofs[index].name),
        );
        if current == accepted.accepted {
            report.already_present.push(identity);
            continue;
        }
        let expected = snake_field(
            accepted
                .expected
                .strip_suffix("Case")
                .unwrap_or(&accepted.expected),
        );
        if !alias_allowed(&current, &expected, accepted.action, false) {
            report.conflicts.push(format!(
                "{identity} reason=current-readable current={current} expected={expected}"
            ));
            continue;
        }
        let display = snake_field(
            accepted
                .accepted
                .strip_suffix("Case")
                .unwrap_or(&accepted.accepted),
        );
        if !identifier(&display)
            || symbols.contains(&display)
            || future_symbols
                .get(&(Some(runtime_type), display.clone()))
                .copied()
                .unwrap_or_default()
                > 1
        {
            report
                .conflicts
                .push(format!("{identity} reason=invalid-or-conflicting"));
            continue;
        }
        symbols.remove(&current);
        symbols.insert(display);
        message.oneofs[index].name = accepted.accepted.clone();
        report.applied.push(identity);
    }
}

fn current_scope_symbols(
    items: &TypeToItemMap,
    graph: &StructuralGraph,
    scope: Option<RuntimeType>,
    excluded_variant: (RuntimeType, usize),
) -> HashSet<String> {
    let mut symbols = HashSet::new();
    if let Some(owner) = scope
        && let Some(item) = items.get(&owner)
        && let ProtoItem::Message(message) = &*item.borrow()
    {
        for field in message
            .fields
            .iter()
            .chain(message.oneofs.iter().flat_map(|oneof| oneof.fields.iter()))
        {
            let display = snake_field(&field.name);
            symbols.insert(display.clone());
            if field.kind.starts_with("map<") {
                symbols.insert(protox_map_entry_name(&display));
            }
        }
        for oneof in &message.oneofs {
            symbols.insert(snake_field(
                oneof.name.strip_suffix("Case").unwrap_or(&oneof.name),
            ));
        }
    }

    for (runtime_type, node) in &graph.nodes {
        if node.parent != scope {
            continue;
        }
        let item = items[runtime_type].borrow();
        symbols.insert(current_type_name(&item).to_owned());
        if let ProtoItem::Enum(enumeration) = &*item {
            for (index, (name, _)) in enumeration.variants.iter().enumerate() {
                if (*runtime_type, index) != excluded_variant {
                    symbols.insert(name.clone());
                }
            }
        }
    }
    symbols
}

fn future_scope_symbol_counts(
    manifest: &AcceptedManifest,
    matched: &HashMap<String, RuntimeType>,
    graph: &StructuralGraph,
) -> HashMap<(Option<RuntimeType>, String), usize> {
    let mut result = HashMap::new();
    let mut add = |scope, name: String| {
        *result.entry((scope, name)).or_default() += 1;
    };
    for record in &manifest.types {
        let Some(runtime_type) = matched.get(&record.canonical).copied() else {
            continue;
        };
        if let Some(name) = &record.accepted_name {
            add(
                graph.nodes[&runtime_type].parent,
                short_name(name).to_owned(),
            );
        }
        for field in &record.fields {
            add(Some(runtime_type), snake_field(&field.accepted));
        }
        for oneof in &record.oneofs {
            add(
                Some(runtime_type),
                snake_field(
                    oneof
                        .accepted
                        .strip_suffix("Case")
                        .unwrap_or(&oneof.accepted),
                ),
            );
        }
        for variant in &record.variants {
            add(graph.nodes[&runtime_type].parent, variant.accepted.clone());
        }
    }
    result
}

fn apply_variant_records(
    items: &mut TypeToItemMap,
    graph: &StructuralGraph,
    future_symbols: &HashMap<(Option<RuntimeType>, String), usize>,
    runtime_type: RuntimeType,
    record: &AcceptedType,
    report: &mut ApplicationReport,
) {
    if record.variants.is_empty() {
        return;
    }
    let Some(item) = items.get(&runtime_type) else {
        return;
    };
    let original = {
        let item = item.borrow();
        let ProtoItem::Enum(enumeration) = &*item else {
            report.conflicts.push(format!(
                "type={} reason=variant-record-on-message",
                record.canonical
            ));
            return;
        };
        enumeration.variants.clone()
    };
    let mut proposed = original
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let mut proposal_indices = Vec::new();
    for accepted in &record.variants {
        let identity = format!("variant={}:number={}", record.canonical, accepted.number);
        let matches = original
            .iter()
            .enumerate()
            .filter(|(_, (_, number))| *number == accepted.number)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            report.conflicts.push(format!(
                "{identity} reason=duplicate-runtime-enum-number count={}",
                matches.len()
            ));
            continue;
        }
        let index = matches[0];
        let current = &original[index].0;
        if current == &accepted.accepted {
            report.already_present.push(identity);
            continue;
        }
        if !alias_allowed(current, &accepted.expected, accepted.action, true) {
            report.conflicts.push(format!(
                "{identity} reason=current-readable current={current} expected={}",
                accepted.expected
            ));
            continue;
        }
        let scope = graph.nodes[&runtime_type].parent;
        let current_symbols = current_scope_symbols(items, graph, scope, (runtime_type, index));
        let future_count = future_symbols
            .get(&(scope, accepted.accepted.clone()))
            .copied()
            .unwrap_or_default();
        if current_symbols.contains(&accepted.accepted) || future_count > 1 {
            report
                .conflicts
                .push(format!("{identity} reason=scope-collision"));
            continue;
        }
        proposed[index] = accepted.accepted.clone();
        proposal_indices.push((index, accepted, identity));
    }
    let counts = proposed
        .iter()
        .fold(HashMap::<String, usize>::new(), |mut map, name| {
            *map.entry(name.clone()).or_default() += 1;
            map
        });
    let mut item = item.borrow_mut();
    let ProtoItem::Enum(enumeration) = &mut *item else {
        return;
    };
    for (index, accepted, identity) in proposal_indices {
        if identifier(&proposed[index]) && counts[&proposed[index]] == 1 {
            enumeration.variants[index].0 = proposed[index].clone();
            report.applied.push(identity);
        } else {
            report.conflicts.push(format!(
                "variant={}:number={} reason=invalid-or-conflicting",
                record.canonical, accepted.number
            ));
        }
    }
}

fn current_type_scope_symbols(
    items: &TypeToItemMap,
    graph: &StructuralGraph,
    runtime_type: RuntimeType,
) -> HashSet<String> {
    let scope = graph.nodes[&runtime_type].parent;
    let mut symbols = HashSet::new();
    if let Some(owner) = scope
        && let Some(item) = items.get(&owner)
        && let ProtoItem::Message(message) = &*item.borrow()
    {
        for field in message
            .fields
            .iter()
            .chain(message.oneofs.iter().flat_map(|oneof| oneof.fields.iter()))
        {
            let display = snake_field(&field.name);
            symbols.insert(display.clone());
            if field.kind.starts_with("map<") {
                symbols.insert(protox_map_entry_name(&display));
            }
        }
        symbols.extend(
            message
                .oneofs
                .iter()
                .map(|oneof| snake_field(oneof.name.strip_suffix("Case").unwrap_or(&oneof.name))),
        );
    }

    for (candidate, node) in &graph.nodes {
        if node.parent != scope {
            continue;
        }
        let item = items[candidate].borrow();
        if *candidate != runtime_type {
            symbols.insert(current_type_name(&item).to_owned());
        }
        if let ProtoItem::Enum(enumeration) = &*item {
            symbols.extend(enumeration.variants.iter().map(|(name, _)| name.clone()));
        }
    }
    symbols
}

fn apply_manifest(
    items: &mut TypeToItemMap,
    packet_ids: &mut HashMap<i32, String>,
    manifest: &AcceptedManifest,
) -> Result<AcceptedApplication, String> {
    validate_manifest(manifest)?;
    let graph = build_graph(items, manifest.fingerprint_rounds)?;
    let mut report = ApplicationReport::new(manifest);
    let mut by_shape: HashMap<(String, String), Vec<RuntimeType>> = HashMap::new();
    for (runtime_type, node) in &graph.nodes {
        by_shape
            .entry((node.kind.as_str().to_owned(), node.shape.clone()))
            .or_default()
            .push(*runtime_type);
    }

    let mut matched = HashMap::<String, RuntimeType>::new();
    for record in &manifest.types {
        let identity = format!("type={}", record.canonical);
        let candidates = by_shape
            .get(&(record.kind.clone(), record.shape.clone()))
            .cloned()
            .unwrap_or_default();
        if candidates.is_empty() {
            report
                .unresolved
                .push(format!("{identity} reason=shape-not-found"));
            continue;
        }
        let command = record
            .cmd_id
            .map(|command_id| {
                candidates
                    .iter()
                    .copied()
                    .filter(|candidate| graph.nodes[candidate].cmd_id == command_id)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let native = if record.write_to_rva != 0 || record.merge_from_rva != 0 {
            candidates
                .iter()
                .copied()
                .filter(|candidate| {
                    let node = &graph.nodes[candidate];
                    node.write_to_rva == record.write_to_rva
                        && node.merge_from_rva == record.merge_from_rva
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let (selected, mode) = if record.cmd_id.is_some() && command.len() != 1 {
            report.conflicts.push(format!(
                "{identity} reason=command-anchor-count count={}",
                command.len()
            ));
            (None, None)
        } else if command.len() == 1 && native.len() == 1 && command[0] != native[0] {
            report.conflicts.push(format!(
                "{identity} reason=command-and-native-anchors-disagree"
            ));
            (None, None)
        } else if command.len() == 1 {
            (Some(command[0]), Some("cmd-id"))
        } else if candidates.len() == 1 {
            (Some(candidates[0]), Some("unique-structure"))
        } else if native.len() == 1 {
            (Some(native[0]), Some("exact-native-rva"))
        } else {
            report.ambiguous.push(format!(
                "{identity} reason=multiple-shape-candidates count={} native_matches={}",
                candidates.len(),
                native.len()
            ));
            (None, None)
        };
        if let Some(runtime_type) = selected {
            matched.insert(record.canonical.clone(), runtime_type);
            report.matches.push(format!(
                "{identity} mode={} runtime={runtime_type:?}",
                mode.unwrap_or("unknown")
            ));
        }
    }

    let mut reverse = HashMap::<RuntimeType, Vec<String>>::new();
    for (canonical, runtime_type) in &matched {
        reverse
            .entry(*runtime_type)
            .or_default()
            .push(canonical.clone());
    }
    for (runtime_type, canonicals) in reverse {
        if canonicals.len() > 1 {
            for canonical in &canonicals {
                matched.remove(canonical);
                report.conflicts.push(format!(
                    "type={canonical} reason=multiple-manifest-types-match-runtime runtime={runtime_type:?}"
                ));
            }
        }
    }

    let manifest_packet_ids = manifest
        .packets
        .iter()
        .map(|packet| packet.cmd_id)
        .collect::<HashSet<_>>();
    for command_id in packet_ids.keys() {
        if !manifest_packet_ids.contains(command_id) {
            report.unresolved.push(format!(
                "packet={command_id} reason=current-packet-not-in-manifest"
            ));
        }
    }
    let mut runtime_by_cmd = HashMap::<i32, Vec<RuntimeType>>::new();
    for (runtime_type, node) in &graph.nodes {
        if node.kind == ItemKind::Message && node.cmd_id != 0 {
            runtime_by_cmd
                .entry(i32::from(node.cmd_id))
                .or_default()
                .push(*runtime_type);
        }
    }
    let mut packet_runtime = HashMap::<i32, RuntimeType>::new();
    let mut packet_ready_types = HashSet::<String>::new();
    for packet in &manifest.packets {
        let identity = format!("packet={}", packet.cmd_id);
        let Some(runtime_type) = matched.get(&packet.type_canonical).copied() else {
            report
                .unresolved
                .push(format!("{identity} reason=type-unmatched"));
            continue;
        };
        let owners = runtime_by_cmd
            .get(&packet.cmd_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if owners.len() != 1 {
            report.conflicts.push(format!(
                "{identity} reason=duplicate-runtime-cmd-id count={}",
                owners.len()
            ));
            continue;
        }
        if owners[0] != runtime_type {
            report
                .conflicts
                .push(format!("{identity} reason=cmd-id-bound-to-different-type"));
            continue;
        }
        let node = &graph.nodes[&runtime_type];
        if node.fingerprint != packet.type_fingerprint || i32::from(node.cmd_id) != packet.cmd_id {
            report
                .conflicts
                .push(format!("{identity} reason=packet-structural-guard"));
            continue;
        }
        let Some(current_packet_name) = packet_ids.get(&packet.cmd_id) else {
            report
                .unresolved
                .push(format!("{identity} reason=packet-id-missing"));
            continue;
        };
        let expected_current = short_name(&node.display_path);
        if current_packet_name != expected_current {
            report.conflicts.push(format!(
                "{identity} reason=current-packet-binding-mismatch current={} expected={expected_current}",
                current_packet_name
            ));
            continue;
        }
        packet_runtime.insert(packet.cmd_id, runtime_type);
        packet_ready_types.insert(packet.type_canonical.clone());
    }

    let future_symbols = future_scope_symbol_counts(manifest, &matched, &graph);
    let mut type_candidates = Vec::new();
    for record in &manifest.types {
        let Some(accepted) = &record.accepted_name else {
            continue;
        };
        let Some(runtime_type) = matched.get(&record.canonical).copied() else {
            continue;
        };
        let item = items[&runtime_type].borrow();
        let current = current_type_name(&item);
        if current == accepted {
            report
                .already_present
                .push(format!("type={}", record.canonical));
        } else if !is_obfuscated(current) {
            report.conflicts.push(format!(
                "type={} reason=current-readable current={} accepted={}",
                record.canonical, current, accepted
            ));
        } else if record.cmd_id.is_some() && !packet_ready_types.contains(&record.canonical) {
            report.conflicts.push(format!(
                "type={} reason=packet-preflight-rejected",
                record.canonical
            ));
        } else {
            type_candidates.push((
                record.canonical.as_str(),
                runtime_type,
                graph.nodes[&runtime_type].parent,
                accepted.as_str(),
            ));
        }
    }
    let mut type_scope_counts = HashMap::<(Option<RuntimeType>, &str), usize>::new();
    for (_, _, scope, accepted) in &type_candidates {
        *type_scope_counts.entry((*scope, *accepted)).or_default() += 1;
    }
    let mut type_names = HashMap::new();
    for (canonical, runtime_type, scope, accepted) in type_candidates {
        let future_count = future_symbols
            .get(&(scope, accepted.to_owned()))
            .copied()
            .unwrap_or_default();
        if type_scope_counts[&(scope, accepted)] != 1 || future_count > 1 {
            report.conflicts.push(format!(
                "type={canonical} reason=accepted-scope-collision accepted={accepted}"
            ));
            continue;
        }
        if current_type_scope_symbols(items, &graph, runtime_type).contains(accepted) {
            report.conflicts.push(format!(
                "type={canonical} reason=current-scope-collision accepted={accepted}"
            ));
            continue;
        }
        type_names.insert(
            graph.nodes[&runtime_type].raw_path.clone(),
            accepted.to_owned(),
        );
    }
    let final_aliases = apply_type_names(items, &type_names);
    for record in &manifest.types {
        let Some(accepted) = &record.accepted_name else {
            continue;
        };
        let Some(runtime_type) = matched.get(&record.canonical).copied() else {
            continue;
        };
        let item = items[&runtime_type].borrow();
        if current_type_name(&item) == accepted
            && !report
                .already_present
                .iter()
                .any(|entry| entry == &format!("type={}", record.canonical))
        {
            report.applied.push(format!("type={}", record.canonical));
        } else if current_type_name(&item) != accepted
            && type_names.contains_key(&graph.nodes[&runtime_type].raw_path)
        {
            report.conflicts.push(format!(
                "type={} reason=namespace-rejected accepted={}",
                record.canonical, accepted
            ));
        }
    }

    for record in &manifest.types {
        let Some(runtime_type) = matched.get(&record.canonical).copied() else {
            continue;
        };
        apply_variant_records(
            items,
            &graph,
            &future_symbols,
            runtime_type,
            record,
            &mut report,
        );
    }
    for record in &manifest.types {
        let Some(runtime_type) = matched.get(&record.canonical).copied() else {
            continue;
        };
        apply_field_records(
            items,
            &graph,
            &future_symbols,
            runtime_type,
            record,
            &mut report,
        );
    }

    for packet in &manifest.packets {
        let identity = format!("packet={}", packet.cmd_id);
        let Some(runtime_type) = packet_runtime.get(&packet.cmd_id).copied() else {
            continue;
        };
        let final_name = current_type_name(&items[&runtime_type].borrow()).to_owned();
        if final_name != packet.accepted_name {
            report.conflicts.push(format!(
                "{identity} reason=packet-name-mismatch current={} accepted={}",
                final_name, packet.accepted_name
            ));
            continue;
        }
        let Some(current_packet_name) = packet_ids.get_mut(&packet.cmd_id) else {
            report
                .unresolved
                .push(format!("{identity} reason=packet-id-missing"));
            continue;
        };
        if *current_packet_name == packet.accepted_name {
            report.already_present.push(identity);
        } else {
            *current_packet_name = packet.accepted_name.clone();
            report.applied.push(identity);
        }
    }

    report.finish();
    Ok(AcceptedApplication {
        report,
        type_aliases: final_aliases,
    })
}

const EMBEDDED_MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/proto/accepted-names.v1.json"
));

const EMBEDDED_DATASET_ID: &str = "hsr-4.6.51-wave10-2026-10-04";
const EMBEDDED_PACKET_COUNT: usize = 1_108;
const EMBEDDED_PACKET_KEY_SET: &str = "9e144691ef972f902d3444d154a933fd";

fn validate_embedded_manifest(manifest: &AcceptedManifest) -> Result<(), String> {
    if manifest.dataset_id != EMBEDDED_DATASET_ID {
        return Err(format!(
            "embedded dataset mismatch: expected {EMBEDDED_DATASET_ID}, got {}",
            manifest.dataset_id
        ));
    }
    if manifest.packets.len() != EMBEDDED_PACKET_COUNT {
        return Err(format!(
            "embedded packet count mismatch: expected {EMBEDDED_PACKET_COUNT}, got {}",
            manifest.packets.len()
        ));
    }
    let mut packet_ids = manifest
        .packets
        .iter()
        .map(|packet| packet.cmd_id)
        .collect::<Vec<_>>();
    packet_ids.sort_unstable();
    let packet_key_set = packet_ids
        .iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if hash_pair(&packet_key_set) != EMBEDDED_PACKET_KEY_SET {
        return Err("embedded packet key set mismatch".to_owned());
    }

    let expected_source = [
        ("review_status", "approved"),
        (
            "independent_review_sha256",
            "a81e23b98998d486cbee92bf9368e5ac8a64b8b1c686bb9a2b2251a69d0d13a7",
        ),
        (
            "accepted_ledger_sha256",
            "8567e763c96e4b609eabe70b04fa90925f195188c6ff8e73c527892b44818318",
        ),
        (
            "accepted_application_script_sha256",
            "9741df949c9c173b68080c12e5ac030c287b0de3d65bd7e3e6f47b8d5259c793",
        ),
        (
            "raw_proto_sha256",
            "a51d18abc03d078c24b10447238a4feb435f272d59364b491ab0038f9f0dbdaf",
        ),
        (
            "accepted_proto_sha256",
            "13e54d35c89a289cb262614c9d6ab7648bb2ddcaeee326d468334796d64146f1",
        ),
        (
            "raw_packet_ids_sha256",
            "92ac1c51eb01993b5f27daf14006822146134e9e880beb0e1f714fb8fbc964d0",
        ),
        (
            "accepted_packet_ids_sha256",
            "c16a3f4d235d71a52150b4c6ec1fb89f951d2df2b7a6a7070b877d881daf4d77",
        ),
        ("packet_key_set_fingerprint", EMBEDDED_PACKET_KEY_SET),
    ];
    for (key, expected) in expected_source {
        let actual = manifest.source.get(key).and_then(serde_json::Value::as_str);
        if actual != Some(expected) {
            return Err(format!("embedded source provenance mismatch for {key}"));
        }
    }
    let counts = manifest
        .source
        .get("counts")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "embedded source counts missing".to_owned())?;
    if counts
        .get("packet_bindings")
        .and_then(serde_json::Value::as_u64)
        != Some(EMBEDDED_PACKET_COUNT as u64)
    {
        return Err("embedded packet binding count mismatch".to_owned());
    }
    if counts
        .get("active_type_records")
        .and_then(serde_json::Value::as_u64)
        != Some(manifest.types.len() as u64)
    {
        return Err("embedded active type count mismatch".to_owned());
    }
    Ok(())
}

static PARSED_EMBEDDED_MANIFEST: LazyLock<Result<AcceptedManifest, String>> = LazyLock::new(|| {
    let manifest: AcceptedManifest = serde_json::from_str(EMBEDDED_MANIFEST)
        .map_err(|error| format!("invalid accepted-name manifest JSON: {error}"))?;
    validate_manifest(&manifest)?;
    validate_embedded_manifest(&manifest)?;
    Ok(manifest)
});

fn embedded_manifest() -> Result<&'static AcceptedManifest, String> {
    PARSED_EMBEDDED_MANIFEST
        .as_ref()
        .map_err(std::clone::Clone::clone)
}

pub(super) fn validate_embedded() -> Result<(), String> {
    embedded_manifest().map(|_| ())
}

pub(super) fn apply_embedded(
    items: &mut TypeToItemMap,
    packet_ids: &mut HashMap<i32, String>,
) -> Result<AcceptedApplication, String> {
    apply_manifest(items, packet_ids, embedded_manifest()?)
}

#[cfg(test)]
fn apply_manifest_json(
    items: &mut TypeToItemMap,
    packet_ids: &mut HashMap<i32, String>,
    source: &str,
) -> Result<ApplicationReport, String> {
    let manifest: AcceptedManifest = serde_json::from_str(source)
        .map_err(|error| format!("invalid accepted-name manifest JSON: {error}"))?;
    apply_manifest(items, packet_ids, &manifest).map(|application| application.report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::output::{
        Enum, Field, Message, MessageType, OneOf, ProtoItem, TypeToItemMap,
    };
    use reflection::runtime_type::RuntimeType;
    use serde_json::json;
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    fn field(kind: &str, name: &str, number: u32) -> Field {
        Field {
            kind: kind.into(),
            name: name.into(),
            number,
            offset: number * 8,
        }
    }

    fn message(name: &str, cmd_id: u16) -> Message {
        Message {
            cmd_id,
            name: name.into(),
            deobfuscated_name: None,
            fields: vec![],
            oneofs: vec![],
            children: vec![],
            has_parent: false,
            msg_type: MessageType::None,
            write_to_rva: 0,
            merge_from_rva: 0,
        }
    }

    fn insert(items: &mut TypeToItemMap, id: usize, message: Message) {
        items.insert(
            RuntimeType(id),
            Rc::new(RefCell::new(ProtoItem::Message(message))),
        );
    }

    fn enumeration(name: &str, variants: &[(&str, i32)]) -> Enum {
        Enum {
            name: name.into(),
            deobfuscated_name: None,
            variants: variants
                .iter()
                .map(|(name, number)| ((*name).into(), *number))
                .collect(),
            has_parent: true,
        }
    }

    fn type_record(
        graph: &StructuralGraph,
        runtime_type: RuntimeType,
        canonical: &str,
        accepted_name: Option<&str>,
        cmd_id: Option<u16>,
        fields: serde_json::Value,
    ) -> serde_json::Value {
        let node = graph.nodes.get(&runtime_type).unwrap();
        json!({
            "canonical": canonical,
            "kind": "message",
            "shape": node.shape,
            "fingerprint": node.fingerprint,
            "cmd_id": cmd_id,
            "write_to_rva": node.write_to_rva,
            "merge_from_rva": node.merge_from_rva,
            "accepted_name": accepted_name,
            "fields": fields,
            "oneofs": [],
            "variants": []
        })
    }

    #[test]
    fn unique_structure_survives_raw_name_changes_and_renames_packets() {
        let mut source = TypeToItemMap::new();
        let mut source_parent = message("AAAAAAAAAAA", 7);
        source_parent.fields = vec![field("BBBBBBBBBBB", "CCCCCCCCCCC", 1)];
        insert(&mut source, 1, source_parent);
        insert(&mut source, 2, message("BBBBBBBBBBB", 0));
        let source_graph = build_graph(&source, 4).unwrap();
        let parent_field = source_graph.nodes[&RuntimeType(1)].fields[&1].clone();

        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 4,
            "source": {},
            "types": [
                type_record(
                    &source_graph,
                    RuntimeType(1),
                    "AAAAAAAAAAA",
                    Some("RecoveredParent"),
                    Some(7),
                    json!([{
                        "tag": 1,
                        "shape": parent_field.shape,
                        "oneof_tags": [],
                        "expected": "CCCCCCCCCCC",
                        "accepted": "child_data",
                        "action": "alias"
                    }]),
                ),
                type_record(
                    &source_graph,
                    RuntimeType(2),
                    "BBBBBBBBBBB",
                    Some("RecoveredChild"),
                    None,
                    json!([]),
                )
            ],
            "packets": [{
                "cmd_id": 7,
                "type_canonical": "AAAAAAAAAAA",
                "type_fingerprint": source_graph.nodes[&RuntimeType(1)].fingerprint,
                "accepted_name": "RecoveredParent"
            }]
        });

        let mut current = TypeToItemMap::new();
        let mut current_parent = message("XXXXXXXXXXX", 7);
        current_parent.fields = vec![field("YYYYYYYYYYY", "ZZZZZZZZZZZ", 1)];
        insert(&mut current, 10, current_parent);
        insert(&mut current, 11, message("YYYYYYYYYYY", 0));
        let mut packet_ids = HashMap::from([(7, "XXXXXXXXXXX".to_string())]);

        let report = apply_manifest_json(
            &mut current,
            &mut packet_ids,
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        let parent = current[&RuntimeType(10)].borrow();
        let ProtoItem::Message(parent) = &*parent else {
            panic!()
        };
        assert_eq!(parent.deobfuscated_name.as_deref(), Some("RecoveredParent"));
        assert_eq!(parent.fields[0].name, "child_data");
        assert_eq!(parent.fields[0].kind, "RecoveredChild");
        assert_eq!(packet_ids[&7], "RecoveredParent");
        assert!(report.ambiguous.is_empty());
        assert!(report.conflicts.is_empty());
    }

    #[test]
    fn duplicate_structures_without_an_anchor_remain_ambiguous() {
        let mut source = TypeToItemMap::new();
        insert(&mut source, 1, message("AAAAAAAAAAA", 0));
        let graph = build_graph(&source, 2).unwrap();
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [type_record(
                &graph,
                RuntimeType(1),
                "AAAAAAAAAAA",
                Some("Recovered"),
                None,
                json!([]),
            )],
            "packets": []
        });

        let mut current = TypeToItemMap::new();
        insert(&mut current, 10, message("AAAAAAAAAAA", 0));
        insert(&mut current, 11, message("YYYYYYYYYYY", 0));
        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        assert_eq!(report.ambiguous.len(), 1);
        for item in current.values() {
            let item = item.borrow();
            let ProtoItem::Message(message) = &*item else {
                panic!()
            };
            assert!(message.deobfuscated_name.is_none());
        }
    }

    #[test]
    fn field_shape_mismatch_and_readable_conflicts_fail_closed() {
        let mut source = TypeToItemMap::new();
        let mut source_message = message("AAAAAAAAAAA", 0);
        source_message.fields = vec![
            field("uint32", "BBBBBBBBBBB", 1),
            field("uint32", "param", 2),
        ];
        insert(&mut source, 1, source_message);
        let source_graph = build_graph(&source, 2).unwrap();

        let mut current = TypeToItemMap::new();
        let mut current_message = message("AAAAAAAAAAA", 0);
        current_message.fields = vec![
            field("uint64", "current_name", 1),
            field("uint32", "param", 2),
        ];
        current_message.oneofs = vec![OneOf {
            name: "ChoiceCase".into(),
            fields: vec![],
        }];
        insert(&mut current, 10, current_message);
        let current_graph = build_graph(&current, 2).unwrap();

        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [{
                "canonical": "AAAAAAAAAAA",
                "kind": "message",
                "shape": current_graph.nodes[&RuntimeType(10)].shape,
                "fingerprint": current_graph.nodes[&RuntimeType(10)].fingerprint,
                "cmd_id": null,
                "accepted_name": null,
                "fields": [
                    {
                        "tag": 1,
                        "shape": source_graph.nodes[&RuntimeType(1)].fields[&1].shape,
                        "oneof_tags": [],
                        "expected": "BBBBBBBBBBB",
                        "accepted": "accepted_name",
                        "action": "alias"
                    },
                    {
                        "tag": 2,
                        "shape": source_graph.nodes[&RuntimeType(1)].fields[&2].shape,
                        "oneof_tags": [],
                        "expected": "param",
                        "accepted": "target",
                        "action": "override_exact"
                    }
                ],
                "oneofs": [],
                "variants": []
            }],
            "packets": []
        });

        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        let item = current[&RuntimeType(10)].borrow();
        let ProtoItem::Message(message) = &*item else {
            panic!()
        };
        assert_eq!(message.fields[0].name, "current_name");
        assert_eq!(message.fields[1].name, "target");
        assert!(report.conflicts.iter().any(|row| row.contains("tag=1")));
    }

    #[test]
    fn oneof_discriminator_enums_do_not_change_serialized_structure() {
        let mut source = TypeToItemMap::new();
        let mut source_message = message("AAAAAAAAAAA", 0);
        source_message.oneofs = vec![OneOf {
            name: "BBBBBBBBBBBCase".into(),
            fields: vec![field("uint32", "CCCCCCCCCCC", 1)],
        }];
        insert(&mut source, 1, source_message);

        let mut current = TypeToItemMap::new();
        let discriminator = Rc::new(RefCell::new(ProtoItem::Enum(enumeration(
            "BBBBBBBBBBBOneofCase",
            &[("None", 0), ("CCCCCCCCCCC", 1)],
        ))));
        let mut current_message = message("AAAAAAAAAAA", 0);
        current_message.oneofs = vec![OneOf {
            name: "BBBBBBBBBBBCase".into(),
            fields: vec![field("uint32", "CCCCCCCCCCC", 1)],
        }];
        current_message.children.push(discriminator.clone());
        insert(&mut current, 10, current_message);
        current.insert(RuntimeType(11), discriminator);

        let source_graph = build_graph(&source, 2).unwrap();
        let current_graph = build_graph(&current, 2).unwrap();
        assert_eq!(current_graph.nodes.len(), 1);
        assert_eq!(
            source_graph.nodes[&RuntimeType(1)].shape,
            current_graph.nodes[&RuntimeType(10)].shape
        );
    }

    #[test]
    fn duplicate_runtime_cmd_ids_reject_packet_aliases() {
        let mut source = TypeToItemMap::new();
        let mut target = message("AAAAAAAAAAA", 7);
        target.fields = vec![field("uint32", "BBBBBBBBBBB", 1)];
        insert(&mut source, 1, target);
        let graph = build_graph(&source, 2).unwrap();
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [type_record(
                &graph,
                RuntimeType(1),
                "AAAAAAAAAAA",
                Some("RecoveredPacket"),
                Some(7),
                json!([]),
            )],
            "packets": [{
                "cmd_id": 7,
                "type_canonical": "AAAAAAAAAAA",
                "type_fingerprint": graph.nodes[&RuntimeType(1)].fingerprint,
                "accepted_name": "RecoveredPacket"
            }]
        });

        let mut current = TypeToItemMap::new();
        let mut current_target = message("XXXXXXXXXXX", 7);
        current_target.fields = vec![field("uint32", "YYYYYYYYYYY", 1)];
        insert(&mut current, 10, current_target);
        let mut duplicate = message("ZZZZZZZZZZZ", 7);
        duplicate.fields = vec![field("string", "WWWWWWWWWWW", 1)];
        insert(&mut current, 11, duplicate);
        let mut packet_ids = HashMap::from([(7, "XXXXXXXXXXX".to_string())]);

        let report = apply_manifest_json(
            &mut current,
            &mut packet_ids,
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(packet_ids[&7], "XXXXXXXXXXX");
        let target = current[&RuntimeType(10)].borrow();
        let ProtoItem::Message(target) = &*target else {
            panic!()
        };
        assert!(target.deobfuscated_name.is_none());
        assert!(
            report
                .conflicts
                .iter()
                .any(|row| row.contains("duplicate-runtime-cmd-id"))
        );
    }

    #[test]
    fn historical_type_collision_preserves_current_readable_name() {
        let mut current = TypeToItemMap::new();
        let mut readable = message("AAAAAAAAAAA", 0);
        readable.deobfuscated_name = Some("ReadableType".into());
        insert(&mut current, 1, readable);
        let mut candidate = message("BBBBBBBBBBB", 0);
        candidate.fields = vec![field("uint32", "CCCCCCCCCCC", 1)];
        insert(&mut current, 2, candidate);
        let graph = build_graph(&current, 2).unwrap();
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [type_record(
                &graph,
                RuntimeType(2),
                "BBBBBBBBBBB",
                Some("ReadableType"),
                None,
                json!([]),
            )],
            "packets": []
        });

        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        {
            let item = current[&RuntimeType(1)].borrow();
            let ProtoItem::Message(readable) = &*item else {
                panic!()
            };
            assert_eq!(readable.deobfuscated_name.as_deref(), Some("ReadableType"));
        }
        let candidate = current[&RuntimeType(2)].borrow();
        let ProtoItem::Message(candidate) = &*candidate else {
            panic!()
        };
        assert!(candidate.deobfuscated_name.is_none());
        assert!(
            report
                .conflicts
                .iter()
                .any(|row| row.contains("current-scope-collision"))
        );
    }

    #[test]
    fn enum_alias_cannot_shadow_a_synthetic_map_entry() {
        let mut current = TypeToItemMap::new();
        let enumeration = Rc::new(RefCell::new(ProtoItem::Enum(enumeration(
            "EEEEEEEEEEE",
            &[("None", 0), ("VVVVVVVVVVV", 1)],
        ))));
        let mut parent = message("PPPPPPPPPPP", 0);
        parent.fields = vec![field("map<string, uint32>", "foo", 1)];
        parent.children = vec![enumeration.clone()];
        insert(&mut current, 1, parent);
        current.insert(RuntimeType(2), enumeration);
        let graph = build_graph(&current, 2).unwrap();
        let enum_node = &graph.nodes[&RuntimeType(2)];
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [{
                "canonical": "PPPPPPPPPPP.EEEEEEEEEEE",
                "kind": "enum",
                "shape": enum_node.shape,
                "fingerprint": enum_node.fingerprint,
                "cmd_id": null,
                "write_to_rva": 0,
                "merge_from_rva": 0,
                "accepted_name": null,
                "fields": [],
                "oneofs": [],
                "variants": [{
                    "number": 1,
                    "expected": "VVVVVVVVVVV",
                    "accepted": "FooEntry",
                    "action": "alias"
                }]
            }],
            "packets": []
        });

        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        {
            let item = current[&RuntimeType(2)].borrow();
            let ProtoItem::Enum(enumeration) = &*item else {
                panic!()
            };
            assert_eq!(enumeration.variants[1].0, "VVVVVVVVVVV");
        }
        assert!(report.conflicts.iter().any(|row| {
            row.contains("variant=PPPPPPPPPPP.EEEEEEEEEEE:number=1")
                && row.contains("scope-collision")
        }));

        let parent = current[&RuntimeType(1)].borrow();
        let ProtoItem::Message(parent) = &*parent else {
            panic!()
        };
        let rendered = format!(
            "syntax = \"proto3\";\n\n{}",
            parent.fmt_protobuf_with_depth(0)
        );
        let output = std::env::temp_dir().join(format!(
            "hsr-owner-map-entry-scope-{}.proto",
            std::process::id()
        ));
        std::fs::write(&output, rendered).unwrap();
        let compile_result = protox::compile([&output], [output.parent().unwrap()]);
        let _ = std::fs::remove_file(&output);
        compile_result.unwrap();
    }

    #[test]
    fn uppercase_map_entry_blocks_enum_alias() {
        let mut current = TypeToItemMap::new();
        let enumeration = Rc::new(RefCell::new(ProtoItem::Enum(enumeration(
            "EEEEEEEEEEE",
            &[("None", 0), ("VVVVVVVVVVV", 1)],
        ))));
        let mut parent = message("PPPPPPPPPPP", 0);
        parent.fields = vec![field("map<string, uint32>", "HEDHGPKEGBI", 1)];
        parent.children = vec![enumeration.clone()];
        insert(&mut current, 1, parent);
        current.insert(RuntimeType(2), enumeration);
        let graph = build_graph(&current, 2).unwrap();
        let enum_node = &graph.nodes[&RuntimeType(2)];
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [{
                "canonical": "PPPPPPPPPPP.EEEEEEEEEEE",
                "kind": "enum",
                "shape": enum_node.shape,
                "fingerprint": enum_node.fingerprint,
                "cmd_id": null,
                "write_to_rva": 0,
                "merge_from_rva": 0,
                "accepted_name": null,
                "fields": [],
                "oneofs": [],
                "variants": [{
                    "number": 1,
                    "expected": "VVVVVVVVVVV",
                    "accepted": "HEDHGPKEGBIEntry",
                    "action": "alias"
                }]
            }],
            "packets": []
        });

        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        {
            let item = current[&RuntimeType(2)].borrow();
            let ProtoItem::Enum(enumeration) = &*item else {
                panic!()
            };
            assert_eq!(enumeration.variants[1].0, "VVVVVVVVVVV");
        }
        assert!(report.conflicts.iter().any(|row| {
            row.contains("variant=PPPPPPPPPPP.EEEEEEEEEEE:number=1")
                && row.contains("scope-collision")
        }));

        let parent = current[&RuntimeType(1)].borrow();
        let ProtoItem::Message(parent) = &*parent else {
            panic!()
        };
        let rendered = format!(
            "syntax = \"proto3\";\n\n{}",
            parent.fmt_protobuf_with_depth(0)
        );
        let output = std::env::temp_dir().join(format!(
            "hsr-owner-uppercase-map-entry-enum-{}.proto",
            std::process::id()
        ));
        std::fs::write(&output, rendered).unwrap();
        let compile_result = protox::compile([&output], [output.parent().unwrap()]);
        let _ = std::fs::remove_file(&output);
        compile_result.unwrap();
    }

    #[test]
    fn uppercase_map_entry_blocks_nested_type_alias() {
        let mut current = TypeToItemMap::new();
        let child = Rc::new(RefCell::new(ProtoItem::Message(message("CCCCCCCCCCC", 0))));
        let mut parent = message("PPPPPPPPPPP", 0);
        parent.fields = vec![field("map<string, uint32>", "HEDHGPKEGBI", 1)];
        parent.children = vec![child.clone()];
        insert(&mut current, 1, parent);
        current.insert(RuntimeType(2), child);
        let graph = build_graph(&current, 2).unwrap();
        let child_node = &graph.nodes[&RuntimeType(2)];
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [{
                "canonical": "PPPPPPPPPPP.CCCCCCCCCCC",
                "kind": "message",
                "shape": child_node.shape,
                "fingerprint": child_node.fingerprint,
                "cmd_id": null,
                "write_to_rva": 0,
                "merge_from_rva": 0,
                "accepted_name": "HEDHGPKEGBIEntry",
                "fields": [],
                "oneofs": [],
                "variants": []
            }],
            "packets": []
        });

        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        {
            let item = current[&RuntimeType(2)].borrow();
            let ProtoItem::Message(child) = &*item else {
                panic!()
            };
            assert_eq!(child.deobfuscated_name, None);
        }
        assert!(report.conflicts.iter().any(|row| {
            row.contains("type=PPPPPPPPPPP.CCCCCCCCCCC") && row.contains("current-scope-collision")
        }));

        let parent = current[&RuntimeType(1)].borrow();
        let ProtoItem::Message(parent) = &*parent else {
            panic!()
        };
        let rendered = format!(
            "syntax = \"proto3\";\n\n{}",
            parent.fmt_protobuf_with_depth(0)
        );
        let output = std::env::temp_dir().join(format!(
            "hsr-owner-uppercase-map-entry-type-{}.proto",
            std::process::id()
        ));
        std::fs::write(&output, rendered).unwrap();
        let compile_result = protox::compile([&output], [output.parent().unwrap()]);
        let _ = std::fs::remove_file(&output);
        compile_result.unwrap();
    }

    #[test]
    fn uppercase_map_field_alias_cannot_create_a_synthetic_type_collision() {
        let mut current = TypeToItemMap::new();
        let child = Rc::new(RefCell::new(ProtoItem::Message(message(
            "HEDHGPKEGBIEntry",
            0,
        ))));
        let mut parent = message("PPPPPPPPPPP", 0);
        parent.fields = vec![field("map<string, uint32>", "FFFFFFFFFFF", 1)];
        parent.children = vec![child.clone()];
        insert(&mut current, 1, parent);
        current.insert(RuntimeType(2), child);
        let graph = build_graph(&current, 2).unwrap();
        let parent_node = &graph.nodes[&RuntimeType(1)];
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [{
                "canonical": "PPPPPPPPPPP",
                "kind": "message",
                "shape": parent_node.shape,
                "fingerprint": parent_node.fingerprint,
                "cmd_id": null,
                "write_to_rva": 0,
                "merge_from_rva": 0,
                "accepted_name": null,
                "fields": [{
                    "tag": 1,
                    "shape": parent_node.fields[&1].shape,
                    "oneof_tags": [],
                    "expected": "FFFFFFFFFFF",
                    "accepted": "HEDHGPKEGBI",
                    "action": "alias"
                }],
                "oneofs": [],
                "variants": []
            }],
            "packets": []
        });

        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        let parent = current[&RuntimeType(1)].borrow();
        let ProtoItem::Message(parent) = &*parent else {
            panic!()
        };
        assert_eq!(parent.fields[0].name, "FFFFFFFFFFF");
        assert!(report.conflicts.iter().any(|row| {
            row.contains("field=PPPPPPPPPPP:tag=1") && row.contains("invalid-or-conflicting")
        }));
        let rendered = format!(
            "syntax = \"proto3\";\n\n{}",
            parent.fmt_protobuf_with_depth(0)
        );
        let output = std::env::temp_dir().join(format!(
            "hsr-owner-uppercase-map-entry-field-{}.proto",
            std::process::id()
        ));
        std::fs::write(&output, rendered).unwrap();
        let compile_result = protox::compile([&output], [output.parent().unwrap()]);
        let _ = std::fs::remove_file(&output);
        compile_result.unwrap();
    }

    #[test]
    fn future_type_and_enum_alias_collision_rejects_both() {
        let mut current = TypeToItemMap::new();
        let child = Rc::new(RefCell::new(ProtoItem::Message(message("CCCCCCCCCCC", 0))));
        let enumeration = Rc::new(RefCell::new(ProtoItem::Enum(enumeration(
            "EEEEEEEEEEE",
            &[("None", 0), ("VVVVVVVVVVV", 1)],
        ))));
        let mut parent = message("PPPPPPPPPPP", 0);
        parent.children = vec![child.clone(), enumeration.clone()];
        insert(&mut current, 1, parent);
        current.insert(RuntimeType(2), child);
        current.insert(RuntimeType(3), enumeration);
        let graph = build_graph(&current, 2).unwrap();
        let enum_node = &graph.nodes[&RuntimeType(3)];
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [
                type_record(
                    &graph,
                    RuntimeType(2),
                    "PPPPPPPPPPP.CCCCCCCCCCC",
                    Some("SharedName"),
                    None,
                    json!([]),
                ),
                {
                    "canonical": "PPPPPPPPPPP.EEEEEEEEEEE",
                    "kind": "enum",
                    "shape": enum_node.shape,
                    "fingerprint": enum_node.fingerprint,
                    "cmd_id": null,
                    "write_to_rva": 0,
                    "merge_from_rva": 0,
                    "accepted_name": null,
                    "fields": [],
                    "oneofs": [],
                    "variants": [{
                        "number": 1,
                        "expected": "VVVVVVVVVVV",
                        "accepted": "SharedName",
                        "action": "alias"
                    }]
                }
            ],
            "packets": []
        });

        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        {
            let item = current[&RuntimeType(2)].borrow();
            let ProtoItem::Message(child) = &*item else {
                panic!()
            };
            assert!(child.deobfuscated_name.is_none());
        }
        let enumeration = current[&RuntimeType(3)].borrow();
        let ProtoItem::Enum(enumeration) = &*enumeration else {
            panic!()
        };
        assert_eq!(enumeration.variants[1].0, "VVVVVVVVVVV");
        assert!(report.conflicts.iter().any(|row| {
            row.contains("type=PPPPPPPPPPP.CCCCCCCCCCC") && row.contains("accepted-scope-collision")
        }));
        assert!(report.conflicts.iter().any(|row| {
            row.contains("variant=PPPPPPPPPPP.EEEEEEEEEEE:number=1")
                && row.contains("scope-collision")
        }));
    }

    #[test]
    fn enum_variant_collisions_with_the_containing_message_fail_closed() {
        let mut current = TypeToItemMap::new();
        let child = Rc::new(RefCell::new(ProtoItem::Enum(enumeration(
            "EEEEEEEEEEE",
            &[("VVVVVVVVVVV", 0)],
        ))));
        let mut parent = message("PPPPPPPPPPP", 0);
        parent.fields = vec![field("uint32", "FFFFFFFFFFF", 1)];
        parent.children.push(child.clone());
        insert(&mut current, 1, parent);
        current.insert(RuntimeType(2), child);
        let graph = build_graph(&current, 2).unwrap();
        let parent_node = &graph.nodes[&RuntimeType(1)];
        let node = &graph.nodes[&RuntimeType(2)];
        let parent_record = type_record(
            &graph,
            RuntimeType(1),
            "PPPPPPPPPPP",
            None,
            None,
            json!([{
                "tag": 1,
                "shape": parent_node.fields[&1].shape,
                "oneof_tags": [],
                "expected": "FFFFFFFFFFF",
                "accepted": "collision",
                "action": "alias"
            }]),
        );
        let enum_record = json!({
            "canonical": "PPPPPPPPPPP.EEEEEEEEEEE",
            "kind": "enum",
            "shape": node.shape,
            "fingerprint": node.fingerprint,
            "cmd_id": null,
            "accepted_name": null,
            "fields": [],
            "oneofs": [],
            "variants": [{
                "number": 0,
                "expected": "VVVVVVVVVVV",
                "accepted": "collision",
                "action": "alias"
            }]
        });
        let manifest = json!({
            "schema_version": 1,
            "dataset_id": "unit-test",
            "fingerprint_rounds": 2,
            "source": {},
            "types": [parent_record, enum_record],
            "packets": []
        });

        let report = apply_manifest_json(
            &mut current,
            &mut HashMap::new(),
            &serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        let item = current[&RuntimeType(2)].borrow();
        let ProtoItem::Enum(enumeration) = &*item else {
            panic!()
        };
        assert_eq!(enumeration.variants[0].0, "VVVVVVVVVVV");
        drop(item);
        let parent = current[&RuntimeType(1)].borrow();
        let ProtoItem::Message(parent) = &*parent else {
            panic!()
        };
        assert_eq!(parent.fields[0].name, "FFFFFFFFFFF");
        assert!(
            report
                .conflicts
                .iter()
                .any(|row| row.contains("scope-collision"))
        );
    }

    #[test]
    fn embedded_manifest_requirements_reject_wrong_identity_or_packet_count() {
        let mut wrong_identity: AcceptedManifest = serde_json::from_str(EMBEDDED_MANIFEST).unwrap();
        wrong_identity.dataset_id = "wrong-dataset".into();
        assert!(
            validate_embedded_manifest(&wrong_identity)
                .unwrap_err()
                .contains("dataset")
        );

        let mut wrong_count: AcceptedManifest = serde_json::from_str(EMBEDDED_MANIFEST).unwrap();
        wrong_count.packets.pop();
        assert!(
            validate_embedded_manifest(&wrong_count)
                .unwrap_err()
                .contains("packet count")
        );
    }
}
