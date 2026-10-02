//! Explicit, offline acceptance replay over an existing dump. No IL2CPP APIs are used.

use super::output::{self, Enum, Field, Message, MessageType, OneOf, ProtoItem, TypeToItemMap};
use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use reflection::runtime_type::RuntimeType;
use serde_json::json;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    rc::Rc,
};

type ItemRef = Rc<RefCell<ProtoItem>>;

#[derive(Default)]
struct Metadata {
    obfuscated_name: Option<String>,
    message_type: Option<MessageType>,
    command_id: u16,
    write_to_rva: usize,
    merge_from_rva: usize,
}

enum Scope {
    Item(ItemRef),
    OneOf(ItemRef, usize),
}

struct ParsedDump {
    syntax: String,
    items: TypeToItemMap,
}

/// This accepts the line grammar emitted by `fmt_protobuf_with_depth`, not arbitrary protobuf.
/// Unknown lines fail visibly so a new output feature cannot silently disappear in replay.
fn parse_dump(source: &str) -> Result<ParsedDump> {
    let mut items = TypeToItemMap::new();
    let mut scopes = Vec::<Scope>::new();
    let mut metadata = Metadata::default();
    let mut syntax = None;

    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("syntax = ") {
            ensure!(
                syntax.is_none() && scopes.is_empty(),
                "duplicate/nested syntax at {line_number}"
            );
            syntax = Some(line.to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix("// Obf: ") {
            metadata.obfuscated_name = Some(value.trim().to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix("// Type: ") {
            metadata.message_type = Some(match value.trim() {
                "Req" => MessageType::Req,
                "Rsp" => MessageType::Rsp,
                "Notify" => MessageType::Notify,
                "None" => MessageType::None,
                other => bail!("unknown message type {other} at {line_number}"),
            });
            continue;
        }
        if let Some(value) = line.strip_prefix("// CmdID: ") {
            metadata.command_id = value
                .parse()
                .with_context(|| format!("CmdID at {line_number}"))?;
            continue;
        }
        if let Some(value) = line.strip_prefix("// WriteTo: ") {
            let (write_to, merge_from) = value
                .split_once(" | MergeFrom: ")
                .with_context(|| format!("RVA comment at {line_number}"))?;
            metadata.write_to_rva = parse_rva(write_to)?;
            metadata.merge_from_rva = parse_rva(merge_from)?;
            continue;
        }
        if line.starts_with("//") {
            continue;
        }
        if line == "}" {
            ensure!(
                scopes.pop().is_some(),
                "unmatched closing brace at {line_number}"
            );
            continue;
        }

        if let Some(declaration) = line.strip_suffix(" {") {
            let (kind, displayed_name) = declaration
                .split_once(' ')
                .with_context(|| format!("declaration at {line_number}"))?;
            if kind == "oneof" {
                let Some(Scope::Item(parent)) = scopes.last() else {
                    bail!("oneof outside a message at {line_number}");
                };
                let parent = parent.clone();
                let oneof_index = match &mut *parent.borrow_mut() {
                    ProtoItem::Message(message) => {
                        let index = message.oneofs.len();
                        message.oneofs.push(OneOf {
                            name: displayed_name.to_string(),
                            fields: Vec::new(),
                        });
                        index
                    }
                    ProtoItem::Enum(_) => bail!("oneof inside enum at {line_number}"),
                };
                scopes.push(Scope::OneOf(parent, oneof_index));
                continue;
            }

            let pending = std::mem::take(&mut metadata);
            let deobfuscated_name = pending
                .obfuscated_name
                .as_ref()
                .map(|_| displayed_name.to_string());
            let name = pending
                .obfuscated_name
                .unwrap_or_else(|| displayed_name.to_string());
            let has_parent = !scopes.is_empty();
            let item = match kind {
                "message" => ProtoItem::Message(Message {
                    cmd_id: pending.command_id,
                    name,
                    deobfuscated_name,
                    fields: Vec::new(),
                    oneofs: Vec::new(),
                    children: Vec::new(),
                    has_parent,
                    msg_type: pending.message_type.unwrap_or(MessageType::None),
                    write_to_rva: pending.write_to_rva,
                    merge_from_rva: pending.merge_from_rva,
                }),
                "enum" => ProtoItem::Enum(Enum {
                    name,
                    deobfuscated_name,
                    variants: Vec::new(),
                    has_parent,
                }),
                other => bail!("unsupported declaration {other} at {line_number}"),
            };
            let item = Rc::new(RefCell::new(item));
            if let Some(scope) = scopes.last() {
                let Scope::Item(parent) = scope else {
                    bail!("type declared inside oneof at {line_number}");
                };
                match &mut *parent.borrow_mut() {
                    ProtoItem::Message(message) => message.children.push(item.clone()),
                    ProtoItem::Enum(_) => bail!("type declared inside enum at {line_number}"),
                }
            }
            // A monotonically increasing opaque map key only; it is never dereferenced.
            items.insert(RuntimeType(items.len() + 1), item.clone());
            scopes.push(Scope::Item(item));
            continue;
        }

        let (declaration, comment) = line.split_once("//").unwrap_or((line, ""));
        let (left, right) = declaration
            .split_once('=')
            .with_context(|| format!("unsupported line {line_number}: {line}"))?;
        let number = right
            .trim()
            .strip_suffix(';')
            .with_context(|| format!("missing semicolon at {line_number}"))?;
        match scopes.last() {
            Some(Scope::Item(item)) => match &mut *item.borrow_mut() {
                ProtoItem::Enum(enumeration) => enumeration
                    .variants
                    .push((left.trim().to_string(), number.trim().parse()?)),
                ProtoItem::Message(message) => {
                    message
                        .fields
                        .push(parse_field(left, number, comment, line_number)?)
                }
            },
            Some(Scope::OneOf(item, index)) => {
                let mut item = item.borrow_mut();
                let ProtoItem::Message(message) = &mut *item else {
                    unreachable!()
                };
                message.oneofs[*index].fields.push(parse_field(
                    left,
                    number,
                    comment,
                    line_number,
                )?);
            }
            None => bail!("field/variant outside a type at {line_number}"),
        }
    }
    ensure!(scopes.is_empty(), "unclosed type/oneof at end of dump");
    ensure!(!items.is_empty(), "dump contains no types");
    Ok(ParsedDump {
        syntax: syntax.context("missing syntax declaration")?,
        items,
    })
}

fn parse_rva(value: &str) -> Result<usize> {
    Ok(usize::from_str_radix(
        value
            .trim()
            .strip_prefix("0x")
            .context("missing hex RVA prefix")?,
        16,
    )?)
}

fn parse_field(left: &str, number: &str, comment: &str, line: usize) -> Result<Field> {
    let (kind, name) = left
        .trim()
        .rsplit_once(' ')
        .with_context(|| format!("field kind/name at {line}"))?;
    let offset = match comment.trim().strip_prefix("offset: ") {
        Some(offset) => offset
            .parse()
            .with_context(|| format!("offset at {line}"))?,
        None => 0,
    };
    Ok(Field {
        kind: kind.trim().to_string(),
        name: name.to_string(),
        number: number.trim().parse()?,
        offset,
    })
}

fn read_name_map(source: &str) -> Result<IndexMap<String, String>> {
    let mut names = IndexMap::new();
    for (index, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (original, recovered) = line
            .split_once(char::is_whitespace)
            .with_context(|| format!("nt.txt line {}", index + 1))?;
        ensure!(
            !recovered.trim().is_empty(),
            "empty nt.txt target at line {}",
            index + 1
        );
        ensure!(
            names
                .insert(original.to_string(), recovered.trim().to_string())
                .is_none(),
            "duplicate nt.txt source {original}"
        );
    }
    Ok(names)
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_obfuscated(name: &str) -> bool {
    name.len() == 11 && name.bytes().all(|c| c.is_ascii_uppercase())
}

fn visit_fields(
    message: &mut Message,
    mut visit: impl FnMut(&mut Field) -> Result<()>,
) -> Result<()> {
    for field in &mut message.fields {
        visit(field)?;
    }
    for oneof in &mut message.oneofs {
        for field in &mut oneof.fields {
            visit(field)?;
        }
    }
    Ok(())
}

/// Legacy numeric URL candidates cannot become legal protobuf identifiers. Recover the
/// unique original name from nt.txt, then exclude the invalid candidate from naming input.
fn restore_invalid_fields(
    items: &mut TypeToItemMap,
    names: &IndexMap<String, String>,
) -> Result<usize> {
    let mut count = 0;
    for item in items.values_mut() {
        if let ProtoItem::Message(message) = &mut *item.borrow_mut() {
            visit_fields(message, |field| {
                if is_identifier(&field.name) {
                    return Ok(());
                }
                let originals = names
                    .iter()
                    .filter(|(_, value)| *value == &field.name)
                    .map(|(key, _)| key)
                    .collect::<Vec<_>>();
                ensure!(
                    originals.len() == 1,
                    "invalid field {} tag {} has {} reverse mappings",
                    field.name,
                    field.number,
                    originals.len()
                );
                ensure!(
                    is_identifier(originals[0]),
                    "reverse mapping {} is also invalid",
                    originals[0]
                );
                field.name = originals[0].clone();
                count += 1;
                Ok(())
            })?;
        }
    }
    Ok(count)
}

#[derive(Default)]
struct ReadableNameRecovery {
    restored: usize,
    ambiguous: usize,
    absent: usize,
    ambiguous_samples: Vec<String>,
}

/// Formatting erased the raw names of previously translated fields. Only a
/// unique reverse mapping from the predeobf seed region can restore that evidence.
/// Restoring a raw name lets production conflict checks reject a bad candidate.
fn restore_readable_seed_fields(
    items: &mut TypeToItemMap,
    names: &IndexMap<String, String>,
) -> Result<ReadableNameRecovery> {
    let type_keys = items
        .values()
        .map(|item| match &*item.borrow() {
            ProtoItem::Message(message) => message.name.clone(),
            ProtoItem::Enum(enumeration) => enumeration.name.clone(),
        })
        .collect::<HashSet<_>>();
    let first_type = names
        .iter()
        .position(|(key, _)| type_keys.contains(key))
        .context("nt.txt has no type boundary for field-name recovery")?;
    let mut reverse = HashMap::<String, Vec<String>>::new();
    for (original, recovered) in names.iter().take(first_type) {
        if !type_keys.contains(original) {
            reverse
                .entry(output::snake_field(recovered))
                .or_default()
                .push(original.clone());
        }
    }
    let mut result = ReadableNameRecovery::default();
    for item in items.values_mut() {
        if let ProtoItem::Message(message) = &mut *item.borrow_mut() {
            let message_name = message.name.clone();
            visit_fields(message, |field| {
                if !is_identifier(&field.name) || is_obfuscated(&field.name) {
                    return Ok(());
                }
                match reverse.get(&field.name) {
                    Some(originals) if originals.len() == 1 && is_obfuscated(&originals[0]) => {
                        field.name = originals[0].clone();
                        result.restored += 1;
                    }
                    Some(originals) if originals.len() > 1 => {
                        result.ambiguous += 1;
                        if result.ambiguous_samples.len() < 12 {
                            result.ambiguous_samples.push(format!(
                                "{message_name}:tag={}:name={}:candidates={}",
                                field.number,
                                field.name,
                                originals.len()
                            ));
                        }
                    }
                    _ => result.absent += 1,
                }
                Ok(())
            })?;
        }
    }
    Ok(result)
}

fn split_name_map(
    items: &TypeToItemMap,
    names: &IndexMap<String, String>,
) -> Result<(HashMap<String, String>, HashMap<String, String>, usize)> {
    let mut type_keys = HashSet::new();
    let mut field_keys = HashSet::new();
    for item in items.values() {
        match &*item.borrow() {
            ProtoItem::Message(message) => {
                type_keys.insert(message.name.clone());
                for field in &message.fields {
                    field_keys.insert(field.name.clone());
                }
                for oneof in &message.oneofs {
                    field_keys.insert(oneof.name.clone());
                    for field in &oneof.fields {
                        field_keys.insert(field.name.clone());
                    }
                }
            }
            ProtoItem::Enum(enumeration) => {
                type_keys.insert(enumeration.name.clone());
            }
        }
    }
    let types = names
        .iter()
        .filter(|(key, _)| type_keys.contains(*key))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Dump order is predeobf fields, existing type names, then logic additions.
    // Later field entries may have used the old same-wire-type ordering guess.
    let first_type = names
        .iter()
        .position(|(key, _)| type_keys.contains(key))
        .context("nt.txt has no type boundary; cannot identify trusted field seeds")?;
    let mut fields: HashMap<String, String> = names
        .iter()
        .take(first_type)
        .filter(|(_, value)| is_identifier(&output::snake_field(value)))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Some readable names cannot be uniquely reversed. Preserve those names as
    // identity seeds rather than inventing raw names or rematching by order.
    for name in &field_keys {
        if is_identifier(name) && !is_obfuscated(name) {
            fields.entry(name.clone()).or_insert_with(|| name.clone());
        }
    }
    Ok((types, fields, first_type))
}

#[derive(Debug, PartialEq, Eq)]
struct FieldLayout {
    number: u32,
    kind: String,
    offset: u32,
    oneof: Option<usize>,
}

#[derive(Debug, PartialEq, Eq)]
enum ItemLayout {
    Message {
        fields: Vec<FieldLayout>,
        oneof_count: usize,
        child_ids: Vec<usize>,
        has_parent: bool,
        command_id: u16,
        message_type: String,
        write_to_rva: usize,
        merge_from_rva: usize,
    },
    Enum {
        numbers: Vec<i32>,
        has_parent: bool,
    },
}

fn snapshot(items: &TypeToItemMap) -> Vec<ItemLayout> {
    let ids = items
        .iter()
        .map(|(id, item)| (Rc::as_ptr(item) as usize, id.0))
        .collect::<HashMap<_, _>>();
    items
        .values()
        .map(|item| match &*item.borrow() {
            ProtoItem::Message(message) => {
                let mut fields = message
                    .fields
                    .iter()
                    .map(|field| FieldLayout {
                        number: field.number,
                        kind: field.kind.clone(),
                        offset: field.offset,
                        oneof: None,
                    })
                    .collect::<Vec<_>>();
                for (index, oneof) in message.oneofs.iter().enumerate() {
                    fields.extend(oneof.fields.iter().map(|field| FieldLayout {
                        number: field.number,
                        kind: field.kind.clone(),
                        offset: field.offset,
                        oneof: Some(index),
                    }));
                }
                ItemLayout::Message {
                    fields,
                    oneof_count: message.oneofs.len(),
                    child_ids: message
                        .children
                        .iter()
                        .map(|child| ids[&(Rc::as_ptr(child) as usize)])
                        .collect(),
                    has_parent: message.has_parent,
                    command_id: message.cmd_id,
                    message_type: format!("{:?}", message.msg_type),
                    write_to_rva: message.write_to_rva,
                    merge_from_rva: message.merge_from_rva,
                }
            }
            ProtoItem::Enum(enumeration) => ItemLayout::Enum {
                numbers: enumeration
                    .variants
                    .iter()
                    .map(|(_, number)| *number)
                    .collect(),
                has_parent: enumeration.has_parent,
            },
        })
        .collect()
}

fn expected_kind(kind: &str, aliases: &HashMap<String, String>) -> String {
    if let Some(element) = kind.strip_prefix("repeated ") {
        return format!("repeated {}", expected_kind(element, aliases));
    }
    if let Some(entry) = kind
        .strip_prefix("map<")
        .and_then(|value| value.strip_suffix('>'))
    {
        let (key, value) = entry.split_once(',').expect("generated map kind");
        return format!(
            "map<{}, {}>",
            expected_kind(key.trim(), aliases),
            expected_kind(value.trim(), aliases)
        );
    }
    if let Some(name) = aliases.get(kind) {
        return name.clone();
    }
    // Generated nested references may be relative to the owning message. Match
    // the first unambiguous qualified suffix in the accepted alias table.
    for (index, _) in kind.match_indices('.') {
        if let Some(name) = aliases.get(&kind[index + 1..]) {
            return name.clone();
        }
    }
    kind.to_string()
}

fn format_dump(parsed: &ParsedDump) -> String {
    let mut result = format!("{}\n\n", parsed.syntax);
    for item in parsed.items.values() {
        let item = item.borrow();
        let has_parent = match &*item {
            ProtoItem::Message(message) => message.has_parent,
            ProtoItem::Enum(enumeration) => enumeration.has_parent,
        };
        if !has_parent {
            result.push_str(&item.fmt_protobuf_with_depth(0));
            result.push('\n');
        }
    }
    result
}

fn counts(items: &TypeToItemMap) -> (usize, usize, usize, usize) {
    let (mut messages, mut fields, mut obfuscated_messages, mut obfuscated_fields) = (0, 0, 0, 0);
    for item in items.values() {
        if let ProtoItem::Message(message) = &*item.borrow() {
            messages += 1;
            obfuscated_messages += usize::from(is_obfuscated(
                message
                    .deobfuscated_name
                    .as_deref()
                    .unwrap_or(&message.name),
            ));
            for field in message
                .fields
                .iter()
                .chain(message.oneofs.iter().flat_map(|oneof| oneof.fields.iter()))
            {
                fields += 1;
                obfuscated_fields += usize::from(is_obfuscated(&field.name));
            }
        }
    }
    (messages, fields, obfuscated_messages, obfuscated_fields)
}

#[test]
#[ignore = "offline acceptance replay; requires an existing HSR dump"]
fn replay_dump() -> Result<()> {
    let directory = std::env::var_os("HSR_PROTO_REPLAY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("D:/StarRail_Beta/DUMP"));
    println!(
        "[Proto replay] stage=read directory={}",
        directory.display()
    );
    let source = fs::read_to_string(directory.join("StarRail.proto"))?;
    let names = read_name_map(&fs::read_to_string(directory.join("nt.txt"))?)?;
    let mut parsed = parse_dump(&source)?;
    let before_counts = counts(&parsed.items);
    let restored_invalid_fields = restore_invalid_fields(&mut parsed.items, &names)?;
    let readable_recovery = restore_readable_seed_fields(&mut parsed.items, &names)?;
    let mut expected = snapshot(&parsed.items);
    let (mut type_names, mut field_names, legacy_seed_entries) =
        split_name_map(&parsed.items, &names)?;
    let obfuscated_enums_before = obfuscated_enums(&parsed.items);
    println!("[Proto replay] stage=XLua enum names");
    let xlua_enum_names = if directory.join("script-mini.json").is_file()
        && directory.join("methods2.json").is_file()
        && directory
            .parent()
            .is_some_and(|parent| parent.join("GameAssembly.dll").is_file())
    {
        super::xlua_enum_replay::recover(&directory, &parsed.items)?
    } else {
        println!(
            "[Proto replay] XLua enum verification skipped: matching script/methods/DLL inputs unavailable"
        );
        HashMap::new()
    };
    let xlua_enum_candidates = xlua_enum_names.len();
    for (original, recovered) in xlua_enum_names {
        if let Some(previous) = type_names.get(&original) {
            ensure!(
                previous == &recovered,
                "XLua enum source conflicts: {original} old={previous} candidate={recovered}"
            );
        }
        type_names.insert(original, recovered);
    }
    let seed_field_names = field_names.len();
    let mut logic_names: IndexMap<String, String> = names
        .iter()
        .filter(|(key, _)| type_names.contains_key(*key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let item_refs = parsed.items.values().cloned().collect::<Vec<_>>();
    super::logic_nt::field::deobf_fields(&item_refs, &mut logic_names, &mut field_names);
    let new_logic_field_names = field_names.len() - seed_field_names;

    println!(
        "[Proto replay] stage=apply types={} fields={} restored_invalid_fields={restored_invalid_fields} restored_readable_fields={} ambiguous_reverse_fields={} absent_reverse_fields={}",
        type_names.len(),
        field_names.len(),
        readable_recovery.restored,
        readable_recovery.ambiguous,
        readable_recovery.absent,
    );
    let accepted_types = output::apply_type_names(&mut parsed.items, &type_names);
    output::apply_global_field_map(&mut parsed.items, &field_names);
    for item in &mut expected {
        if let ItemLayout::Message { fields, .. } = item {
            for field in fields {
                field.kind = expected_kind(&field.kind, &accepted_types);
            }
        }
    }
    ensure!(
        snapshot(&parsed.items) == expected,
        "naming changed tags, field kinds, oneof/nested layout, enum numbers, or metadata"
    );

    let output_proto = directory.join("StarRail.deobfuscated.proto");
    let output_ids = directory.join("packetIds.deobfuscated.json");
    let rendered = format_dump(&parsed);
    let rendered_items = parse_dump(&rendered)?;
    ensure!(
        snapshot(&rendered_items.items) == expected,
        "formatted output changed wire layout or metadata"
    );
    fs::write(&output_proto, rendered)?;
    let mut packet_ids: HashMap<i32, String> =
        serde_json::from_str(&fs::read_to_string(directory.join("packetIds.json"))?)?;
    let original_packet_ids = packet_ids.clone();
    output::rename_packet_ids(&mut packet_ids, &accepted_types);
    ensure!(
        original_packet_ids.len() == packet_ids.len(),
        "packet ID count changed"
    );
    for (id, original_name) in &original_packet_ids {
        ensure!(
            packet_ids[id]
                == accepted_types
                    .get(original_name)
                    .unwrap_or(original_name)
                    .as_str(),
            "packet ID {id} changed beyond accepted renaming"
        );
    }
    let message_names = parsed
        .items
        .values()
        .filter_map(|item| match &*item.borrow() {
            ProtoItem::Message(message) if !message.has_parent => Some(
                output::short_name(
                    message
                        .deobfuscated_name
                        .as_deref()
                        .unwrap_or(&message.name),
                )
                .to_string(),
            ),
            _ => None,
        })
        .collect::<HashSet<_>>();
    ensure!(
        packet_ids.values().all(|name| message_names.contains(name)),
        "packet ID refers to a missing top-level message"
    );
    fs::write(&output_ids, serde_json::to_vec_pretty(&packet_ids)?)?;
    let written_ids: HashMap<i32, String> = serde_json::from_slice(&fs::read(&output_ids)?)?;
    ensure!(
        written_ids == packet_ids,
        "written packet IDs did not round-trip"
    );

    println!(
        "[Proto replay] stage=compile output={}",
        output_proto.display()
    );
    let descriptors = protox::compile([&output_proto], [&directory])
        .context("replayed proto failed frontend-compatible compilation")?;
    let after_counts = counts(&parsed.items);
    let summary = json!({
        "validation": "success",
        "source": directory.join("StarRail.proto"),
        "proto_output": output_proto,
        "packet_ids_output": output_ids,
        "messages": before_counts.0,
        "fields": before_counts.1,
        "obfuscated_messages_before": before_counts.2,
        "obfuscated_messages_after": after_counts.2,
        "obfuscated_fields_before": before_counts.3,
        "obfuscated_fields_after": after_counts.3,
        "obfuscated_enums_before": obfuscated_enums_before,
        "obfuscated_enums_after": obfuscated_enums(&parsed.items),
        "xlua_enum_candidates": xlua_enum_candidates,
        "candidate_type_names": type_names.len(),
        "candidate_field_names": field_names.len(),
        "legacy_seed_entries": legacy_seed_entries,
        "seed_field_names": seed_field_names,
        "new_logic_field_names": new_logic_field_names,
        "accepted_type_aliases": accepted_types.len(),
        "restored_invalid_fields": restored_invalid_fields,
        "restored_readable_fields": readable_recovery.restored,
        "ambiguous_reverse_fields_preserved": readable_recovery.ambiguous,
        "absent_reverse_fields_preserved": readable_recovery.absent,
        "ambiguous_reverse_field_samples": readable_recovery.ambiguous_samples,
        "packet_ids": packet_ids.len(),
        "compiled_files": descriptors.file.len(),
        "wire_layout_preserved": true,
        "metadata_preserved": true,
        "packet_id_references_valid": true,
        "verification_scope": "offline replay of existing candidates, conservative field rules and XLua enum array class bindings from the current DLL; no game/runtime execution"
    });
    fs::write(
        directory.join("proto-deobfuscation-validation.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("[Proto replay] stage=complete {summary}");
    Ok(())
}

fn obfuscated_enums(items: &TypeToItemMap) -> usize {
    items
        .values()
        .filter(|item| match &*item.borrow() {
            ProtoItem::Enum(en) => super::util::is_obf(output::short_name(
                en.deobfuscated_name.as_deref().unwrap_or(&en.name),
            )),
            _ => false,
        })
        .count()
}
