//! Re-apply the token-based naming passes to an existing dump without the
//! game. The dumped `StarRail.proto` is parsed back into the dumper's own
//! model; parsing must round-trip byte for byte before anything is renamed.
//!
//! Offline input lost the tokens of fields that already have readable names,
//! so an accepted-token seed is also rejected when its name is readable in any
//! obfuscated message (the owner token is unknown there).
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

use reflection::runtime_type::RuntimeType;
use serde::Serialize;

use super::{
    accepted_names,
    names::rename_handler_keys,
    output::{Enum, Field, Message, MessageType, OneOf, ProtoItem, TypeToItemMap, short_name},
    token_names::{self, is_token},
};

/// Counts before and after the offline passes.
#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub obfuscated_types_before: usize,
    pub obfuscated_types_after: usize,
    pub obfuscated_fields_before: usize,
    pub obfuscated_fields_after: usize,
    pub packet_names_changed: usize,
}

/// Result of [`rename`]. Reports are the same evidence objects the in-game
/// dumper writes.
pub struct Renamed {
    pub proto: String,
    pub packet_ids: String,
    pub type_aliases: HashMap<String, String>,
    pub summary: Summary,
    pub evidence: serde_json::Value,
}

enum Frame {
    Message(Rc<RefCell<ProtoItem>>),
    Enum(Rc<RefCell<ProtoItem>>),
    OneOf(Rc<RefCell<ProtoItem>>),
}

#[derive(Default)]
struct Pending {
    obf: Option<String>,
    msg_type: Option<MessageType>,
    cmd_id: u16,
    write_to_rva: usize,
    merge_from_rva: usize,
}

fn parse_hex(value: &str) -> Result<usize, String> {
    let digits = value
        .trim()
        .strip_prefix("0x")
        .ok_or_else(|| format!("invalid RVA {value}"))?;
    usize::from_str_radix(digits, 16).map_err(|error| format!("invalid RVA {value}: {error}"))
}

/// `KIND NAME = NUMBER;` with an optional `// offset: N`.
fn parse_field(line: &str) -> Option<Field> {
    let (declaration, offset) = match line.split_once("; // offset: ") {
        Some((declaration, offset)) => (declaration, offset.parse().ok()?),
        None => (line.strip_suffix(';')?, 0),
    };
    let (left, number) = declaration.rsplit_once(" = ")?;
    let (kind, name) = left.rsplit_once(' ')?;
    Some(Field {
        kind: kind.to_owned(),
        name: name.to_owned(),
        number: number.parse().ok()?,
        offset,
    })
}

fn parse_variant(line: &str) -> Option<(String, i32)> {
    let (name, number) = line.strip_suffix(';')?.split_once(" = ")?;
    Some((name.to_owned(), number.parse().ok()?))
}

/// Parse a dump written by `output::write_protobuf`. Returns the header line
/// and the items in output order.
fn parse(text: &str) -> Result<(String, TypeToItemMap), String> {
    let mut lines = text.split('\n').enumerate();
    let header = match lines.next() {
        Some((_, line)) if line.starts_with("syntax = ") => line.to_owned(),
        _ => return Err("input does not start with a dumper syntax header".into()),
    };
    let mut items = TypeToItemMap::new();
    let mut stack = Vec::<Frame>::new();
    let mut pending = Pending::default();
    let mut next_id = 1usize;
    for (index, raw_line) in lines {
        let number = index + 1;
        let line = raw_line.trim_start_matches('\t');
        let error = || format!("line {number}: unsupported input `{raw_line}`");
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix("// ") {
            if let Some(obf) = comment.strip_prefix("Obf: ") {
                pending.obf = Some(obf.to_owned());
            } else if let Some(kind) = comment.strip_prefix("Type: ") {
                pending.msg_type = Some(match kind {
                    "Req" => MessageType::Req,
                    "Rsp" => MessageType::Rsp,
                    "Notify" => MessageType::Notify,
                    "None" => MessageType::None,
                    _ => return Err(error()),
                });
            } else if let Some(cmd_id) = comment.strip_prefix("CmdID: ") {
                pending.cmd_id = cmd_id.parse().map_err(|_| error())?;
            } else if let Some(rvas) = comment.strip_prefix("WriteTo: ") {
                let (write_to, merge_from) = rvas.split_once(" | MergeFrom: ").ok_or_else(error)?;
                pending.write_to_rva = parse_hex(write_to)?;
                pending.merge_from_rva = parse_hex(merge_from)?;
            } else {
                return Err(error());
            }
            continue;
        }
        if line == "}" {
            stack.pop().ok_or_else(error)?;
            continue;
        }
        let has_parent = matches!(stack.last(), Some(Frame::Message(_)));
        if let Some(name) = line
            .strip_prefix("message ")
            .and_then(|rest| rest.strip_suffix(" {"))
        {
            let pending = std::mem::take(&mut pending);
            let item = Rc::new(RefCell::new(ProtoItem::Message(Message {
                cmd_id: pending.cmd_id,
                deobfuscated_name: pending.obf.is_some().then(|| name.to_owned()),
                name: pending.obf.unwrap_or_else(|| name.to_owned()),
                fields: Vec::new(),
                oneofs: Vec::new(),
                children: Vec::new(),
                has_parent,
                msg_type: pending.msg_type.unwrap_or(MessageType::None),
                write_to_rva: pending.write_to_rva,
                merge_from_rva: pending.merge_from_rva,
            })));
            attach(&stack, &item, has_parent).map_err(|_| error())?;
            items.insert(RuntimeType(next_id), item.clone());
            next_id += 1;
            stack.push(Frame::Message(item));
            continue;
        }
        if let Some(name) = line
            .strip_prefix("enum ")
            .and_then(|rest| rest.strip_suffix(" {"))
        {
            let pending = std::mem::take(&mut pending);
            if pending.msg_type.is_some() || pending.cmd_id != 0 || pending.write_to_rva != 0 {
                return Err(error());
            }
            let item = Rc::new(RefCell::new(ProtoItem::Enum(Enum {
                deobfuscated_name: pending.obf.is_some().then(|| name.to_owned()),
                name: pending.obf.unwrap_or_else(|| name.to_owned()),
                variants: Vec::new(),
                has_parent,
            })));
            attach(&stack, &item, has_parent).map_err(|_| error())?;
            items.insert(RuntimeType(next_id), item.clone());
            next_id += 1;
            stack.push(Frame::Enum(item));
            continue;
        }
        let top = match stack.last() {
            Some(Frame::Message(item)) => Some((true, item.clone())),
            Some(Frame::OneOf(item)) => Some((false, item.clone())),
            Some(Frame::Enum(item)) => {
                let mut item = item.borrow_mut();
                let ProtoItem::Enum(enumeration) = &mut *item else {
                    return Err(error());
                };
                enumeration
                    .variants
                    .push(parse_variant(line).ok_or_else(error)?);
                None
            }
            None => return Err(error()),
        };
        let Some((in_message, owner)) = top else {
            continue;
        };
        let oneof_name = line
            .strip_prefix("oneof ")
            .and_then(|rest| rest.strip_suffix(" {"));
        {
            let mut item = owner.borrow_mut();
            let ProtoItem::Message(message) = &mut *item else {
                return Err(error());
            };
            match (in_message, oneof_name) {
                (true, Some(name)) => message.oneofs.push(OneOf {
                    name: name.to_owned(),
                    fields: Vec::new(),
                }),
                (true, None) => message.fields.push(parse_field(line).ok_or_else(error)?),
                (false, None) => message
                    .oneofs
                    .last_mut()
                    .ok_or_else(error)?
                    .fields
                    .push(parse_field(line).ok_or_else(error)?),
                (false, Some(_)) => return Err(error()),
            }
        }
        if in_message && oneof_name.is_some() {
            stack.push(Frame::OneOf(owner));
        }
    }
    if !stack.is_empty() {
        return Err("unterminated message or enum at end of input".into());
    }
    Ok((header, items))
}

fn attach(stack: &[Frame], item: &Rc<RefCell<ProtoItem>>, has_parent: bool) -> Result<(), ()> {
    if !has_parent {
        return if stack.is_empty() { Ok(()) } else { Err(()) };
    }
    let Some(Frame::Message(parent)) = stack.last() else {
        return Err(());
    };
    let mut parent = parent.borrow_mut();
    let ProtoItem::Message(parent) = &mut *parent else {
        return Err(());
    };
    parent.children.push(item.clone());
    Ok(())
}

/// Same layout as `output::write_protobuf`, with the input header.
fn write(header: &str, items: &TypeToItemMap) -> String {
    let mut out = format!("{header}\n\n");
    for item in items.values() {
        let item = item.borrow();
        let nested = match &*item {
            ProtoItem::Message(message) => message.has_parent,
            ProtoItem::Enum(enumeration) => enumeration.has_parent,
        };
        if !nested {
            out.push_str(&item.fmt_protobuf_with_depth(0));
            out.push('\n');
        }
    }
    out
}

fn first_difference(left: &str, right: &str) -> usize {
    left.split('\n')
        .zip(right.split('\n'))
        .position(|(a, b)| a != b)
        .map_or_else(
            || left.split('\n').count().min(right.split('\n').count()),
            |i| i,
        )
        + 1
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

fn count_obfuscated(items: &TypeToItemMap) -> (usize, usize) {
    let mut types = 0;
    let mut fields = 0;
    for item in items.values() {
        let item = item.borrow();
        types += usize::from(is_token(current_type_name(&item)));
        if let ProtoItem::Message(message) = &*item {
            fields += message
                .fields
                .iter()
                .chain(message.oneofs.iter().flat_map(|oneof| oneof.fields.iter()))
                .filter(|field| is_token(&field.name))
                .count();
        }
    }
    (types, fields)
}

/// Rename an existing dump with the embedded accepted-name manifest (structural
/// and token-identity bindings) and token propagation with accepted-token
/// seeds. `packet_ids` is the dumped `packetIds.json`.
pub fn rename(proto: &str, packet_ids: &str) -> Result<Renamed, String> {
    let (header, mut items) = parse(proto)?;
    let round_trip = write(&header, &items);
    if round_trip != proto {
        return Err(format!(
            "parser does not round-trip the input (first difference at line {})",
            first_difference(proto, &round_trip)
        ));
    }
    let (_, raw) = parse(proto)?;

    let packet_json: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(packet_ids).map_err(|error| format!("invalid packet IDs: {error}"))?;
    let mut packets = HashMap::new();
    for (key, value) in &packet_json {
        let command = key
            .parse::<i32>()
            .map_err(|_| format!("invalid packet ID key {key}"))?;
        let name = value
            .as_str()
            .ok_or_else(|| format!("packet ID {key} has no string name"))?;
        packets.insert(command, name.to_owned());
    }

    let (types_before, fields_before) = count_obfuscated(&items);
    let client = token_names::snapshot(&items);
    let application = accepted_names::apply_embedded(&mut items, &mut packets)?;
    let unknown_owner_names = token_names::unknown_owner_names(&raw);
    let token_report = token_names::propagate_with_seeds(
        &raw,
        "",
        &client,
        &mut items,
        &application.field_seeds,
        &unknown_owner_names,
    );
    let (types_after, fields_after) = count_obfuscated(&items);

    let mut packet_out = serde_json::Map::new();
    let mut packet_names_changed = 0;
    for (key, value) in packet_json {
        let command = key.parse::<i32>().unwrap_or_default();
        let renamed = packets
            .get(&command)
            .cloned()
            .unwrap_or_else(|| value.as_str().unwrap_or_default().to_owned());
        packet_names_changed += usize::from(value.as_str() != Some(renamed.as_str()));
        packet_out.insert(key, serde_json::Value::String(renamed));
    }
    let mut packet_ids = serde_json::to_string_pretty(&packet_out)
        .map_err(|error| format!("cannot write packet IDs: {error}"))?;
    packet_ids.push('\n');

    let summary = Summary {
        obfuscated_types_before: types_before,
        obfuscated_types_after: types_after,
        obfuscated_fields_before: fields_before,
        obfuscated_fields_after: fields_after,
        packet_names_changed,
    };
    let evidence = serde_json::json!({
        "source": "offline re-application of the embedded accepted-name manifest and token propagation to an existing dump",
        "summary": &summary,
        "accepted_names": &application.report,
        "token_propagation": &token_report,
    });
    Ok(Renamed {
        proto: write(&header, &items),
        packet_ids,
        type_aliases: application.type_aliases,
        summary,
        evidence,
    })
}

/// Rename handler-map keys (`cs-type-infos.json`, `sc-packet-handlers.json`)
/// with the type aliases of [`rename`]; output keys are sorted.
pub fn rename_handlers(json: &str, aliases: &HashMap<String, String>) -> Result<String, String> {
    let mut handlers: HashMap<String, Vec<String>> =
        serde_json::from_str(json).map_err(|error| format!("invalid handler map: {error}"))?;
    rename_handler_keys(&mut handlers, aliases);
    let sorted = handlers.into_iter().collect::<BTreeMap<_, _>>();
    serde_json::to_string_pretty(&sorted).map_err(|error| format!("cannot write handlers: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "syntax = \"proto3\"; // ex-RushiaLover ProtoDumper | Game Version: TEST\n\n\
// Obf: AAAAAAAAAAA\n\
// Type: Req\n\
// CmdID: 7\n\
// WriteTo: 0x10 | MergeFrom: 0x20\n\
message Named {\n\
\tmap<uint32, BBBBBBBBBBB> CCCCCCCCCCC = 1; // offset: 24\n\
\trepeated uint32 level_list = 2; // offset: 32\n\
\toneof DDDDDDDDDDD {\n\
\t\tBBBBBBBBBBB EEEEEEEEEEE = 3; // offset: 40\n\
\t\tuint32 FFFFFFFFFFF = 4;\n\
\t}\n\
}\n\n\
message BBBBBBBBBBB {\n\
\tuint32 retcode = 1; // offset: 16\n\
}\n\n\
enum GGGGGGGGGGG {\n\
\tGGGGGGGGGGG_HHHHHHHHHHH = 0;\n\
\tGGGGGGGGGGG_IIIIIIIIIII = 1;\n\
}\n\n";

    #[test]
    fn dump_text_round_trips() {
        let (header, items) = parse(SAMPLE).unwrap();
        assert_eq!(write(&header, &items), SAMPLE);
        let first = items[0].borrow();
        let ProtoItem::Message(message) = &*first else {
            panic!()
        };
        assert_eq!(message.name, "AAAAAAAAAAA");
        assert_eq!(message.deobfuscated_name.as_deref(), Some("Named"));
        assert_eq!(message.cmd_id, 7);
        assert_eq!(message.oneofs[0].fields.len(), 2);
    }

    #[test]
    fn unsupported_lines_fail_closed() {
        let input = SAMPLE.replace("\tuint32 retcode = 1; // offset: 16", "\treserved 5;");
        assert!(parse(&input).is_err());
    }
}
