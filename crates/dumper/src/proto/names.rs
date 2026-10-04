//! Apply recovered names as a single, checked step. A rejected name never
//! changes the field tag, type, offset, or oneof membership.
use std::collections::{HashMap, HashSet};

use super::output::{ProtoItem, TypeToItemMap, short_name, snake_field};

pub(super) fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub(super) fn map_kind(kind: &str, mut translate: impl FnMut(&str) -> String) -> String {
    let mut result = String::new();
    let mut start = 0;
    for (index, ch) in kind.char_indices() {
        if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.') {
            if start != index {
                result.push_str(&translate(&kind[start..index]));
            }
            result.push(ch);
            start = index + ch.len_utf8();
        }
    }
    if start < kind.len() {
        result.push_str(&translate(&kind[start..]));
    }
    result
}

fn resolved_type(token: &str, aliases: &HashMap<String, String>) -> String {
    let mut suffix = token;
    loop {
        if let Some(name) = aliases.get(suffix) {
            return name.clone();
        }
        let Some((_, rest)) = suffix.split_once('.') else {
            return token.to_owned();
        };
        suffix = rest;
    }
}

fn display_field(name: &str) -> String {
    snake_field(name)
}

// Match the frontend's prost-reflect/protox duplicate-field check: ASCII
// lowercase without underscores (stricter than comparing JSON spellings).
pub(super) fn field_name_key(name: &str) -> String {
    name.chars()
        .filter(|ch| *ch != '_')
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

pub(super) fn protox_map_entry_name(field_name: &str) -> String {
    let mut result = String::with_capacity(field_name.len() + "Entry".len());
    let mut uppercase_next = true;
    for ch in field_name.chars() {
        if ch == '_' {
            uppercase_next = true;
        } else if uppercase_next {
            result.push(ch.to_ascii_uppercase());
            uppercase_next = false;
        } else {
            result.push(ch);
        }
    }
    result.push_str("Entry");
    result
}

fn message_symbols(message: &super::output::Message) -> HashSet<String> {
    let mut symbols: HashSet<_> = message
        .fields
        .iter()
        .chain(message.oneofs.iter().flat_map(|o| o.fields.iter()))
        .map(|f| display_field(&f.name))
        .collect();
    symbols.extend(
        message
            .oneofs
            .iter()
            .map(|o| snake_field(o.name.strip_suffix("Case").unwrap_or(&o.name))),
    );
    for field in &message.fields {
        if field.kind.starts_with("map<") {
            symbols.insert(protox_map_entry_name(&display_field(&field.name)));
        }
    }
    symbols
}

pub(super) type ScopedFieldNames = HashMap<String, HashMap<u32, String>>;

pub fn apply_global_field_map(items: &mut TypeToItemMap, names: &HashMap<String, String>) {
    apply_field_maps(items, names, &ScopedFieldNames::new());
}

pub(super) fn apply_field_maps(
    items: &mut TypeToItemMap,
    global: &HashMap<String, String>,
    scoped: &ScopedFieldNames,
) {
    let mut applied = 0;
    let mut rejected = 0;
    for item in items.values() {
        let mut item = item.borrow_mut();
        let ProtoItem::Message(message) = &mut *item else {
            continue;
        };
        // Oneof members share the message's field namespace.
        let originals: Vec<_> = message
            .fields
            .iter()
            .chain(message.oneofs.iter().flat_map(|o| o.fields.iter()))
            .map(|f| f.name.clone())
            .collect();
        let message_names = scoped.get(&message.name);
        let mut proposed: Vec<_> = message
            .fields
            .iter()
            .chain(message.oneofs.iter().flat_map(|o| o.fields.iter()))
            .map(|field| {
                message_names
                    .and_then(|names| names.get(&field.number))
                    .or_else(|| global.get(&field.name))
                    .cloned()
                    .unwrap_or_else(|| field.name.clone())
            })
            .collect();
        let reserved: HashSet<_> = message
            .oneofs
            .iter()
            .map(|o| snake_field(o.name.strip_suffix("Case").unwrap_or(&o.name)))
            .chain(message.children.iter().map(|c| match &*c.borrow() {
                ProtoItem::Message(m) => {
                    short_name(m.deobfuscated_name.as_deref().unwrap_or(&m.name)).to_owned()
                }
                ProtoItem::Enum(e) => {
                    short_name(e.deobfuscated_name.as_deref().unwrap_or(&e.name)).to_owned()
                }
            }))
            .chain(message.children.iter().flat_map(|c| {
                match &*c.borrow() {
                    ProtoItem::Enum(e) => e
                        .variants
                        .iter()
                        .map(|(name, _)| name.clone())
                        .collect::<Vec<_>>(),
                    _ => vec![],
                }
            }))
            .collect();
        loop {
            let mut counts = HashMap::<String, usize>::new();
            for name in &proposed {
                *counts
                    .entry(field_name_key(&display_field(name)))
                    .or_default() += 1;
            }
            let mut changed = false;
            for (index, name) in proposed.iter_mut().enumerate() {
                if *name == originals[index] {
                    continue;
                }
                let display = display_field(name);
                let map_entry_conflict = message.fields.get(index).is_some_and(|f| {
                    f.kind.starts_with("map<")
                        && reserved.contains(&protox_map_entry_name(&display))
                });
                if !identifier(&display)
                    || counts[&field_name_key(&display)] > 1
                    || reserved.contains(&display)
                    || map_entry_conflict
                {
                    if rejected < 12 {
                        log::warn!(
                            "[Proto Names] rejected field: message={} original={} candidate={} reason=invalid-or-conflicting",
                            message.name,
                            originals[index],
                            name
                        );
                    }
                    rejected += 1;
                    *name = originals[index].clone();
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for (field, name) in message
            .fields
            .iter_mut()
            .chain(message.oneofs.iter_mut().flat_map(|o| o.fields.iter_mut()))
            .zip(proposed)
        {
            applied += usize::from(field.name != name);
            field.name = name;
        }
        // The discriminator/group is a separate symbol, not a wire field.
        let mut symbols: HashSet<_> = message
            .fields
            .iter()
            .chain(message.oneofs.iter().flat_map(|o| o.fields.iter()))
            .map(|f| display_field(&f.name))
            .collect();
        symbols.extend(reserved);
        for oneof in &mut message.oneofs {
            let original = snake_field(oneof.name.strip_suffix("Case").unwrap_or(&oneof.name));
            let Some(candidate) = global.get(&oneof.name) else {
                continue;
            };
            let display = snake_field(candidate.strip_suffix("Case").unwrap_or(candidate));
            if identifier(&display) && (display == original || !symbols.contains(&display)) {
                symbols.remove(&original);
                symbols.insert(display);
                applied += usize::from(oneof.name != *candidate);
                oneof.name = candidate.clone();
            } else {
                rejected += 1;
            }
        }
    }
    log::info!("[Proto Names] fields: applied={applied} rejected={rejected}");
}

struct TypeName {
    original: String,
    local: String,
    display: String,
    proposed: String,
    parent: Option<usize>,
}

fn type_path(index: usize, records: &[TypeName], name: fn(&TypeName) -> &str) -> String {
    let record = &records[index];
    let local = name(record);
    if let Some(parent) = record.parent {
        format!("{}.{}", type_path(parent, records, name), local)
    } else {
        local.to_owned()
    }
}

pub fn apply_type_names(
    items: &mut TypeToItemMap,
    names: &HashMap<String, String>,
) -> HashMap<String, String> {
    let array: Vec<_> = items.values().cloned().collect();
    let indices: HashMap<_, _> = array
        .iter()
        .enumerate()
        .map(|(i, item)| (std::rc::Rc::as_ptr(item), i))
        .collect();
    let mut parents = HashMap::new();
    for (index, item) in array.iter().enumerate() {
        if let ProtoItem::Message(m) = &*item.borrow() {
            for child in &m.children {
                if let Some(&child_index) = indices.get(&std::rc::Rc::as_ptr(child)) {
                    parents.insert(child_index, index);
                }
            }
        }
    }
    let mut records: Vec<_> = array
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let item = item.borrow();
            let (name, recovered) = match &*item {
                ProtoItem::Message(m) => (&m.name, &m.deobfuscated_name),
                ProtoItem::Enum(e) => (&e.name, &e.deobfuscated_name),
            };
            let local = short_name(name).to_owned();
            let proposal = recovered
                .as_ref()
                .or_else(|| names.get(name))
                .or_else(|| names.get(&local));
            TypeName {
                original: name.clone(),
                local: local.clone(),
                display: short_name(recovered.as_deref().unwrap_or(name)).to_owned(),
                proposed: proposal.map(|s| short_name(s).to_owned()).unwrap_or(local),
                parent: parents.get(&i).copied(),
            }
        })
        .collect();
    for index in 0..records.len() {
        let old_path = type_path(index, &records, |record| &record.local);
        if records[index].proposed == records[index].local
            && let Some(candidate) = names.get(&old_path)
        {
            records[index].proposed = short_name(candidate).to_owned();
        }
    }
    let mut reserved: HashMap<Option<usize>, HashSet<String>> = HashMap::new();
    for (index, item) in array.iter().enumerate() {
        match &*item.borrow() {
            ProtoItem::Message(m) => {
                reserved
                    .entry(Some(index))
                    .or_default()
                    .extend(message_symbols(m));
            }
            ProtoItem::Enum(e) => {
                reserved
                    .entry(records[index].parent)
                    .or_default()
                    .extend(e.variants.iter().map(|(name, _)| name.clone()));
            }
        }
    }
    let mut rejected = 0;
    loop {
        let mut counts = HashMap::new();
        for record in &records {
            *counts
                .entry((record.parent, record.proposed.clone()))
                .or_insert(0) += 1;
        }
        let mut changed = false;
        for record in &mut records {
            if record.proposed != record.local
                && (!identifier(&record.proposed)
                    || counts[&(record.parent, record.proposed.clone())] > 1
                    || reserved
                        .get(&record.parent)
                        .is_some_and(|symbols| symbols.contains(&record.proposed)))
            {
                if rejected < 12 {
                    log::warn!(
                        "[Proto Names] rejected type: original={} candidate={} reason=invalid-or-conflicting",
                        record.original,
                        record.proposed
                    );
                }
                record.proposed = record.local.clone();
                rejected += 1;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut aliases = HashMap::new();
    let mut ambiguous = HashSet::new();
    let mut applied = 0;
    for (i, record) in records.iter().enumerate() {
        let final_path = type_path(i, &records, |record| &record.proposed);
        let old_path = type_path(i, &records, |record| &record.local);
        // References may already use names accepted by an earlier pass.
        let display_path = type_path(i, &records, |record| &record.display);
        for alias in [&record.original, &record.local, &old_path, &display_path] {
            if let Some(previous) = aliases.insert(alias.clone(), final_path.clone())
                && previous != final_path
            {
                ambiguous.insert(alias.clone());
            }
        }
        let mut item = array[i].borrow_mut();
        let deobf = match &mut *item {
            ProtoItem::Message(m) => &mut m.deobfuscated_name,
            ProtoItem::Enum(e) => &mut e.deobfuscated_name,
        };
        applied += usize::from(record.proposed != record.local);
        *deobf = (record.proposed != record.local).then(|| record.proposed.clone());
    }
    for alias in ambiguous {
        aliases.remove(&alias);
    }
    for item in &array {
        if let ProtoItem::Message(m) = &mut *item.borrow_mut() {
            for field in m
                .fields
                .iter_mut()
                .chain(m.oneofs.iter_mut().flat_map(|o| o.fields.iter_mut()))
            {
                field.kind = map_kind(&field.kind, |token| resolved_type(token, &aliases));
            }
        }
    }
    log::info!("[Proto Names] types: applied={applied} rejected={rejected}");
    aliases
}

pub fn rename_packet_ids(ids: &mut HashMap<i32, String>, accepted: &HashMap<String, String>) {
    for name in ids.values_mut() {
        if let Some(recovered) = accepted.get(name) {
            *name = recovered.clone();
        }
    }
}

pub fn rename_handler_keys(
    handlers: &mut HashMap<String, Vec<String>>,
    accepted: &HashMap<String, String>,
) {
    let mut resolved: HashMap<String, Vec<String>> = HashMap::new();
    for (name, addresses) in std::mem::take(handlers) {
        resolved
            .entry(resolved_type(&name, accepted))
            .or_default()
            .extend(addresses);
    }
    for addresses in resolved.values_mut() {
        addresses.sort();
        addresses.dedup();
    }
    *handlers = resolved;
}

#[cfg(test)]
mod tests {
    use super::super::output::{Enum, Field, Message, MessageType, OneOf};
    use super::*;
    use reflection::runtime_type::RuntimeType;
    use std::{cell::RefCell, rc::Rc};

    fn field(name: &str, number: u32) -> Field {
        Field {
            name: name.into(),
            kind: "uint32".into(),
            number,
            offset: number * 8,
        }
    }
    fn message(name: &str) -> Message {
        Message {
            name: name.into(),
            deobfuscated_name: None,
            fields: vec![],
            oneofs: vec![],
            children: vec![],
            has_parent: false,
            msg_type: MessageType::None,
            cmd_id: 0,
            write_to_rva: 0,
            merge_from_rva: 0,
        }
    }
    fn items(message: Message) -> TypeToItemMap {
        TypeToItemMap::from([(
            RuntimeType(1),
            Rc::new(RefCell::new(ProtoItem::Message(message))),
        )])
    }

    #[test]
    fn conflicting_and_invalid_fields_stay_original_including_oneofs() {
        let mut m = message("GateServer");
        m.fields = vec![
            field("AAAAAAAAAAA", 1),
            field("BBBBBBBBBBB", 2),
            field("CCCCCCCCCCC", 3),
        ];
        m.oneofs = vec![OneOf {
            name: "ChoiceCase".into(),
            fields: vec![field("DDDDDDDDDDD", 4)],
        }];
        let mut items = items(m);
        let map = HashMap::from([
            ("AAAAAAAAAAA".into(), "color_header".into()),
            ("BBBBBBBBBBB".into(), "ColorHeader".into()),
            ("CCCCCCCCCCC".into(), "1_asset_bundle_url".into()),
            ("DDDDDDDDDDD".into(), "region_name".into()),
        ]);
        apply_global_field_map(&mut items, &map);
        let item = items.values().next().unwrap().borrow();
        let ProtoItem::Message(m) = &*item else {
            panic!()
        };
        assert_eq!(
            m.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["AAAAAAAAAAA", "BBBBBBBBBBB", "CCCCCCCCCCC"]
        );
        assert_eq!(m.oneofs[0].fields[0].name, "region_name");
        assert_eq!(m.oneofs[0].fields[0].number, 4);
        assert_eq!(m.oneofs[0].fields[0].offset, 32);
    }

    #[test]
    fn nested_references_map_values_and_packet_ids_follow_accepted_names() {
        let mut parent = message("AAAAAAAAAAA");
        let mut child = message("BBBBBBBBBBB");
        child.has_parent = true;
        let child = Rc::new(RefCell::new(ProtoItem::Message(child)));
        parent.children.push(child.clone());
        parent.fields.push(Field {
            kind: "map<uint32, Proto.AAAAAAAAAAA.BBBBBBBBBBB>".into(),
            ..field("CCCCCCCCCCC", 1)
        });
        parent.oneofs.push(OneOf {
            name: "Choice".into(),
            fields: vec![Field {
                kind: "Proto.AAAAAAAAAAA.BBBBBBBBBBB".into(),
                ..field("DDDDDDDDDDD", 2)
            }],
        });
        let mut items = items(parent);
        items.insert(RuntimeType(2), child);
        let names = HashMap::from([
            ("AAAAAAAAAAA".into(), "Outer".into()),
            ("BBBBBBBBBBB".into(), "Inner".into()),
        ]);
        let accepted = apply_type_names(&mut items, &names);
        let item = items.values().next().unwrap().borrow();
        let ProtoItem::Message(m) = &*item else {
            panic!()
        };
        assert_eq!(m.fields[0].kind, "map<uint32, Outer.Inner>");
        assert_eq!(m.oneofs[0].fields[0].kind, "Outer.Inner");
        let mut ids = HashMap::from([(5, "AAAAAAAAAAA".into())]);
        rename_packet_ids(&mut ids, &accepted);
        assert_eq!(ids[&5], "Outer");
    }

    #[test]
    fn second_pass_parent_rename_updates_previously_renamed_nested_references() {
        let mut parent = message("P");
        let mut child = message("B");
        child.has_parent = true;
        let child = Rc::new(RefCell::new(ProtoItem::Message(child)));
        let enumeration = Rc::new(RefCell::new(ProtoItem::Enum(Enum {
            name: "E".into(),
            deobfuscated_name: None,
            variants: vec![("STATUS_UNSPECIFIED".into(), 0)],
            has_parent: true,
        })));
        parent.children = vec![child.clone(), enumeration.clone()];
        let kinds = [
            "Proto.P.B",
            "Proto.P.E",
            "repeated Proto.P.B",
            "repeated Proto.P.E",
            "map<uint32, Proto.P.B>",
            "map<uint32, Proto.P.E>",
            "Proto.P.B",
            "Proto.P.E",
        ];
        let mut fields = kinds.iter().enumerate().map(|(index, kind)| Field {
            kind: (*kind).into(),
            ..field(&format!("field_{}", index + 1), index as u32 + 1)
        });
        parent.fields = fields.by_ref().take(6).collect();
        parent.oneofs = vec![OneOf {
            name: "Choice".into(),
            fields: fields.collect(),
        }];
        let mut items = items(parent);
        items.insert(RuntimeType(2), child);
        items.insert(RuntimeType(3), enumeration);

        for (names, parent_name) in [
            (
                HashMap::from([("B".into(), "Info".into()), ("E".into(), "Status".into())]),
                "P",
            ),
            (
                HashMap::from([("P".into(), "NamedParent".into())]),
                "NamedParent",
            ),
        ] {
            let accepted = apply_type_names(&mut items, &names);
            let item = items[&RuntimeType(1)].borrow();
            let ProtoItem::Message(parent) = &*item else {
                panic!()
            };
            let expected = [
                format!("{parent_name}.Info"),
                format!("{parent_name}.Status"),
                format!("repeated {parent_name}.Info"),
                format!("repeated {parent_name}.Status"),
                format!("map<uint32, {parent_name}.Info>"),
                format!("map<uint32, {parent_name}.Status>"),
                format!("{parent_name}.Info"),
                format!("{parent_name}.Status"),
            ];
            for (index, (field, kind)) in parent
                .fields
                .iter()
                .chain(parent.oneofs.iter().flat_map(|o| o.fields.iter()))
                .zip(expected)
                .enumerate()
            {
                assert_eq!(field.kind, kind);
                assert_eq!(field.name, format!("field_{}", index + 1));
                assert_eq!(field.number, index as u32 + 1);
                assert_eq!(field.offset, (index as u32 + 1) * 8);
            }
            assert_eq!(parent.name, "P");
            assert_eq!(parent.oneofs[0].name, "Choice");
            assert_eq!(accepted["B"], format!("{parent_name}.Info"));
            assert_eq!(accepted["E"], format!("{parent_name}.Status"));
            if parent_name == "NamedParent" {
                assert_eq!(parent.deobfuscated_name.as_deref(), Some("NamedParent"));
                assert_eq!(accepted["P.Info"], "NamedParent.Info");
                assert_eq!(accepted["P.Status"], "NamedParent.Status");
            }
        }
        let child = items[&RuntimeType(2)].borrow();
        let ProtoItem::Message(child) = &*child else {
            panic!()
        };
        assert_eq!(child.name, "B");
        assert_eq!(child.deobfuscated_name.as_deref(), Some("Info"));
        let enumeration = items[&RuntimeType(3)].borrow();
        let ProtoItem::Enum(enumeration) = &*enumeration else {
            panic!()
        };
        assert_eq!(enumeration.name, "E");
        assert_eq!(enumeration.deobfuscated_name.as_deref(), Some("Status"));
        assert_eq!(enumeration.variants, [("STATUS_UNSPECIFIED".into(), 0)]);
    }

    #[test]
    fn duplicate_type_proposals_do_not_change_definitions_or_references() {
        let mut a = message("AAAAAAAAAAA");
        a.fields.push(Field {
            kind: "Proto.BBBBBBBBBBB".into(),
            ..field("CCCCCCCCCCC", 1)
        });
        let mut items = items(a);
        items.insert(
            RuntimeType(2),
            Rc::new(RefCell::new(ProtoItem::Message(message("BBBBBBBBBBB")))),
        );
        let accepted = apply_type_names(
            &mut items,
            &HashMap::from([
                ("AAAAAAAAAAA".into(), "Same".into()),
                ("BBBBBBBBBBB".into(), "Same".into()),
            ]),
        );
        assert_eq!(accepted["AAAAAAAAAAA"], "AAAAAAAAAAA");
        assert_eq!(accepted["BBBBBBBBBBB"], "BBBBBBBBBBB");
        let item = items.values().next().unwrap().borrow();
        let ProtoItem::Message(m) = &*item else {
            panic!()
        };
        assert_eq!(m.fields[0].kind, "BBBBBBBBBBB");
    }

    #[test]
    fn uppercase_map_entry_blocks_nested_type_alias() {
        let mut parent = message("PPPPPPPPPPP");
        parent.fields.push(Field {
            kind: "map<string, uint32>".into(),
            ..field("HEDHGPKEGBI", 1)
        });
        let mut child = message("CCCCCCCCCCC");
        child.has_parent = true;
        let child = Rc::new(RefCell::new(ProtoItem::Message(child)));
        parent.children.push(child.clone());
        let mut items = items(parent);
        items.insert(RuntimeType(2), child);

        apply_type_names(
            &mut items,
            &HashMap::from([("CCCCCCCCCCC".into(), "HEDHGPKEGBIEntry".into())]),
        );

        let item = items[&RuntimeType(2)].borrow();
        let ProtoItem::Message(child) = &*item else {
            panic!()
        };
        assert_eq!(child.deobfuscated_name, None);
    }

    #[test]
    fn uppercase_map_field_alias_cannot_shadow_nested_type() {
        let mut parent = message("PPPPPPPPPPP");
        parent.fields.push(Field {
            kind: "map<string, uint32>".into(),
            ..field("FFFFFFFFFFF", 1)
        });
        let mut child = message("HEDHGPKEGBIEntry");
        child.has_parent = true;
        let child = Rc::new(RefCell::new(ProtoItem::Message(child)));
        parent.children.push(child.clone());
        let mut items = items(parent);
        items.insert(RuntimeType(2), child);

        apply_global_field_map(
            &mut items,
            &HashMap::from([("FFFFFFFFFFF".into(), "HEDHGPKEGBI".into())]),
        );

        let item = items[&RuntimeType(1)].borrow();
        let ProtoItem::Message(parent) = &*item else {
            panic!()
        };
        assert_eq!(parent.fields[0].name, "FFFFFFFFFFF");
    }

    #[test]
    fn field_candidate_without_underscore_cannot_collide_with_existing_field() {
        let mut m = message("BattleAvatar");
        m.fields = vec![field("buff_list", 1), field("AAAAAAAAAAA", 2)];
        let mut items = items(m);
        apply_global_field_map(
            &mut items,
            &HashMap::from([("AAAAAAAAAAA".into(), "bufflist".into())]),
        );

        let item = items.values().next().unwrap().borrow();
        let ProtoItem::Message(m) = &*item else {
            panic!()
        };
        assert_eq!(m.fields[0].name, "buff_list");
        assert_eq!(m.fields[1].name, "AAAAAAAAAAA");
        assert_eq!(m.fields[1].kind, "uint32");
        assert_eq!(m.fields[1].number, 2);
        assert_eq!(m.fields[1].offset, 16);
    }

    #[test]
    fn scoped_fields_use_exact_message_and_tag_without_cross_message_leaks() {
        let mut first = message("AAAAAAAAAAA");
        first.fields = vec![field("CCCCCCCCCCC", 1), field("DDDDDDDDDDD", 2)];
        first.deobfuscated_name = Some("RecoveredFirst".into());
        let mut second = message("BBBBBBBBBBB");
        second.fields = vec![field("CCCCCCCCCCC", 7)];
        let mut items = items(first);
        items.insert(
            RuntimeType(2),
            Rc::new(RefCell::new(ProtoItem::Message(second))),
        );
        let scoped = ScopedFieldNames::from([
            (
                "AAAAAAAAAAA".into(),
                HashMap::from([(1, "avatar_id".into()), (7, "wrong_tag".into())]),
            ),
            ("BBBBBBBBBBB".into(), HashMap::from([(7, "shop_id".into())])),
            (
                "RecoveredFirst".into(),
                HashMap::from([(2, "wrong_message".into())]),
            ),
        ]);
        apply_field_maps(&mut items, &HashMap::new(), &scoped);

        for (runtime_type, expected) in [
            (RuntimeType(1), vec!["avatar_id", "DDDDDDDDDDD"]),
            (RuntimeType(2), vec!["shop_id"]),
        ] {
            let item = items[&runtime_type].borrow();
            let ProtoItem::Message(m) = &*item else {
                panic!()
            };
            assert_eq!(
                m.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn scoped_names_override_global_for_regular_and_oneof_fields_only() {
        let mut m = message("AAAAAAAAAAA");
        m.fields = vec![field("BBBBBBBBBBB", 1)];
        m.oneofs = vec![OneOf {
            name: "DDDDDDDDDDDCase".into(),
            fields: vec![field("CCCCCCCCCCC", 2)],
        }];
        let mut items = items(m);
        let global = HashMap::from([
            ("BBBBBBBBBBB".into(), "global_regular".into()),
            ("CCCCCCCCCCC".into(), "global_oneof".into()),
            ("DDDDDDDDDDDCase".into(), "PayloadCase".into()),
        ]);
        let scoped = ScopedFieldNames::from([(
            "AAAAAAAAAAA".into(),
            HashMap::from([(1, "scoped_regular".into()), (2, "scoped_oneof".into())]),
        )]);
        apply_field_maps(&mut items, &global, &scoped);

        let item = items[&RuntimeType(1)].borrow();
        let ProtoItem::Message(m) = &*item else {
            panic!()
        };
        assert_eq!(m.fields[0].name, "scoped_regular");
        assert_eq!(m.oneofs[0].fields[0].name, "scoped_oneof");
        assert_eq!(m.oneofs[0].name, "PayloadCase");
        for (field, tag) in [(&m.fields[0], 1), (&m.oneofs[0].fields[0], 2)] {
            assert_eq!(field.number, tag);
            assert_eq!(field.kind, "uint32");
            assert_eq!(field.offset, tag * 8);
        }
    }

    #[test]
    fn conflicting_or_invalid_scoped_names_revert_to_raw_names_not_global_names() {
        let mut m = message("AAAAAAAAAAA");
        m.fields = vec![field("BBBBBBBBBBB", 1), field("CCCCCCCCCCC", 2)];
        m.oneofs = vec![OneOf {
            name: "ChoiceCase".into(),
            fields: vec![field("DDDDDDDDDDD", 3)],
        }];
        let mut items = items(m);
        let global = HashMap::from([
            ("BBBBBBBBBBB".into(), "global_first".into()),
            ("CCCCCCCCCCC".into(), "global_second".into()),
            ("DDDDDDDDDDD".into(), "global_third".into()),
        ]);
        let scoped = ScopedFieldNames::from([(
            "AAAAAAAAAAA".into(),
            HashMap::from([
                (1, "buff_list".into()),
                (2, "BuffList".into()),
                (3, "1_invalid".into()),
            ]),
        )]);
        apply_field_maps(&mut items, &global, &scoped);

        let item = items[&RuntimeType(1)].borrow();
        let ProtoItem::Message(m) = &*item else {
            panic!()
        };
        let fields: Vec<_> = m
            .fields
            .iter()
            .chain(m.oneofs.iter().flat_map(|o| o.fields.iter()))
            .collect();
        for (field, (raw, tag)) in
            fields
                .iter()
                .zip([("BBBBBBBBBBB", 1), ("CCCCCCCCCCC", 2), ("DDDDDDDDDDD", 3)])
        {
            assert_eq!(field.name, raw);
            assert_eq!(field.number, tag);
            assert_eq!(field.kind, "uint32");
            assert_eq!(field.offset, tag * 8);
        }
        assert_eq!(m.oneofs[0].name, "ChoiceCase");
    }

    #[test]
    fn nested_type_candidates_cannot_shadow_existing_field_or_enum_value() {
        for candidate in ["collision", "COLLISION"] {
            let mut parent = message("Outer");
            parent.fields = vec![
                field("collision", 1),
                Field {
                    kind: "repeated Proto.Outer.BBBBBBBBBBB".into(),
                    ..field("CCCCCCCCCCC", 2)
                },
            ];
            let mut child = message("BBBBBBBBBBB");
            child.has_parent = true;
            let child = Rc::new(RefCell::new(ProtoItem::Message(child)));
            let enumeration = Rc::new(RefCell::new(ProtoItem::Enum(Enum {
                name: "Status".into(),
                deobfuscated_name: None,
                variants: vec![("COLLISION".into(), 0)],
                has_parent: true,
            })));
            parent.children = vec![child.clone(), enumeration.clone()];
            let mut items = items(parent);
            items.insert(RuntimeType(2), child.clone());
            items.insert(RuntimeType(3), enumeration);

            let accepted = apply_type_names(
                &mut items,
                &HashMap::from([("BBBBBBBBBBB".into(), candidate.into())]),
            );
            assert_eq!(accepted["BBBBBBBBBBB"], "Outer.BBBBBBBBBBB");
            let child = child.borrow();
            let ProtoItem::Message(child) = &*child else {
                panic!()
            };
            assert_eq!(child.name, "BBBBBBBBBBB");
            assert_eq!(child.deobfuscated_name, None);
            let parent = items[&RuntimeType(1)].borrow();
            let ProtoItem::Message(parent) = &*parent else {
                panic!()
            };
            assert_eq!(parent.fields[0].name, "collision");
            assert_eq!(parent.fields[1].kind, "repeated Outer.BBBBBBBBBBB");
            assert_eq!(parent.fields[1].number, 2);
            assert_eq!(parent.fields[1].offset, 16);
        }
    }

    #[test]
    fn handler_keys_use_final_type_names_and_merge_addresses_after_rejection() {
        let mut items = items(message("AAAAAAAAAAA"));
        for (index, name) in [(2, "BBBBBBBBBBB"), (3, "CCCCCCCCCCC")] {
            items.insert(
                RuntimeType(index),
                Rc::new(RefCell::new(ProtoItem::Message(message(name)))),
            );
        }
        let accepted = apply_type_names(
            &mut items,
            &HashMap::from([
                ("AAAAAAAAAAA".into(), "Recovered".into()),
                ("BBBBBBBBBBB".into(), "Rejected".into()),
                ("CCCCCCCCCCC".into(), "Rejected".into()),
            ]),
        );
        let mut handlers = HashMap::from([
            ("AAAAAAAAAAA".into(), vec!["0x20".into(), "0x10".into()]),
            (
                "Proto.AAAAAAAAAAA".into(),
                vec!["0x30".into(), "0x20".into()],
            ),
            ("BBBBBBBBBBB".into(), vec!["0x40".into(), "0x40".into()]),
            ("Proto.BBBBBBBBBBB".into(), vec!["0x50".into()]),
            ("CCCCCCCCCCC".into(), vec!["0x60".into()]),
        ]);
        rename_handler_keys(&mut handlers, &accepted);

        assert_eq!(handlers.len(), 3);
        assert_eq!(handlers["Recovered"], ["0x10", "0x20", "0x30"]);
        assert_eq!(handlers["BBBBBBBBBBB"], ["0x40", "0x50"]);
        assert_eq!(handlers["CCCCCCCCCCC"], ["0x60"]);
        assert!(!handlers.contains_key("Rejected"));
        assert!(!handlers.contains_key("AAAAAAAAAAA"));
        assert!(!handlers.contains_key("Proto.AAAAAAAAAAA"));
        assert!(!handlers.contains_key("Proto.BBBBBBBBBBB"));
    }
}
