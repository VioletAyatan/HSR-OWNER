//! Propagate recovered field names across messages by obfuscated token.
//!
//! The client's obfuscator maps an original identifier to the same 11-letter
//! A-P token wherever it occurs (verified across client versions: 4.5.51 and
//! 4.6.51 share 5127 type tokens and keep per-message field tokens while wire
//! tags are reshuffled; `Retcode` is one token in ~1160 messages). A field
//! token resolved in one message therefore names every other field carrying
//! that token, and one name cannot belong to two tokens.
//!
//! Aliases from the embedded accepted-name database come from reference
//! protos, so they are checked against names recovered from the running
//! client: an alias is reverted only when the client assigns its name to
//! another token with clearly more support (e.g. `retcode` on a request
//! field). Other disagreements are reported, not resolved. Accepted aliases
//! only seed tokens that have no client name. Every proposal still passes the per-message collision checks
//! in `names::apply_field_maps`.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use super::{
    names::{ScopedFieldNames, apply_field_maps, field_name_key},
    output::{Field, Message, ProtoItem, TypeToItemMap, snake_field},
};

/// Field names keyed by original message name and wire tag.
pub(super) type FieldNameSnapshot = HashMap<(String, u32), String>;

/// A name owned by another token needs at least this many client fields.
const MIN_OWNER_SUPPORT: usize = 2;

pub(super) fn is_token(name: &str) -> bool {
    name.len() == 11 && name.bytes().all(|b| (b'A'..=b'P').contains(&b))
}

#[derive(Serialize)]
struct Source {
    message: String,
    tag: u32,
    name: String,
    origin: &'static str,
}

#[derive(Serialize)]
struct Target {
    message: String,
    tag: u32,
    status: &'static str,
}

#[derive(Serialize, Default)]
struct TokenRecord {
    candidate: Option<String>,
    sources: Vec<Source>,
    targets: Vec<Target>,
}

#[derive(Serialize)]
struct AliasCheck {
    message: String,
    tag: u32,
    token: String,
    alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    restored: Option<String>,
    reason: &'static str,
    client_evidence: Vec<String>,
}

#[derive(Serialize, Default)]
pub(super) struct Report {
    accepted_aliases_checked: usize,
    accepted_aliases_reverted: usize,
    tokens_resolved: usize,
    tokens_conflicting: usize,
    fields_proposed: usize,
    fields_applied: usize,
    fields_rejected: usize,
    obfuscated_fields_before: usize,
    obfuscated_fields_after: usize,
    reverted_aliases: Vec<AliasCheck>,
    alias_conflicts: Vec<AliasCheck>,
    tokens: BTreeMap<String, TokenRecord>,
}

fn message_fields(message: &Message) -> impl Iterator<Item = &Field> {
    message
        .fields
        .iter()
        .chain(message.oneofs.iter().flat_map(|o| o.fields.iter()))
}

fn message_fields_mut(message: &mut Message) -> impl Iterator<Item = &mut Field> {
    message
        .fields
        .iter_mut()
        .chain(message.oneofs.iter_mut().flat_map(|o| o.fields.iter_mut()))
}

/// Current field names; take it before accepted aliases are applied.
pub(super) fn snapshot(items: &TypeToItemMap) -> FieldNameSnapshot {
    let mut result = FieldNameSnapshot::new();
    for item in items.values() {
        if let ProtoItem::Message(message) = &*item.borrow() {
            for field in message_fields(message) {
                result.insert((message.name.clone(), field.number), field.name.clone());
            }
        }
    }
    result
}

/// Raw wire tag -> obfuscated token, per raw message name. `retcode_token` is
/// the client's token for `retcode`, which the raw output already renames.
fn raw_tokens(raw: &TypeToItemMap, retcode_token: &str) -> HashMap<String, HashMap<u32, String>> {
    let retcode_token = is_token(retcode_token).then_some(retcode_token);
    let mut result = HashMap::new();
    for item in raw.values() {
        let item = item.borrow();
        let ProtoItem::Message(message) = &*item else {
            continue;
        };
        let tokens: HashMap<_, _> = message_fields(message)
            .filter_map(|field| {
                if is_token(&field.name) {
                    Some((field.number, field.name.clone()))
                } else if field.name == "retcode" {
                    retcode_token.map(|token| (field.number, token.to_owned()))
                } else {
                    None
                }
            })
            .collect();
        if !tokens.is_empty() {
            result.insert(message.name.clone(), tokens);
        }
    }
    result
}

fn count_obfuscated(items: &TypeToItemMap) -> usize {
    items
        .values()
        .map(|item| match &*item.borrow() {
            ProtoItem::Message(message) => message_fields(message)
                .filter(|f| is_token(&f.name))
                .count(),
            ProtoItem::Enum(_) => 0,
        })
        .sum()
}

fn key(name: &str) -> String {
    field_name_key(&snake_field(name))
}

/// Single consistent name (most common spelling) or `None` on conflict.
fn consensus<'a>(names: impl Iterator<Item = &'a str>) -> Option<Option<String>> {
    let mut spellings = BTreeMap::<String, usize>::new();
    for name in names {
        *spellings.entry(snake_field(name)).or_default() += 1;
    }
    if spellings.is_empty() {
        return None;
    }
    let keys: BTreeSet<_> = spellings.keys().map(|n| field_name_key(n)).collect();
    if keys.len() != 1 {
        return Some(None);
    }
    Some(
        spellings
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(name, _)| name),
    )
}

struct Observed {
    message: String,
    tag: u32,
    token: String,
    name: String,
    before: Option<String>,
}

/// `raw` must be generated from the same minimal infos without field names and
/// `client` must be the snapshot taken before accepted aliases were applied;
/// all maps keep the original (obfuscated) message name in `Message::name`.
pub(super) fn propagate(
    raw: &TypeToItemMap,
    retcode_token: &str,
    client: &FieldNameSnapshot,
    items: &mut TypeToItemMap,
) -> Report {
    let raw_tokens = raw_tokens(raw, retcode_token);
    let mut report = Report {
        obfuscated_fields_before: count_obfuscated(items),
        ..Default::default()
    };
    let mut observed = Vec::new();
    for item in items.values() {
        let item = item.borrow();
        let ProtoItem::Message(message) = &*item else {
            continue;
        };
        let Some(tokens) = raw_tokens.get(&message.name) else {
            continue;
        };
        for field in message_fields(message) {
            if let Some(token) = tokens.get(&field.number) {
                observed.push(Observed {
                    message: message.name.clone(),
                    tag: field.number,
                    token: token.clone(),
                    name: field.name.clone(),
                    before: client.get(&(message.name.clone(), field.number)).cloned(),
                });
            }
        }
    }
    let is_client = |o: &Observed| o.name != o.token && o.before.as_deref() == Some(&o.name);
    let is_alias = |o: &Observed| o.name != o.token && o.before.as_deref() != Some(&o.name);

    // Client evidence: token -> names, and name key -> owning tokens.
    let mut client_names = HashMap::<String, Vec<String>>::new();
    let mut owners = HashMap::<String, BTreeMap<String, usize>>::new();
    for o in observed.iter().filter(|o| is_client(o)) {
        client_names
            .entry(o.token.clone())
            .or_default()
            .push(o.name.clone());
        *owners
            .entry(key(&o.name))
            .or_default()
            .entry(o.token.clone())
            .or_default() += 1;
    }

    // Check accepted aliases against client evidence. Only a name that the
    // client clearly assigns to another token is proof that an alias is wrong;
    // other disagreements are reported and the alias is kept.
    let mut alias_support = HashMap::<(String, &str), usize>::new();
    for o in observed.iter().filter(|o| is_alias(o)) {
        *alias_support.entry((key(&o.name), &o.token)).or_default() += 1;
    }
    let mut reverts = HashMap::<(String, u32), String>::new();
    for o in observed.iter().filter(|o| is_alias(o)) {
        report.accepted_aliases_checked += 1;
        let alias_key = key(&o.name);
        if let Some(tokens) = owners.get(&alias_key)
            && !tokens.contains_key(&o.token)
        {
            let owner_support: usize = tokens.values().sum();
            let support = alias_support[&(alias_key.clone(), o.token.as_str())];
            if owner_support >= MIN_OWNER_SUPPORT && owner_support >= 2 * support {
                let restored = o.before.clone().unwrap_or_else(|| o.token.clone());
                reverts.insert((o.message.clone(), o.tag), restored.clone());
                report.reverted_aliases.push(AliasCheck {
                    message: o.message.clone(),
                    tag: o.tag,
                    token: o.token.clone(),
                    alias: o.name.clone(),
                    restored: Some(restored),
                    reason: "name-owned-by-other-token",
                    client_evidence: tokens
                        .iter()
                        .map(|(token, count)| format!("{token} x{count}"))
                        .collect(),
                });
                continue;
            }
        }
        if let Some(names) = client_names.get(&o.token)
            && !names.iter().any(|n| key(n) == alias_key)
        {
            let evidence: BTreeSet<_> = names.iter().map(|n| snake_field(n)).collect();
            report.alias_conflicts.push(AliasCheck {
                message: o.message.clone(),
                tag: o.tag,
                token: o.token.clone(),
                alias: o.name.clone(),
                restored: None,
                reason: "token-has-different-client-name",
                client_evidence: evidence.into_iter().collect(),
            });
        } else if let Some(tokens) = owners.get(&alias_key)
            && !tokens.contains_key(&o.token)
        {
            report.alias_conflicts.push(AliasCheck {
                message: o.message.clone(),
                tag: o.tag,
                token: o.token.clone(),
                alias: o.name.clone(),
                restored: None,
                reason: "name-also-used-by-other-token",
                client_evidence: tokens
                    .iter()
                    .map(|(token, count)| format!("{token} x{count}"))
                    .collect(),
            });
        }
    }
    report.accepted_aliases_reverted = reverts.len();
    if !reverts.is_empty() {
        for item in items.values() {
            let mut item = item.borrow_mut();
            let ProtoItem::Message(message) = &mut *item else {
                continue;
            };
            let name = message.name.clone();
            for field in message_fields_mut(message) {
                if let Some(restored) = reverts.get(&(name.clone(), field.number)) {
                    field.name = restored.clone();
                }
            }
        }
        for o in &mut observed {
            if let Some(restored) = reverts.get(&(o.message.clone(), o.tag)) {
                o.name = restored.clone();
            }
        }
    }

    // Sources: client names, or surviving aliases for tokens without any.
    let mut unresolved = Vec::new();
    for o in &observed {
        if o.name == o.token {
            unresolved.push((o.message.clone(), o.tag, o.token.clone()));
            continue;
        }
        let client_source = is_client(o);
        if !client_source && client_names.contains_key(&o.token) {
            continue;
        }
        report
            .tokens
            .entry(o.token.clone())
            .or_default()
            .sources
            .push(Source {
                message: o.message.clone(),
                tag: o.tag,
                name: o.name.clone(),
                origin: if client_source {
                    "client"
                } else {
                    "accepted-alias"
                },
            });
    }

    for record in report.tokens.values_mut() {
        match consensus(record.sources.iter().map(|s| s.name.as_str())) {
            Some(Some(candidate)) => {
                record.candidate = Some(candidate);
                report.tokens_resolved += 1;
            }
            Some(None) => report.tokens_conflicting += 1,
            None => {}
        }
    }

    let mut scoped = ScopedFieldNames::new();
    for (message, tag, token) in &unresolved {
        let Some(candidate) = report.tokens.get(token).and_then(|r| r.candidate.clone()) else {
            continue;
        };
        scoped
            .entry(message.clone())
            .or_default()
            .insert(*tag, candidate);
        report.fields_proposed += 1;
    }
    apply_field_maps(items, &HashMap::new(), &scoped);

    // Read back the outcome: the shared collision checks may reject proposals.
    let mut applied = HashMap::<(String, u32), bool>::new();
    for item in items.values() {
        let item = item.borrow();
        let ProtoItem::Message(message) = &*item else {
            continue;
        };
        if let Some(fields) = scoped.get(&message.name) {
            for field in message_fields(message) {
                if let Some(candidate) = fields.get(&field.number) {
                    applied.insert(
                        (message.name.clone(), field.number),
                        field.name == *candidate,
                    );
                }
            }
        }
    }
    for (message, tag, token) in unresolved {
        let Some(record) = report.tokens.get_mut(&token) else {
            continue;
        };
        if record.candidate.is_none() {
            record.targets.push(Target {
                message,
                tag,
                status: "skipped-conflicting-sources",
            });
            continue;
        }
        let ok = applied
            .get(&(message.clone(), tag))
            .copied()
            .unwrap_or(false);
        if ok {
            report.fields_applied += 1;
        } else {
            report.fields_rejected += 1;
        }
        record.targets.push(Target {
            message,
            tag,
            status: if ok { "applied" } else { "rejected-collision" },
        });
    }
    // Keep tokens that changed or could not change a field, plus every token
    // whose recovered names disagree: the obfuscator maps one original name to
    // one token, so such a token proves at least one existing name is wrong.
    report
        .tokens
        .retain(|_, record| !record.targets.is_empty() || record.candidate.is_none());
    report.obfuscated_fields_after = count_obfuscated(items);
    log::info!(
        "[Proto Names] token propagation: aliases_checked={} aliases_reverted={} tokens_resolved={} tokens_conflicting={} proposed={} applied={} rejected={} obfuscated_fields {} -> {}",
        report.accepted_aliases_checked,
        report.accepted_aliases_reverted,
        report.tokens_resolved,
        report.tokens_conflicting,
        report.fields_proposed,
        report.fields_applied,
        report.fields_rejected,
        report.obfuscated_fields_before,
        report.obfuscated_fields_after
    );
    report
}

#[cfg(test)]
mod tests {
    use super::super::output::{Message, MessageType, OneOf};
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

    fn message(name: &str, fields: Vec<Field>) -> Rc<RefCell<ProtoItem>> {
        Rc::new(RefCell::new(ProtoItem::Message(Message {
            name: name.into(),
            deobfuscated_name: None,
            fields,
            oneofs: vec![],
            children: vec![],
            has_parent: false,
            msg_type: MessageType::None,
            cmd_id: 0,
            write_to_rva: 0,
            merge_from_rva: 0,
        })))
    }

    fn names(items: &TypeToItemMap, key: usize) -> Vec<String> {
        match &*items[&RuntimeType(key)].borrow() {
            ProtoItem::Message(m) => message_fields(m).map(|f| f.name.clone()).collect(),
            ProtoItem::Enum(_) => vec![],
        }
    }

    #[test]
    fn resolved_token_names_other_messages_with_collision_and_conflict_guards() {
        let raw = TypeToItemMap::from([
            (
                RuntimeType(1),
                message(
                    "AAAAAAAAAAA",
                    vec![field("KKKKKKKKKKK", 1), field("LLLLLLLLLLL", 2)],
                ),
            ),
            (
                RuntimeType(2),
                message(
                    "BBBBBBBBBBB",
                    vec![
                        field("KKKKKKKKKKK", 7),
                        field("LLLLLLLLLLL", 8),
                        field("MMMMMMMMMMM", 9),
                    ],
                ),
            ),
            (
                RuntimeType(3),
                message(
                    "CCCCCCCCCCC",
                    vec![field("MMMMMMMMMMM", 3), field("NNNNNNNNNNN", 4)],
                ),
            ),
            (
                RuntimeType(4),
                message("DDDDDDDDDDD", vec![field("NNNNNNNNNNN", 5)]),
            ),
        ]);
        let mut items = TypeToItemMap::from([
            // KKK resolved as avatar_id; LLL resolved here...
            (
                RuntimeType(1),
                message("AAAAAAAAAAA", vec![field("avatarId", 1), field("level", 2)]),
            ),
            // ...but this message already has a different `level` field.
            (
                RuntimeType(2),
                message(
                    "BBBBBBBBBBB",
                    vec![
                        field("KKKKKKKKKKK", 7),
                        field("LLLLLLLLLLL", 8),
                        field("level", 9),
                    ],
                ),
            ),
            // NNN has two different recovered names: never propagated.
            (
                RuntimeType(3),
                message(
                    "CCCCCCCCCCC",
                    vec![field("MMMMMMMMMMM", 3), field("exp", 4)],
                ),
            ),
            (
                RuntimeType(4),
                message("DDDDDDDDDDD", vec![field("score", 5)]),
            ),
        ]);
        let client = snapshot(&items);
        let report = propagate(&raw, "", &client, &mut items);
        assert_eq!(names(&items, 2), ["avatar_id", "LLLLLLLLLLL", "level"]);
        // MMM was resolved as `level` in message 2; message 3 accepts it.
        assert_eq!(names(&items, 3), ["level", "exp"]);
        assert_eq!(report.fields_applied, 2);
        assert_eq!(report.fields_rejected, 1);
        assert_eq!(report.tokens_conflicting, 1);
        assert_eq!(report.obfuscated_fields_before, 3);
        assert_eq!(report.obfuscated_fields_after, 1);
    }

    #[test]
    fn oneof_members_participate_and_tags_are_never_changed() {
        let mut raw_message = Message {
            name: "AAAAAAAAAAA".into(),
            deobfuscated_name: None,
            fields: vec![],
            oneofs: vec![OneOf {
                name: "PPPPPPPPPPPCase".into(),
                fields: vec![field("KKKKKKKKKKK", 11)],
            }],
            children: vec![],
            has_parent: false,
            msg_type: MessageType::None,
            cmd_id: 0,
            write_to_rva: 0,
            merge_from_rva: 0,
        };
        let raw = TypeToItemMap::from([
            (
                RuntimeType(1),
                Rc::new(RefCell::new(ProtoItem::Message(Message {
                    name: raw_message.name.clone(),
                    deobfuscated_name: None,
                    fields: vec![],
                    oneofs: vec![OneOf {
                        name: "PPPPPPPPPPPCase".into(),
                        fields: vec![field("KKKKKKKKKKK", 11)],
                    }],
                    children: vec![],
                    has_parent: false,
                    msg_type: MessageType::None,
                    cmd_id: 0,
                    write_to_rva: 0,
                    merge_from_rva: 0,
                }))),
            ),
            (
                RuntimeType(2),
                message("BBBBBBBBBBB", vec![field("KKKKKKKKKKK", 3)]),
            ),
        ]);
        raw_message.oneofs[0].fields[0].name = "rogue_info".into();
        let mut items = TypeToItemMap::from([
            (
                RuntimeType(1),
                Rc::new(RefCell::new(ProtoItem::Message(raw_message))),
            ),
            (
                RuntimeType(2),
                message("BBBBBBBBBBB", vec![field("KKKKKKKKKKK", 3)]),
            ),
        ]);
        let client = snapshot(&items);
        propagate(&raw, "", &client, &mut items);
        match &*items[&RuntimeType(2)].borrow() {
            ProtoItem::Message(m) => {
                assert_eq!(m.fields[0].name, "rogue_info");
                assert_eq!(m.fields[0].number, 3);
                assert_eq!(m.fields[0].offset, 24);
            }
            ProtoItem::Enum(_) => panic!(),
        }
    }

    fn set_name(items: &TypeToItemMap, key: usize, tag: u32, name: &str) {
        if let ProtoItem::Message(m) = &mut *items[&RuntimeType(key)].borrow_mut() {
            for f in message_fields_mut(m) {
                if f.number == tag {
                    f.name = name.into();
                }
            }
        }
    }

    #[test]
    fn accepted_aliases_are_checked_against_client_names_and_never_spread_over_them() {
        let raw = TypeToItemMap::from([
            (
                RuntimeType(1),
                message("AAAAAAAAAAA", vec![field("KKKKKKKKKKK", 1)]),
            ),
            (
                RuntimeType(2),
                message("BBBBBBBBBBB", vec![field("KKKKKKKKKKK", 2)]),
            ),
            (
                RuntimeType(3),
                message("CCCCCCCCCCC", vec![field("LLLLLLLLLLL", 3)]),
            ),
            (
                RuntimeType(4),
                message("DDDDDDDDDDD", vec![field("LLLLLLLLLLL", 4)]),
            ),
            (
                RuntimeType(5),
                message("EEEEEEEEEEE", vec![field("MMMMMMMMMMM", 5)]),
            ),
            (
                RuntimeType(6),
                message("FFFFFFFFFFF", vec![field("MMMMMMMMMMM", 6)]),
            ),
            (
                RuntimeType(7),
                message("GGGGGGGGGGG", vec![field("NNNNNNNNNNN", 7)]),
            ),
            (
                RuntimeType(8),
                message("HHHHHHHHHHH", vec![field("NNNNNNNNNNN", 8)]),
            ),
        ]);
        let mut items = TypeToItemMap::from([
            // Client evidence: KKK is retcode in two messages, LLL is level_id.
            (
                RuntimeType(1),
                message("AAAAAAAAAAA", vec![field("retcode", 1)]),
            ),
            (
                RuntimeType(2),
                message("BBBBBBBBBBB", vec![field("retcode", 2)]),
            ),
            (
                RuntimeType(3),
                message("CCCCCCCCCCC", vec![field("level_id", 3)]),
            ),
            (
                RuntimeType(4),
                message("DDDDDDDDDDD", vec![field("LLLLLLLLLLL", 4)]),
            ),
            (
                RuntimeType(5),
                message("EEEEEEEEEEE", vec![field("MMMMMMMMMMM", 5)]),
            ),
            (
                RuntimeType(6),
                message("FFFFFFFFFFF", vec![field("MMMMMMMMMMM", 6)]),
            ),
            (
                RuntimeType(7),
                message("GGGGGGGGGGG", vec![field("NNNNNNNNNNN", 7)]),
            ),
            (
                RuntimeType(8),
                message("HHHHHHHHHHH", vec![field("NNNNNNNNNNN", 8)]),
            ),
        ]);
        let client = snapshot(&items);
        // Accepted aliases applied after the snapshot.
        set_name(&items, 4, 4, "stage_id"); // LLL has client name level_id
        set_name(&items, 5, 5, "retcode"); // retcode belongs to KKK
        set_name(&items, 7, 7, "dungeon_id"); // no conflict: kept and spread
        let report = propagate(&raw, "", &client, &mut items);
        // Disagreement with the token's client name is reported, not resolved.
        assert_eq!(names(&items, 4), ["stage_id"]);
        // `retcode` belongs to KKK (2 client fields vs 1 alias): reverted.
        assert_eq!(names(&items, 5), ["MMMMMMMMMMM"]);
        assert_eq!(names(&items, 6), ["MMMMMMMMMMM"]);
        assert_eq!(names(&items, 7), ["dungeon_id"]);
        assert_eq!(names(&items, 8), ["dungeon_id"]);
        assert_eq!(report.accepted_aliases_checked, 3);
        assert_eq!(report.accepted_aliases_reverted, 1);
        assert_eq!(
            report.reverted_aliases[0].reason,
            "name-owned-by-other-token"
        );
        assert_eq!(report.alias_conflicts.len(), 1);
        assert_eq!(
            report.alias_conflicts[0].reason,
            "token-has-different-client-name"
        );
    }

    #[test]
    fn raw_retcode_fields_count_as_the_retcode_token() {
        // The raw output already renames the client's retcode token.
        let raw = TypeToItemMap::from([
            (
                RuntimeType(1),
                message("AAAAAAAAAAA", vec![field("retcode", 1)]),
            ),
            (
                RuntimeType(2),
                message("BBBBBBBBBBB", vec![field("retcode", 2)]),
            ),
            (
                RuntimeType(3),
                message("CCCCCCCCCCC", vec![field("LLLLLLLLLLL", 3)]),
            ),
        ]);
        let mut items = TypeToItemMap::from([
            (
                RuntimeType(1),
                message("AAAAAAAAAAA", vec![field("retcode", 1)]),
            ),
            (
                RuntimeType(2),
                message("BBBBBBBBBBB", vec![field("retcode", 2)]),
            ),
            (
                RuntimeType(3),
                message("CCCCCCCCCCC", vec![field("LLLLLLLLLLL", 3)]),
            ),
        ]);
        let client = snapshot(&items);
        set_name(&items, 3, 3, "retcode");
        let report = propagate(&raw, "JKCOAIGJMMM", &client, &mut items);
        assert_eq!(names(&items, 3), ["LLLLLLLLLLL"]);
        assert_eq!(
            report.reverted_aliases[0].client_evidence,
            ["JKCOAIGJMMM x2"]
        );
    }
}
